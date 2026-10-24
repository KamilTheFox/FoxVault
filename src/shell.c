/* shell.c — команды в стиле bash/sftp внутри контейнера.
 *
 * Пути хоста помечаются префиксом host: (его можно писать явно, а можно
 * опускать — команды lls/lcd/lpwd/put/get и так знают, какая сторона хост).
 * put/get раскрывают шаблоны *, ?, [...] в имени файла.
 */
#include "shell.h"
#include "crypto.h"
#include "editor.h"
#include "platform.h"
#include "rx.h"
#include "util.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if defined(__GNUC__)
#pragma GCC diagnostic ignored "-Wformat-truncation"
#endif

#define FV_SHELL_MAX_ARGS 64
#define FV_LINE_MAX       4096
#define IDLE_DEFAULT      300u          /* секунд до автоблокировки */
#define HISTORY_MAX       500u          /* строк истории в памяти */

typedef struct {
    fv_vault     *v;
    char          cwd[FV_PATH_MAX];      /* текущий каталог внутри контейнера */
    uint64_t      timeout;               /* автоблокировка, 0 = выключена */
    plat_history  hist;                  /* история команд, только в памяти */
    const unsigned char *wild;           /* для argv команды: в аргументе был шаблон */
    int           quit;                  /* команда требует завершить shell */
} shctx;

/* ---------- утилиты вывода ---------- */

static void sh_err(const char *cmd, const char *arg, int rc)
{
    fprintf(stderr, "%s: %s: %s\n", cmd, arg ? arg : "", fv_strerror(rc));
}

static void fmt_time(uint64_t t, char *out, size_t len)
{
    time_t tt = (time_t)t;
    struct tm *tm = localtime(&tt);
    if (tm)
        snprintf(out, len, "%04d-%02d-%02d %02d:%02d",
                 tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
                 tm->tm_hour, tm->tm_min);
    else
        snprintf(out, len, "----");
}

/* ---------- токенизация с кавычками ---------- */

/* Обратный слэш: в Linux экранирует следующий символ (как в bash),
 * в Windows это разделитель пути (C:\Users\...), поэтому там он
 * остаётся как есть; экранируется только \" внутри двойных кавычек.
 * Буквальные *, ? и [ в обоих случаях — через кавычки.
 *
 * wild (может быть NULL): wild[i] = 1, если в i-м аргументе есть *, ? или [
 * вне кавычек и без экранирования — такой аргумент раскрывается как шаблон. */
#ifdef _WIN32
#define BS_ESCAPES 0
#else
#define BS_ESCAPES 1
#endif

static int tokenize(char *line, char **argv, int max, unsigned char *wild)
{
    int argc = 0;
    char *p = line;
    for (;;) {
        while (*p == ' ' || *p == '\t') p++;
        if (!*p) break;
        if (argc + 1 >= max) return -1;
        if (wild) wild[argc] = 0;
        argv[argc++] = p;
        char *w = p;
        for (;;) {
            char c = *p;
            if (c == '\0') break;
            if (c == ' ' || c == '\t') { p++; break; }
            if (c == '\'') {
                p++;
                while (*p && *p != '\'') *w++ = *p++;
                if (*p) p++;
                else return -1;
                continue;
            }
            if (c == '"') {
                p++;
                while (*p && *p != '"') {
                    if (*p == '\\' && (p[1] == '"' || (BS_ESCAPES && p[1] == '\\'))) p++;
                    *w++ = *p++;
                }
                if (*p) p++;
                else return -1;
                continue;
            }
            if (c == '\\' && BS_ESCAPES) {
                p++;
                if (!*p) break;
                *w++ = *p++;
                continue;
            }
            if (wild && (c == '*' || c == '?' || c == '[')) wild[argc - 1] = 1;
            *w++ = *p++;
        }
        *w = '\0';
    }
    argv[argc] = NULL;
    return argc;
}

/* Разрезать строку на команды конвейера по | вне кавычек (на месте).
 * Возврат — число частей (1 — конвейера нет), -1 — слишком много частей. */
static int split_pipes(char *line, char **seg, int max)
{
    int n = 0;
    seg[n++] = line;
    char q = 0;
    for (char *p = line; *p; p++) {
        if (q) {
            if (*p == q) q = 0;
            else if (q == '"' && *p == '\\' && p[1]) p++;
            continue;
        }
        if (*p == '\'' || *p == '"') { q = *p; continue; }
        if (BS_ESCAPES && *p == '\\' && p[1]) { p++; continue; }
        if (*p == '|') {
            if (n >= max) return -1;
            *p = '\0';
            seg[n++] = p + 1;
        }
    }
    return n;
}

/* ---------- пути ---------- */

static void strip_host_prefix(char *s)
{
    size_t l = strlen(s);
    if (l >= 5 && !strncmp(s, "host:", 5))
        memmove(s, s + 5, l - 4);        /* вместе с NUL */
}

static int vault_join(shctx *s, const char *arg, char *out, size_t n)
{
    if (!arg || !*arg || !strcmp(arg, "/")) {
        snprintf(out, n, "/");
        return FV_OK;
    }
    if (arg[0] == '/')
        snprintf(out, n, "%s", arg);
    else if (!strcmp(s->cwd, "/"))
        snprintf(out, n, "/%s", arg);
    else
        snprintf(out, n, "%s/%s", s->cwd, arg);
    return FV_OK;
}

/* ---------- шаблоны: *, ?, [abc], [a-z], [!abc] ---------- */

/* один символ UTF-8 строки с NUL на конце (NUL не байт-продолжение,
 * поэтому дальше конца строки декодер не заглядывает) */
static uint32_t u8_dec(const char **pp)
{
    return fv_u8_decode(pp, *pp + 5);
}

/* без учёта регистра (имена на Windows): латиница и кириллица */
static uint32_t fold_cp(uint32_t c, int fold)
{
    return fold ? fv_fold_cp(c) : c;
}

/* [...]: 1 — символ подходит, 0 — нет, -1 — нет закрывающей ']'.
 * *end — позиция после ']' */
static int glob_class(const char *p, uint32_t c, int fold, const char **end)
{
    int neg = 0, match = 0, first = 1;
    if (*p == '!' || *p == '^') { neg = 1; p++; }
    uint32_t fc = fold_cp(c, fold);
    while (*p && (*p != ']' || first)) {
        first = 0;
        uint32_t lo = u8_dec(&p), hi = lo;
        if (*p == '-' && p[1] && p[1] != ']') {
            p++;
            hi = u8_dec(&p);
        }
        if ((c >= lo && c <= hi) ||
            (fc >= fold_cp(lo, fold) && fc <= fold_cp(hi, fold)))
            match = 1;
    }
    if (*p != ']') return -1;
    *end = p + 1;
    return match != neg;
}

static int glob_match(const char *p, const char *s, int fold)
{
    const char *sp = NULL, *ss = NULL;           /* последняя '*' и откуда она ела */
    while (*s) {
        if (*p == '*') {
            while (*p == '*') p++;
            if (!*p) return 1;
            sp = p;
            ss = s;
            continue;
        }
        const char *s2 = s;
        uint32_t c = u8_dec(&s2);
        int ok = 0;
        if (*p == '?') {
            p++;
            ok = 1;
        } else {
            int literal = 1;
            if (*p == '[') {
                const char *end = NULL;
                int r = glob_class(p + 1, c, fold, &end);
                if (r >= 0) {                    /* настоящий класс */
                    literal = 0;
                    if (r) { p = end; ok = 1; }
                }
            }
            if (literal && *p) {
                const char *p2 = p;
                uint32_t pc = u8_dec(&p2);
                if (fold_cp(pc, fold) == fold_cp(c, fold)) { p = p2; ok = 1; }
            }
        }
        if (ok) { s = s2; continue; }
        if (!sp) return 0;
        const char *t = ss;                      /* '*' съедает ещё один символ */
        (void)u8_dec(&t);
        ss = t;
        s = t;
        p = sp;
    }
    while (*p == '*') p++;
    return *p == '\0';
}

/* имя подходит под шаблон; скрытые (".x") — только если шаблон тоже с точки */
static int name_matches(const char *pat, const char *name, int fold)
{
    if (name[0] == '.' && pat[0] != '.') return 0;
    return glob_match(pat, name, fold);
}

static int has_wild(const char *s)
{
    return strpbrk(s, "*?[") != NULL;
}

static int cmp_str(const void *a, const void *b)
{
    return strcmp(*(const char * const *)a, *(const char * const *)b);
}

#ifdef _WIN32
#define HOST_FOLD 1                              /* NTFS не различает регистр */
#else
#define HOST_FOLD 0
#endif

typedef struct {
    const char *pat;
    fv_strlist *names;
} hglob_ctx;

static void hglob_cb(const char *name, int is_dir, uint64_t size, void *ctx)
{
    (void)size;
    hglob_ctx *g = (hglob_ctx *)ctx;
    if (!is_dir && name_matches(g->pat, name, HOST_FOLD))
        fv_strlist_add(g->names, name);
}

/* Раскрыть шаблон на стороне хоста: файлы (не каталоги) в одном каталоге.
 * Возврат: число добавленных путей, -1 — ошибка (уже напечатана). */
static int expand_host(const char *cmd, const char *arg, fv_strlist *out)
{
    const char *slash = NULL;
    for (const char *q = arg; *q; q++) {
#ifdef _WIN32
        if (*q == '/' || *q == '\\') slash = q;
#else
        if (*q == '/') slash = q;
#endif
    }
    char dir[FV_PATH_MAX];
    const char *pat = arg;
    if (slash) {
        size_t dl = (size_t)(slash - arg) + 1;
        if (dl >= sizeof dir) { sh_err(cmd, arg, FV_ERR_RANGE); return -1; }
        memcpy(dir, arg, dl);
        dir[dl] = '\0';
        pat = slash + 1;
    } else {
        dir[0] = '\0';
    }
    if (has_wild(dir)) {
        fprintf(stderr, "%s: %s: шаблон допустим только в имени файла, не в каталоге\n",
                cmd, arg);
        return -1;
    }
    if (!*pat) { sh_err(cmd, arg, FV_ERR_ARG); return -1; }

    char ldir[FV_PATH_MAX];
    if (!dir[0]) strcpy(ldir, ".");
    else if (plat_expand_path(dir, ldir, sizeof ldir) != FV_OK)
        snprintf(ldir, sizeof ldir, "%s", dir);

    fv_strlist names;
    memset(&names, 0, sizeof names);
    hglob_ctx g = { pat, &names };
    int rc = plat_list_dir(ldir, hglob_cb, &g);
    if (rc != FV_OK) {
        sh_err(cmd, ldir, rc);
        fv_strlist_free(&names);
        return -1;
    }
    if (names.count > 1)
        qsort(names.items, names.count, sizeof(char *), cmp_str);
    int added = 0;
    for (size_t i = 0; i < names.count; i++) {
        char full[FV_PATH_MAX];
        if (snprintf(full, sizeof full, "%s%s", dir, names.items[i]) >= (int)sizeof full)
            continue;
        if (fv_strlist_add(out, full) == FV_OK) added++;
    }
    fv_strlist_free(&names);
    return added;
}

typedef struct {
    const char *pat;
    fv_strlist *names;
} vglob_ctx;

static int vglob_cb(const fv_node *n, void *ctx)
{
    vglob_ctx *g = (vglob_ctx *)ctx;
    if (n->type == FV_NODE_FILE && name_matches(g->pat, n->name, 0))
        fv_strlist_add(g->names, n->name);
    return 0;
}

/* Раскрыть шаблон внутри контейнера (регистр различается). */
static int expand_vault(shctx *s, const char *cmd, const char *arg, fv_strlist *out)
{
    char full[FV_PATH_MAX];
    vault_join(s, arg, full, sizeof full);
    char *slash = strrchr(full, '/');            /* full всегда начинается с '/' */
    if (!slash || !slash[1]) { sh_err(cmd, arg, FV_ERR_ARG); return -1; }
    const char *pat = slash + 1;
    char dir[FV_PATH_MAX];
    size_t dl = (size_t)(slash - full);
    if (dl == 0) {
        strcpy(dir, "/");
    } else {
        memcpy(dir, full, dl);
        dir[dl] = '\0';
    }
    if (has_wild(dir)) {
        fprintf(stderr, "%s: %s: шаблон допустим только в имени файла, не в каталоге\n",
                cmd, arg);
        return -1;
    }
    fv_strlist names;
    memset(&names, 0, sizeof names);
    vglob_ctx g = { pat, &names };
    int rc = fv_vault_list(s->v, dir, vglob_cb, &g);
    if (rc != FV_OK) {
        sh_err(cmd, dir, rc);
        fv_strlist_free(&names);
        return -1;
    }
    int added = 0;
    for (size_t i = 0; i < names.count; i++) {   /* индекс отдаёт уже по порядку */
        char p[FV_PATH_MAX];
        if (snprintf(p, sizeof p, "%s/%s", dl ? dir : "", names.items[i]) >= (int)sizeof p)
            continue;
        if (fv_strlist_add(out, p) == FV_OK) added++;
    }
    fv_strlist_free(&names);
    return added;
}

/* ---------- строки для конвейера: только память, затираются ---------- */

typedef struct {
    char  **v;
    size_t *l;
    size_t  n, cap;
} lines_t;

static int lines_add(lines_t *L, const char *s, size_t len)
{
    if (L->n == L->cap) {
        size_t nc = L->cap ? L->cap * 2 : 64;
        char **nv = (char **)realloc(L->v, nc * sizeof(char *));
        if (!nv) return 0;
        L->v = nv;
        size_t *nl = (size_t *)realloc(L->l, nc * sizeof(size_t));
        if (!nl) return 0;
        L->l = nl;
        L->cap = nc;
    }
    char *cp = (char *)malloc(len + 1);
    if (!cp) return 0;
    memcpy(cp, s, len);
    cp[len] = '\0';
    L->v[L->n] = cp;
    L->l[L->n] = len;
    L->n++;
    return 1;
}

static void lines_free(lines_t *L)
{
    for (size_t i = 0; i < L->n; i++) {
        fv_wipe(L->v[i], L->l[i]);
        free(L->v[i]);
    }
    free(L->v);
    free(L->l);
    memset(L, 0, sizeof *L);
}

/* ---------- ls / lls ---------- */

typedef struct {
    int      longfmt;
    lines_t *out;                    /* не NULL — вывод в конвейер */
} ls_ctx;

static int ls_cb(const fv_node *n, void *ctx)
{
    ls_ctx *c = (ls_ctx *)ctx;
    char line[FV_NAME_MAX + 64];
    if (c->longfmt) {
        char when[20];
        fmt_time(n->mtime, when, sizeof when);
        if (n->type == FV_NODE_DIR)
            snprintf(line, sizeof line, "d %10s  %s %s/", "-", when, n->name);
        else
            snprintf(line, sizeof line, "- %10" PRIu64 "  %s %s", n->size, when, n->name);
    } else {
        snprintf(line, sizeof line, "%s%s", n->name, n->type == FV_NODE_DIR ? "/" : "");
    }
    if (c->out) lines_add(c->out, line, strlen(line));
    else printf("%s\n", line);
    return 0;
}

typedef struct {
    char    **names;
    int      *dirs;
    uint64_t *sizes;
    size_t    n, cap;
} ld_ctx;

static void ld_cb(const char *name, int is_dir, uint64_t size, void *ctx)
{
    ld_ctx *c = (ld_ctx *)ctx;
    if (c->n == c->cap) {
        size_t nc = c->cap ? c->cap * 2 : 32;
        char **nn = (char **)realloc(c->names, nc * sizeof(char *));
        if (!nn) return;
        c->names = nn;
        int *nd = (int *)realloc(c->dirs, nc * sizeof(int));
        if (nd) c->dirs = nd;
        uint64_t *ns = (uint64_t *)realloc(c->sizes, nc * sizeof(uint64_t));
        if (ns) c->sizes = ns;
        c->cap = nc;
    }
    size_t l = strlen(name) + 1;
    c->names[c->n] = (char *)malloc(l);
    if (!c->names[c->n]) return;
    memcpy(c->names[c->n], name, l);
    c->dirs[c->n] = is_dir;
    c->sizes[c->n] = size;
    c->n++;
}

typedef struct {
    char    *name;
    int      dir;
    uint64_t size;
} ld_ent;

static int cmp_ld(const void *a, const void *b)
{
    const ld_ent *x = (const ld_ent *)a;
    const ld_ent *y = (const ld_ent *)b;
    if (x->dir != y->dir) return y->dir - x->dir;    /* каталоги раньше */
    return strcmp(x->name, y->name);
}

static int cmd_lls(shctx *s, int argc, char **argv)
{
    (void)s;
    char path[FV_PATH_MAX];
    if (argc > 0) {
        strip_host_prefix(argv[0]);
        if (plat_expand_path(argv[0], path, sizeof path) != FV_OK)
            strcpy(path, argv[0]);
    } else {
        strcpy(path, ".");
    }

    ld_ctx c;
    memset(&c, 0, sizeof c);
    int rc = plat_list_dir(path, ld_cb, &c);
    if (rc != FV_OK) {
        sh_err("lls", path, rc);
        return 1;
    }
    if (c.n == 0) return 0;

    ld_ent *ents = (ld_ent *)malloc(c.n * sizeof(ld_ent));
    if (!ents) {
        for (size_t i = 0; i < c.n; i++) free(c.names[i]);
        free(c.names); free(c.dirs); free(c.sizes);
        return 1;
    }
    for (size_t i = 0; i < c.n; i++) {
        ents[i].name = c.names[i];
        ents[i].dir = c.dirs[i];
        ents[i].size = c.sizes[i];
    }
    qsort(ents, c.n, sizeof(ld_ent), cmp_ld);
    for (size_t i = 0; i < c.n; i++) {
        if (ents[i].dir)
            printf("d %10s  %s\n", "-", ents[i].name);
        else
            printf("- %10" PRIu64 "  %s\n", ents[i].size, ents[i].name);
    }
    for (size_t i = 0; i < c.n; i++) free(ents[i].name);
    free(ents);
    free(c.names); free(c.dirs); free(c.sizes);
    return 0;
}

/* ---------- команды shell ---------- */

static int ls_run(shctx *s, int argc, char **argv, lines_t *out)
{
    int longfmt = 0;
    int first = 0;
    while (first < argc && argv[first][0] == '-' && argv[first][1]) {
        if (!strcmp(argv[first], "-l")) longfmt = 1;
        else if (!strcmp(argv[first], "-")) break;
        else {
            sh_err("ls", argv[first], FV_ERR_ARG);
            return 1;
        }
        first++;
    }
    char path[FV_PATH_MAX];
    if (first < argc)
        vault_join(s, argv[first], path, sizeof path);
    else
        strcpy(path, s->cwd);

    ls_ctx c = { longfmt, out };
    int rc = fv_vault_list(s->v, path, ls_cb, &c);
    if (rc != FV_OK) {
        sh_err("ls", path, rc);
        return 1;
    }
    return 0;
}

static int cmd_ls(shctx *s, int argc, char **argv)
{
    return ls_run(s, argc, argv, NULL);
}

static int cmd_cd(shctx *s, int argc, char **argv)
{
    char path[FV_PATH_MAX];
    vault_join(s, argc > 0 ? argv[0] : "/", path, sizeof path);
    fv_vstat st;
    int rc = fv_vault_stat(s->v, path, &st);
    if (rc == FV_OK && st.type != FV_NODE_DIR)
        rc = FV_ERR_ARG;
    if (rc != FV_OK) {
        sh_err("cd", path, rc);
        return 1;
    }
    if (fv_index_norm_path(path, s->cwd, sizeof s->cwd) != FV_OK)
        strcpy(s->cwd, "/");
    return 0;
}

static int cmd_pwd(shctx *s, int argc, char **argv)
{
    (void)argc;
    (void)argv;
    printf("%s\n", s->cwd);
    return 0;
}

static int cmd_mkdir(shctx *s, int argc, char **argv)
{
    if (!argc) {
        fprintf(stderr, "использование: mkdir <каталог>\n");
        return 1;
    }
    int bad = 0;
    for (int i = 0; i < argc; i++) {
        char path[FV_PATH_MAX];
        vault_join(s, argv[i], path, sizeof path);
        int rc = fv_vault_mkdir(s->v, path);
        if (rc != FV_OK) {
            sh_err("mkdir", path, rc);
            bad = 1;
        }
    }
    return bad;
}

static int cmd_rm(shctx *s, int argc, char **argv)
{
    int recursive = 0, first = 0;
    while (first < argc && argv[first][0] == '-' && argv[first][1]) {
        if (!strcmp(argv[first], "-r") || !strcmp(argv[first], "-R"))
            recursive = 1;
        else {
            sh_err("rm", argv[first], FV_ERR_ARG);
            return 1;
        }
        first++;
    }
    if (first >= argc) {
        fprintf(stderr, "использование: rm [-r] <путь>...\n");
        return 1;
    }
    int bad = 0;
    for (int i = first; i < argc; i++) {
        char path[FV_PATH_MAX];
        vault_join(s, argv[i], path, sizeof path);
        int rc = fv_vault_rm(s->v, path, recursive);
        if (rc != FV_OK) {
            sh_err("rm", path, rc);
            bad = 1;
        }
    }
    return bad;
}

static int cmd_mv(shctx *s, int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "использование: mv <источник> <цель>\n");
        return 1;
    }
    char src[FV_PATH_MAX], dst[FV_PATH_MAX];
    vault_join(s, argv[0], src, sizeof src);
    vault_join(s, argv[1], dst, sizeof dst);
    int rc = fv_vault_mv(s->v, src, dst);
    if (rc != FV_OK) {
        sh_err("mv", src, rc);
        return 1;
    }
    return 0;
}

/* Аргументы -> полные пути файлов контейнера, маски раскрываются.
 * wild — флаги шаблона для argv (может быть NULL). Возврат: 1 — были
 * ошибки (напечатаны), 0 — всё хорошо. */
static int collect_vault_files(shctx *s, const char *cmd, int argc, char **argv,
                               const unsigned char *wild, fv_strlist *out)
{
    int bad = 0;
    for (int i = 0; i < argc; i++) {
        if (wild && wild[i]) {
            int n = expand_vault(s, cmd, argv[i], out);
            if (n == 0) fprintf(stderr, "%s: %s: нет подходящих файлов\n", cmd, argv[i]);
            if (n <= 0) bad = 1;
        } else {
            char path[FV_PATH_MAX];
            vault_join(s, argv[i], path, sizeof path);
            fv_strlist_add(out, path);
        }
    }
    return bad;
}

static int cmd_cat(shctx *s, int argc, char **argv)
{
    if (!argc) {
        fprintf(stderr, "использование: cat <файл>...\n");
        return 1;
    }
    fv_strlist files;
    memset(&files, 0, sizeof files);
    int bad = collect_vault_files(s, "cat", argc, argv, s->wild, &files);
    for (size_t i = 0; i < files.count; i++) {
        int rc = fv_vault_cat(s->v, files.items[i]);
        if (rc != FV_OK) {
            sh_err("cat", files.items[i], rc);
            bad = 1;
        }
    }
    fv_strlist_free(&files);
    return bad;
}

static int cmd_stat(shctx *s, int argc, char **argv)
{
    if (argc != 1) {
        fprintf(stderr, "использование: stat <путь>\n");
        return 1;
    }
    char path[FV_PATH_MAX];
    vault_join(s, argv[0], path, sizeof path);
    fv_vstat st;
    int rc = fv_vault_stat(s->v, path, &st);
    if (rc != FV_OK) {
        sh_err("stat", path, rc);
        return 1;
    }
    char when[20], human[32];
    fmt_time(st.mtime, when, sizeof when);
    fv_human(st.size, human, sizeof human);
    if (st.type == FV_NODE_DIR)
        printf("%s: каталог, изменён %s\n", path, when);
    else
        printf("%s: файл, %" PRIu64 " байт (%s), чанк %u КиБ, изменён %s\n",
               path, st.size, human, st.chunk_size / 1024u, when);
    return 0;
}

static int cmd_put(shctx *s, int argc, char **argv)
{
    if (argc < 1) {
        fprintf(stderr, "использование: put <файл хоста>... [<путь контейнера>]\n");
        return 1;
    }
    const unsigned char *wild = s->wild;

    /* назначение: последний аргумент, если аргументов больше одного */
    int nsrc = (argc > 1) ? argc - 1 : 1;
    char dst[FV_PATH_MAX];
    if (argc > 1) {
        if (wild && wild[argc - 1]) {
            fprintf(stderr, "put: назначение не может быть шаблоном: %s\n", argv[argc - 1]);
            return 1;
        }
        vault_join(s, argv[argc - 1], dst, sizeof dst);
    } else {
        snprintf(dst, sizeof dst, "%s", s->cwd);
    }

    fv_strlist src;
    memset(&src, 0, sizeof src);
    int bad = 0;
    for (int i = 0; i < nsrc; i++) {
        strip_host_prefix(argv[i]);
        if (wild && wild[i]) {
            int n = expand_host("put", argv[i], &src);
            if (n == 0) fprintf(stderr, "put: %s: нет подходящих файлов\n", argv[i]);
            if (n <= 0) bad = 1;
        } else {
            fv_strlist_add(&src, argv[i]);
        }
    }
    if (src.count == 0) {
        fv_strlist_free(&src);
        return 1;
    }

    /* несколько источников: назначение обязано быть каталогом */
    if (src.count > 1) {
        fv_vstat st;
        int rc = fv_vault_stat(s->v, dst, &st);
        if (rc != FV_OK || st.type != FV_NODE_DIR) {
            fprintf(stderr, "put: %s: каталог назначения не найден "
                            "(для нескольких файлов нужен каталог)\n", dst);
            fv_strlist_free(&src);
            return 1;
        }
    }

    size_t ok = 0;
    for (size_t i = 0; i < src.count; i++) {
        int rc = fv_vault_put(s->v, src.items[i], dst);
        if (rc != FV_OK) {
            sh_err("put", src.items[i], rc);
            bad = 1;
        } else {
            ok++;
            if (src.count > 1) printf("  %s\n", src.items[i]);
        }
        fv_vault_touch(s->v);                    /* долгое копирование — не простой */
    }
    if (src.count > 1)
        printf("put: скопировано %zu из %zu\n", ok, src.count);
    fv_strlist_free(&src);
    return bad;
}

static int cmd_get(shctx *s, int argc, char **argv)
{
    if (argc < 1) {
        fprintf(stderr, "использование: get <путь контейнера>... [<путь хоста>]\n");
        return 1;
    }
    const unsigned char *wild = s->wild;

    int nsrc = (argc > 1) ? argc - 1 : 1;
    char dst[FV_PATH_MAX];
    if (argc > 1) {
        if (wild && wild[argc - 1]) {
            fprintf(stderr, "get: назначение не может быть шаблоном: %s\n", argv[argc - 1]);
            return 1;
        }
        strip_host_prefix(argv[argc - 1]);
        int rc = plat_expand_path(argv[argc - 1], dst, sizeof dst);
        if (rc != FV_OK) {
            sh_err("get", argv[argc - 1], rc);
            return 1;
        }
    } else {
        strcpy(dst, ".");
    }

    fv_strlist src;
    memset(&src, 0, sizeof src);
    int bad = 0;
    for (int i = 0; i < nsrc; i++) {
        if (wild && wild[i]) {
            int n = expand_vault(s, "get", argv[i], &src);
            if (n == 0) fprintf(stderr, "get: %s: нет подходящих файлов\n", argv[i]);
            if (n <= 0) bad = 1;
        } else {
            char path[FV_PATH_MAX];
            vault_join(s, argv[i], path, sizeof path);
            fv_strlist_add(&src, path);
        }
    }
    if (src.count == 0) {
        fv_strlist_free(&src);
        return 1;
    }
    if (src.count > 1 && plat_stat_kind(dst) != 2) {
        fprintf(stderr, "get: %s: каталог назначения не найден "
                        "(для нескольких файлов нужен каталог)\n", dst);
        fv_strlist_free(&src);
        return 1;
    }

    size_t ok = 0;
    for (size_t i = 0; i < src.count; i++) {
        int rc = fv_vault_get(s->v, src.items[i], dst);
        if (rc == FV_ERR_EXISTS) {
            fprintf(stderr, "get: %s: на компьютере уже есть файл с таким именем — пропущен\n",
                    src.items[i]);
            bad = 1;
        } else if (rc != FV_OK) {
            sh_err("get", src.items[i], rc);
            bad = 1;
        } else {
            ok++;
            if (src.count > 1) printf("  %s\n", src.items[i]);
        }
        fv_vault_touch(s->v);
    }
    if (src.count > 1)
        printf("get: скопировано %zu из %zu\n", ok, src.count);
    fv_strlist_free(&src);
    return bad;
}

static int cmd_info(shctx *s, int argc, char **argv)
{
    (void)argc;
    (void)argv;
    char hex[33];
    fv_vault_uuid_hex(s->v, hex);
    size_t files, dirs;
    uint64_t bytes;
    fv_vault_totals(s->v, &files, &dirs, &bytes);
    char human[32];
    fv_human(bytes, human, sizeof human);
    printf("контейнер : %s\n", fv_vault_dir(s->v));
    printf("uuid      : %s\n", hex);
    printf("формат    : foxvault 1, AES-256-GCM, PBKDF2-HMAC-SHA256 %" PRIu32 " итераций\n",
           fv_vault_kdf_iters(s->v));
    printf("поколения : заголовок %" PRIu32 ", индекс %" PRIu32 "\n",
           fv_vault_hdr_gen(s->v), fv_vault_ix_gen(s->v));
    printf("содержимое: файлов %zu, каталогов %zu, суммарно %s\n",
           files, dirs, human);
    return 0;
}

static int cmd_passwd(shctx *s, int argc, char **argv)
{
    (void)argc;
    (void)argv;
    char p1[FV_PASS_MAX], p2[FV_PASS_MAX];
    int rc = plat_read_password("Новый пароль: ", p1, sizeof p1);
    if (rc != FV_OK) return 1;
    rc = plat_read_password("Повторите пароль: ", p2, sizeof p2);
    if (rc != FV_OK) {
        fv_wipe(p1, sizeof p1);
        return 1;
    }
    int ok = !strcmp(p1, p2);
    fv_wipe(p2, sizeof p2);
    if (!ok) {
        fv_wipe(p1, sizeof p1);
        fprintf(stderr, "passwd: пароли не совпадают\n");
        return 1;
    }
    if (strlen(p1) < 8)
        fprintf(stderr, "passwd: предупреждение: короткий пароль\n");
    rc = fv_vault_change_password(s->v, p1);
    fv_wipe(p1, sizeof p1);
    if (rc != FV_OK) {
        sh_err("passwd", NULL, rc);
        return 1;
    }
    printf("пароль изменён, данные не перешифровывались\n");
    return 0;
}

static int cmd_lcd(shctx *s, int argc, char **argv)
{
    (void)s;
    char path[FV_PATH_MAX];
    char arg[FV_PATH_MAX];
    if (argc > 0) {
        snprintf(arg, sizeof arg, "%s", argv[0]);
        strip_host_prefix(arg);
        if (plat_expand_path(arg, path, sizeof path) != FV_OK)
            strcpy(path, arg);
    } else {
        strcpy(path, "~");
        if (plat_expand_path(path, path, sizeof path) != FV_OK)
            strcpy(path, "/");
    }
    if (plat_stat_kind(path) != 2) {
        sh_err("lcd", path, FV_ERR_NOTFOUND);
        return 1;
    }
    int rc = plat_chdir(path);
    if (rc != FV_OK) {
        sh_err("lcd", path, rc);
        return 1;
    }
    return 0;
}

static int cmd_lpwd(shctx *s, int argc, char **argv)
{
    (void)argc;
    (void)argv;
    (void)s;
    char cwd[FV_PATH_MAX];
    if (plat_getcwd(cwd, sizeof cwd) != FV_OK)
        strcpy(cwd, "?");
    printf("%s\n", cwd);
    return 0;
}

static int cmd_history(shctx *s, int argc, char **argv)
{
    if (argc == 1 && !strcmp(argv[0], "-c")) {
        plat_history_clear(&s->hist);
        plat_history_init(&s->hist, HISTORY_MAX);
        printf("история очищена\n");
        return 0;
    }
    size_t from = 0;
    if (argc == 1) {
        char *end = NULL;
        long nlast = strtol(argv[0], &end, 10);
        if (!end || *end || nlast <= 0) {
            fprintf(stderr, "использование: history [N | -c]\n");
            return 1;
        }
        if ((size_t)nlast < s->hist.n) from = s->hist.n - (size_t)nlast;
    } else if (argc > 1) {
        fprintf(stderr, "использование: history [N | -c]\n");
        return 1;
    }
    for (size_t i = from; i < s->hist.n; i++)
        printf("%5zu  %s\n", i + 1, s->hist.items[i]);
    return 0;
}

/* ---------- grep и конвейеры ---------- */

typedef struct {
    int icase, invert, number, count, fixed;
} gopt;

#define C_FILE  "\033[35m"
#define C_SEP   "\033[36m"
#define C_NUM   "\033[32m"
#define C_MATCH "\033[01;31m"
#define C_OFF   "\033[m"

/* Разобрать [-ivncF] шаблон [файлы...]. Возврат: индекс первого файла
 * (argc — файлов нет), -1 — ошибка (напечатана). */
static int grep_parse(int argc, char **argv, gopt *o, const char **pat)
{
    memset(o, 0, sizeof *o);
    int i = 0;
    for (; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "--")) { i++; break; }
        if (a[0] != '-' || !a[1]) break;
        for (const char *p = a + 1; *p; p++) {
            switch (*p) {
            case 'i': o->icase = 1;  break;
            case 'v': o->invert = 1; break;
            case 'n': o->number = 1; break;
            case 'c': o->count = 1;  break;
            case 'F': o->fixed = 1;  break;
            default:
                fprintf(stderr, "grep: неизвестный ключ -%c (есть -i -v -n -c -F)\n", *p);
                return -1;
            }
        }
    }
    if (i >= argc) {
        fprintf(stderr, "использование: grep [-ivncF] <шаблон> <файл|маска>...\n"
                        "          или: cat <файл> | grep <шаблон>\n");
        return -1;
    }
    *pat = argv[i];
    return i + 1;
}

static int grep_compile(const gopt *o, const char *pat, fv_rx **rx)
{
    const char *err = NULL;
    if (fv_rx_compile(rx, pat, o->icase, o->fixed, &err) != FV_OK) {
        fprintf(stderr, "grep: ошибка в шаблоне '%s': %s\n", pat, err ? err : "?");
        return 0;
    }
    return 1;
}

static void badd(fv_buf *b, const char *s) { fv_buf_add(b, s, strlen(s)); }

/* Напечатать (out == NULL) или передать дальше по конвейеру одну строку
 * результата: [файл:][номер:]текст, с подсветкой совпадений при color. */
static void grep_emit(const fv_rx *rx, const gopt *o, const char *label, size_t lineno,
                      const char *s, size_t len, lines_t *out, int color)
{
    fv_buf b;
    fv_buf_init(&b);
    if (label) {
        if (color) badd(&b, C_FILE);
        badd(&b, label);
        badd(&b, color ? C_SEP ":" C_OFF : ":");
    }
    if (o->number) {
        char num[32];
        snprintf(num, sizeof num, "%zu", lineno);
        if (color) badd(&b, C_NUM);
        badd(&b, num);
        badd(&b, color ? C_SEP ":" C_OFF : ":");
    }
    if (color && !o->invert) {
        size_t from = 0, ms, me;
        while (from <= len && fv_rx_search(rx, s, len, from, &ms, &me)) {
            fv_buf_add(&b, s + from, ms - from);
            if (me > ms) {
                badd(&b, C_MATCH);
                fv_buf_add(&b, s + ms, me - ms);
                badd(&b, C_OFF);
                from = me;
            } else {                                 /* пустое совпадение: шаг на символ */
                if (ms >= len) { from = len; break; }
                const char *p = s + ms;
                (void)fv_u8_decode(&p, s + len);
                fv_buf_add(&b, s + ms, (size_t)(p - (s + ms)));
                from = (size_t)(p - s);
            }
        }
        if (from < len) fv_buf_add(&b, s + from, len - from);
    } else {
        fv_buf_add(&b, s, len);
    }
    if (out) {
        lines_add(out, (const char *)b.data, b.len);
    } else {
        fv_buf_add(&b, "\n", 1);
        fwrite(b.data, 1, b.len, stdout);
    }
    if (b.data) fv_wipe(b.data, b.cap);
    fv_buf_free(&b);
}

static int grep_hit(const fv_rx *rx, const gopt *o, const char *s, size_t len)
{
    size_t ms, me;
    return fv_rx_search(rx, s, len, 0, &ms, &me) != o->invert;
}

static void grep_count_out(const char *label, size_t cnt, lines_t *out, int color)
{
    char line[FV_PATH_MAX + 48];
    if (label)
        snprintf(line, sizeof line, "%s%s%s%s%s%zu", color ? C_FILE : "", label,
                 color ? C_SEP : "", ":", color ? C_OFF : "", cnt);
    else
        snprintf(line, sizeof line, "%zu", cnt);
    if (out) lines_add(out, line, strlen(line));
    else printf("%s\n", line);
}

/* grep по файлам контейнера; out == NULL — печать, иначе в конвейер */
static int grep_files(shctx *s, int argc, char **argv, const unsigned char *wild,
                      lines_t *out, int color)
{
    gopt o;
    const char *pat = NULL;
    int first = grep_parse(argc, argv, &o, &pat);
    if (first < 0) return 1;
    if (first >= argc) {
        fprintf(stderr, "grep: укажите файлы: grep %s <файл|маска>... "
                        "(или: cat <файл> | grep %s)\n", pat, pat);
        return 1;
    }
    fv_rx *rx = NULL;
    if (!grep_compile(&o, pat, &rx)) return 1;

    fv_strlist files;
    memset(&files, 0, sizeof files);
    int bad = collect_vault_files(s, "grep", argc - first, argv + first,
                                  wild ? wild + first : NULL, &files);
    int multi = files.count > 1;
    size_t total_hits = 0;

    for (size_t f = 0; f < files.count; f++) {
        const char *path = files.items[f];
        const char *label = multi ? path : NULL;
        fv_vstat st;
        int rc = fv_vault_stat(s->v, path, &st);
        if (rc == FV_OK && st.type == FV_NODE_DIR) {
            fprintf(stderr, "grep: %s: это каталог\n", path);
            bad = 1;
            continue;
        }
        uint8_t *data = NULL;
        size_t dlen = 0;
        rc = (rc == FV_OK) ? fv_vault_read_mem(s->v, path, &data, &dlen) : rc;
        if (rc != FV_OK) {
            sh_err("grep", path, rc);
            bad = 1;
            continue;
        }
        const char *txt = (const char *)data;
        int binary = dlen && memchr(data, 0, dlen) != NULL;
        size_t hits = 0, lineno = 0, i = 0;
        while (i < dlen) {
            size_t j = i;
            while (j < dlen && txt[j] != '\n') j++;
            size_t l = j - i;
            if (l && txt[i + l - 1] == '\r') l--;
            lineno++;
            if (grep_hit(rx, &o, txt + i, l)) {
                hits++;
                if (!o.count && !binary)
                    grep_emit(rx, &o, label, lineno, txt + i, l, out, color);
            }
            i = j + 1;
        }
        if (o.count) {
            grep_count_out(label, hits, out, color);
        } else if (binary && hits) {
            char msg[FV_PATH_MAX + 48];
            snprintf(msg, sizeof msg, "двоичный файл %s совпадает", path);
            if (out) lines_add(out, msg, strlen(msg));
            else printf("%s\n", msg);
        }
        total_hits += hits;
        fv_wipe(data, dlen);
        free(data);
        fv_vault_touch(s->v);
    }
    fv_strlist_free(&files);
    fv_rx_free(rx);
    return (bad || !total_hits) ? 1 : 0;
}

/* grep по строкам, пришедшим по конвейеру */
static int grep_lines(int argc, char **argv, const lines_t *in, lines_t *out, int color)
{
    gopt o;
    const char *pat = NULL;
    int first = grep_parse(argc, argv, &o, &pat);
    if (first < 0) return 1;
    if (first < argc) {
        fprintf(stderr, "grep: после | grep читает строки слева — файлы не указываются\n");
        return 1;
    }
    fv_rx *rx = NULL;
    if (!grep_compile(&o, pat, &rx)) return 1;
    size_t hits = 0;
    for (size_t i = 0; i < in->n; i++) {
        if (grep_hit(rx, &o, in->v[i], in->l[i])) {
            hits++;
            if (!o.count) grep_emit(rx, &o, NULL, i + 1, in->v[i], in->l[i], out, color);
        }
    }
    if (o.count) grep_count_out(NULL, hits, out, color);
    fv_rx_free(rx);
    return hits ? 0 : 1;
}

/* cat в конвейер: строки файлов (двоичные пропускаются) */
static int cat_lines(shctx *s, int argc, char **argv, const unsigned char *wild, lines_t *out)
{
    if (!argc) {
        fprintf(stderr, "использование: cat <файл>... | grep <шаблон>\n");
        return 1;
    }
    fv_strlist files;
    memset(&files, 0, sizeof files);
    int bad = collect_vault_files(s, "cat", argc, argv, wild, &files);
    for (size_t f = 0; f < files.count; f++) {
        uint8_t *data = NULL;
        size_t dlen = 0;
        int rc = fv_vault_read_mem(s->v, files.items[f], &data, &dlen);
        if (rc != FV_OK) {
            sh_err("cat", files.items[f], rc);
            bad = 1;
            continue;
        }
        if (dlen && memchr(data, 0, dlen)) {
            fprintf(stderr, "cat: %s: двоичный файл — в конвейер не передаётся\n",
                    files.items[f]);
        } else {
            const char *t = (const char *)data;
            size_t i = 0;
            while (i < dlen) {
                size_t j = i;
                while (j < dlen && t[j] != '\n') j++;
                size_t l = j - i;
                if (l && t[i + l - 1] == '\r') l--;
                lines_add(out, t + i, l);
                i = j + 1;
            }
        }
        fv_wipe(data, dlen);
        free(data);
    }
    fv_strlist_free(&files);
    return bad;
}

/* Конвейер: слева cat | ls | grep, дальше только grep. Всё в памяти:
 * промежуточные строки нигде не записываются и затираются после работы. */
static int run_pipeline(shctx *s, char **seg, int nseg)
{
    char *argv[FV_SHELL_MAX_ARGS];
    unsigned char wild[FV_SHELL_MAX_ARGS];
    lines_t cur;
    memset(&cur, 0, sizeof cur);
    int color = plat_color_ok();
    int rc = 0;

    for (int i = 0; i < nseg && !rc; i++) {
        int argc = tokenize(seg[i], argv, FV_SHELL_MAX_ARGS, wild);
        if (argc < 0) {
            fprintf(stderr, "foxvault: некорректная строка\n");
            rc = 1;
            break;
        }
        if (argc == 0) {
            fprintf(stderr, "foxvault: пустая команда в конвейере\n");
            rc = 1;
            break;
        }
        int last = (i == nseg - 1);
        if (i == 0) {
            if (!strcmp(argv[0], "cat"))
                rc = cat_lines(s, argc - 1, argv + 1, wild + 1, &cur) && cur.n == 0;
            else if (!strcmp(argv[0], "ls"))
                rc = ls_run(s, argc - 1, argv + 1, &cur);
            else if (!strcmp(argv[0], "grep")) {
                grep_files(s, argc - 1, argv + 1, wild + 1, &cur, 0);
                rc = 0;                              /* «ничего не нашлось» — не ошибка конвейера */
            } else {
                fprintf(stderr, "foxvault: слева от | поддерживаются cat, ls и grep\n");
                rc = 1;
            }
        } else {
            if (strcmp(argv[0], "grep") != 0) {
                fprintf(stderr, "foxvault: справа от | поддерживается только grep\n");
                rc = 1;
                break;
            }
            lines_t next;
            memset(&next, 0, sizeof next);
            grep_lines(argc - 1, argv + 1, &cur, last ? NULL : &next, last && color);
            lines_free(&cur);
            cur = next;
        }
    }
    lines_free(&cur);
    fv_vault_touch(s->v);
    return rc;
}

static int cmd_grep(shctx *s, int argc, char **argv)
{
    return grep_files(s, argc, argv, s->wild, NULL, plat_color_ok());
}

static int cmd_help(shctx *s, int argc, char **argv);

/* ---------- Tab-автодополнение ---------- */

typedef struct {
    char  *s;
    int    dir;
} cand;

typedef struct {
    cand  *v;
    size_t n, cap;
} cands;

static void cands_add(cands *c, const char *s, int is_dir)
{
    if (c->n == c->cap) {
        size_t nc = c->cap ? c->cap * 2 : 16;
        cand *nv = (cand *)realloc(c->v, nc * sizeof(cand));
        if (!nv) return;
        c->v = nv;
        c->cap = nc;
    }
    c->v[c->n].s = strdup(s);
    if (!c->v[c->n].s) return;
    c->v[c->n].dir = is_dir;
    c->n++;
}

static void cands_free(cands *c)
{
    for (size_t i = 0; i < c->n; i++) free(c->v[i].s);
    free(c->v);
    memset(c, 0, sizeof *c);
}

static int cmp_cand(const void *a, const void *b)
{
    const cand *x = (const cand *)a;
    const cand *y = (const cand *)b;
    return strcmp(x->s, y->s);
}

static int vcand_cb(const fv_node *n, void *ctx)
{
    cands_add((cands *)ctx, n->name, n->type == FV_NODE_DIR);
    return 0;
}

static void hcand_cb(const char *name, int is_dir, uint64_t size, void *ctx)
{
    (void)size;
    cands_add((cands *)ctx, name, is_dir);
}

static const char *SH_COMMANDS[] = {
    "ls", "cd", "pwd", "mkdir", "mv", "rm", "cat", "stat",
    "put", "get", "lls", "lcd", "lpwd", "info", "passwd", "edit",
    "history", "grep", "help", "exit", "quit", NULL
};

static void complete_commands(cands *c, const char *word)
{
    size_t wl = strlen(word);
    for (int i = 0; SH_COMMANDS[i]; i++)
        if (!strncmp(SH_COMMANDS[i], word, wl)) cands_add(c, SH_COMMANDS[i], 0);
}

/* Перезаписать последнее слово строки на repl.
 * Если в repl есть пробел (или слово было в кавычках) — заключить в кавычки.
 * Открывающая кавычка добавляется, только если её ещё нет в строке.
 * add_space — добавить пробел после (единственный точный кандидат). */
static size_t tab_replace(char *line, size_t wstart, const char *repl,
                          int had_q, char qch, int add_space)
{
    char out[FV_LINE_MAX];
    size_t rl = strlen(repl);
    int quote = had_q || strchr(repl, ' ') != NULL;
    char qc = had_q ? qch : '"';
    size_t o = wstart;
    if (wstart + rl + 4 >= sizeof out) return 0;
    memcpy(out, line, wstart);
    if (quote && !had_q) out[o++] = qc;              /* открывающая — если не была набрана */
    memcpy(out + o, repl, rl);
    o += rl;
    if (quote) out[o++] = qc;                        /* закрывающая — всегда при кавычках */
    if (add_space) out[o++] = ' ';
    out[o] = '\0';
    memcpy(line, out, o + 1);
    return o;
}

/* fn для plat_readline_ex: дополнить последнее слово в line */
static int sh_tab_complete(char *line, size_t *len, void *ctx)
{
    shctx *s = (shctx *)ctx;
    size_t n = *len;
    line[n] = '\0';

    /* последнее слово: с конца до ближайшего пробела */
    size_t ws = n;
    while (ws > 0 && line[ws - 1] != ' ' && line[ws - 1] != '\t') ws--;
    char *word = line + ws;
    size_t wl = n - ws;
    int had_q = 0;
    char qch = 0;
    if (wl && (word[0] == '"' || word[0] == '\'')) {
        had_q = 1;
        qch = word[0];
        word++;
        wl--;
    }
    size_t base = ws + (size_t)had_q;                /* куда встанет дополнение */

    /* команда — первое слово строки (без последнего слова) */
    char tmp[FV_LINE_MAX];
    size_t cut = ws < sizeof tmp - 1 ? ws : sizeof tmp - 1;
    memcpy(tmp, line, cut);
    tmp[cut] = '\0';
    char *targv[FV_SHELL_MAX_ARGS];
    int targc = tokenize(tmp, targv, FV_SHELL_MAX_ARGS, NULL);
    const char *cmd = (targc > 0) ? targv[0] : NULL;

    int had_host = (wl >= 5 && !strncmp(word, "host:", 5));

    cands c;
    memset(&c, 0, sizeof c);

    if (!cmd || ws == 0) {
        complete_commands(&c, word);
    } else {
        enum { V_VAULT, V_HOST } side;
        if (!strcmp(cmd, "put"))
            side = (had_host || targc == 1) ? V_HOST : V_VAULT;
        else if (!strcmp(cmd, "get"))
            side = had_host ? V_HOST : V_VAULT;
        else if (!strcmp(cmd, "lls") || !strcmp(cmd, "lcd"))
            side = V_HOST;
        else if (!strcmp(cmd, "help"))
            side = V_VAULT;                          /* заполняем командами ниже */
        else if (!strcmp(cmd, "passwd") || !strcmp(cmd, "pwd") ||
                 !strcmp(cmd, "lpwd") || !strcmp(cmd, "info") ||
                 !strcmp(cmd, "history") ||
                 !strcmp(cmd, "exit") || !strcmp(cmd, "quit")) {
            return 0;
        } else {
            side = V_VAULT;                          /* ls cd mkdir rm cat stat mv edit */
        }

        if (!strcmp(cmd, "help")) {
            complete_commands(&c, word);
        } else if (side == V_VAULT) {
            char typed_dir[FV_PATH_MAX];
            const char *namepart;
            const char *slash = strrchr(word, '/');
            if (slash) {
                size_t dl = (size_t)(slash - word) + 1;
                if (dl >= sizeof typed_dir) { cands_free(&c); return 0; }
                memcpy(typed_dir, word, dl);
                typed_dir[dl] = '\0';
                namepart = slash + 1;
            } else {
                typed_dir[0] = '\0';
                namepart = word;
            }
            char listdir[FV_PATH_MAX];
            if (!typed_dir[0]) {
                snprintf(listdir, sizeof listdir, "%s", s->cwd);
            } else if (typed_dir[0] == '/') {
                snprintf(listdir, sizeof listdir, "%s", typed_dir);
            } else {
                vault_join(s, typed_dir, listdir, sizeof listdir);
            }
            cands raw;
            memset(&raw, 0, sizeof raw);
            if (fv_vault_list(s->v, listdir, vcand_cb, &raw) != FV_OK) {
                cands_free(&raw);
                return 0;
            }
            size_t nl = strlen(namepart);
            for (size_t i = 0; i < raw.n; i++) {
                if (!strncmp(raw.v[i].s, namepart, nl)) {
                    char full[FV_PATH_MAX + 2];
                    if (snprintf(full, sizeof full, "%s%s", typed_dir, raw.v[i].s)
                            < (int)sizeof full)
                        cands_add(&c, full, raw.v[i].dir);
                }
            }
            cands_free(&raw);
        } else {
            char w[FV_PATH_MAX];
            snprintf(w, sizeof w, "%s", word);
            if (had_host) memmove(w, w + 5, strlen(w + 5) + 1);
            char typed_dir[FV_PATH_MAX];
            const char *namepart;
            char *slash = NULL;
            for (char *q = w; *q; q++)
                if (*q == '/' || *q == '\\') slash = q;
            if (slash) {
                size_t dl = (size_t)(slash - w) + 1;
                if (dl >= sizeof typed_dir) { cands_free(&c); return 0; }
                memcpy(typed_dir, w, dl);
                typed_dir[dl] = '\0';
                namepart = slash + 1;
            } else {
                typed_dir[0] = '\0';
                namepart = w;
            }
            char hdir[FV_PATH_MAX];
            if (!typed_dir[0]) {
                strcpy(hdir, ".");
            } else if (typed_dir[0] == '~' || typed_dir[0] == '$' ||
                       typed_dir[0] == '%') {
                if (plat_expand_path(typed_dir, hdir, sizeof hdir) != FV_OK) {
                    cands_free(&c);
                    return 0;
                }
            } else {
                snprintf(hdir, sizeof hdir, "%s", typed_dir);
            }
            cands raw;
            memset(&raw, 0, sizeof raw);
            if (plat_list_dir(hdir, hcand_cb, &raw) != FV_OK) {
                cands_free(&raw);
                return 0;
            }
            size_t nl = strlen(namepart);
            for (size_t i = 0; i < raw.n; i++) {
                if (!strncmp(raw.v[i].s, namepart, nl)) {
                    char one[FV_PATH_MAX + 2];
                    if (snprintf(one, sizeof one, "%s%s", typed_dir, raw.v[i].s)
                            >= (int)sizeof one)
                        continue;
                    char full[FV_PATH_MAX + 8];
                    if (had_host)
                        snprintf(full, sizeof full, "host:%s", one);
                    else
                        snprintf(full, sizeof full, "%s", one);
                    cands_add(&c, full, raw.v[i].dir);
                }
            }
            cands_free(&raw);
        }
    }

    if (c.n == 0) { cands_free(&c); return 0; }
    qsort(c.v, c.n, sizeof(cand), cmp_cand);

    /* общий префикс после сортировки = LCP первого и последнего */
    size_t lcp = 0;
    while (c.v[0].s[lcp] && c.v[c.n - 1].s[lcp] &&
           c.v[0].s[lcp] == c.v[c.n - 1].s[lcp]) lcp++;

    if (c.n == 1 && lcp == strlen(c.v[0].s)) {
        /* единственный точный кандидат: каталог — слэш, файл/команда — пробел */
        char repl[FV_PATH_MAX + 4];
        if (snprintf(repl, sizeof repl, "%s%s", c.v[0].s, c.v[0].dir ? "/" : "")
                >= (int)sizeof repl) { cands_free(&c); return 0; }
        size_t nn = tab_replace(line, base, repl, had_q, qch, 1);
        cands_free(&c);
        if (!nn) return 0;
        *len = nn;
        return 1;
    }
    if (lcp > wl) {
        char repl[FV_PATH_MAX + 4];
        if (lcp >= sizeof repl) { cands_free(&c); return 0; }
        memcpy(repl, c.v[0].s, lcp);
        repl[lcp] = '\0';
        size_t nn = tab_replace(line, base, repl, had_q, qch, 0);
        cands_free(&c);
        if (!nn) return 0;
        *len = nn;
        return 1;
    }
    /* прогресса нет, кандидатов несколько — показать список */
    putchar('\n');
    size_t show = c.n < 200 ? c.n : 200;
    for (size_t i = 0; i < show; i++)
        printf("%s%s\n", c.v[i].s, c.v[i].dir ? "/" : "");
    if (c.n > show) printf("... и ещё %zu\n", c.n - show);
    cands_free(&c);
    return 2;
}

/* ---------- справка ---------- */

static const char *HELP_TEXT =
    "Команды внутри контейнера:\n"
    "  ls [-l] [путь]         список файлов (cd меняет текущий каталог)\n"
    "  cd [путь]              сменить каталог (без аргумента — корень)\n"
    "  pwd                    текущий каталог контейнера\n"
    "  mkdir <путь>...        создать каталог\n"
    "  mv <из> <в>            переименовать или переместить\n"
    "  rm [-r] <путь>...      удалить файл или каталог\n"
    "  cat <файл>...          вывести файл в stdout (бинарно, без искажений)\n"
    "  grep [-ivncF] <шаблон> <файл>...  строки, подходящие под шаблон\n"
    "  stat <путь>            сведения об объекте\n"
    "  put <хост>... [путь]   скопировать файлы с компьютера в контейнер\n"
    "  get <путь>... [хост]   скопировать файлы из контейнера на компьютер\n"
    "  lls [путь]             список каталога хоста\n"
    "  lcd [путь]             сменить каталог хоста\n"
    "  lpwd                   текущий каталог хоста\n"
    "  info                   сведения о контейнере\n"
    "  passwd                 сменить пароль контейнера\n"
    "  edit <файл>            редактор в памяти: ^S сохранить, ^X выход\n"
    "  history [N | -c]       история команд (-c — очистить)\n"
    "  help [<тема>]          справка по всем командам или по одной\n"
    "  exit | quit            выход\n"
    "\n"
    "Строка ввода: ←/→ двигают курсор, Home/End — в начало/конец,\n"
    "↑/↓ — предыдущие команды, Tab дополняет команды и пути (help keys).\n"
    "put/get/cat/grep принимают маски: put *.txt /документы/  (help glob)\n"
    "Конвейер: cat отчёт.txt | grep \"ошибка|warn\" | grep -v debug  (help pipe)\n"
    "Пути хоста можно помечать префиксом host:, например:\n"
    "  put host:отчёт.txt /документы/\n"
    "  get /документы/отчёт.txt host:отчёт.txt\n"
    "Справка по отдельной команде: help <команда> или <команда> --help.\n";

/* ---------- темы справки по командам ---------- */

typedef struct {
    const char *name;
    const char *text;
} sh_topic;

static const sh_topic SH_TOPICS[] = {
{ "ls",
"ls [-l] [путь] — список файлов каталога контейнера.\n"
"  ls                 содержимое текущего каталога\n"
"  ls -l              то же с размерами и временем\n"
"  ls -l /документы   конкретный каталог\n"
"Каталоги помечаются косой чертой. Относительные пути отсчитываются\n"
"от текущего каталога (см. cd/pwd), абсолютные начинаются со слэша.\n" },
{ "cd",
"cd [путь] — сменить текущий каталог контейнера.\n"
"  cd /документы   в абсолютный путь\n"
"  cd ..           на уровень вверх\n"
"  cd              в корень контейнера\n"
"Приглашение shell показывает текущий каталог.\n" },
{ "pwd",
"pwd — напечатать текущий каталог внутри контейнера.\n"
"Каталог хоста показывает lpwd, это две независимые позиции.\n" },
{ "mkdir",
"mkdir <путь>... — создать один или несколько каталогов.\n"
"  mkdir отчёты /документы/2026\n"
"Родители не создаются автоматически: путь должен вести к существующему\n"
"каталогу (это сознательно — против опечаток в путях).\n" },
{ "mv",
"mv <из> <в> — переименовать или переместить файл/каталог.\n"
"  mv черновик.txt /архив/черновик-2026.txt\n"
"  mv отчёты /архив/            каталог внутрь /архив\n"
"Если цель — существующий каталог, объект кладётся внутрь с прежним\n"
"именем. Если цель — существующий файл, он заменяется (блоб старого\n"
"удаляется). Каталог нельзя переносить внутрь самого себя.\n" },
{ "rm",
"rm [-r] <путь>... — удалить файлы/каталоги контейнера.\n"
"  rm старое.txt          файл\n"
"  rm -r /кэш             каталог со всем содержимым\n"
"Без -r каталог удаляется, только если он пуст. Восстановления нет:\n"
"блобы удалённых файлов стираются с носителя сразу.\n"
"Шаблоны (*.txt) rm сознательно не раскрывает.\n" },
{ "cat",
"cat <файл>... — вывести файлы в stdout без искажений (бинарный вывод).\n"
"  cat заметка.md\n"
"  cat a.txt b.txt\n"
"  cat /логи/*.log            маски, как в put/get (help glob)\n"
"  cat отчёт.txt | grep долг  конвейер (help pipe)\n"
"Чтобы сохранить файл на компьютер, используйте get.\n" },
{ "stat",
"stat <путь> — сведения об объекте: тип, размер, размер чанка\n"
"шифрования, время изменения. Для проверки пути используйте stat,\n"
"для содержимого каталога — ls.\n" },
{ "put",
"put <файл хоста>... [путь контейнера] — скопировать файлы с компьютера\n"
"в контейнер. Исходные файлы на хосте не изменяются и не удаляются.\n"
"  put отчёт.txt                  в текущий каталог контейнера\n"
"  put a.txt b.txt /документы     несколько файлов в каталог\n"
"  put *.txt /документы           все .txt текущего каталога хоста\n"
"  put ~/фото/IMG_*.jpg /фото/    шаблон в имени файла\n"
"  put host:данные.csv /база/     префикс host: можно писать явно\n"
"Последний аргумент — назначение: существующий каталог или путь файла;\n"
"для нескольких файлов — только каталог. Шаблоны: help glob.\n"
"Если файл с таким именем уже есть в контейнере, он заменяется целиком.\n"
"Табуляция дополняет пути хоста.\n" },
{ "get",
"get <путь>... [путь хоста] — скопировать файлы из контейнера на компьютер.\n"
"  get отчёт.txt                  в текущий каталог хоста\n"
"  get a.txt b.txt /tmp/экспорт   несколько файлов в каталог хоста\n"
"  get /документы/*.pdf ~/pdf     шаблон по файлам контейнера\n"
"  get /документы/итог.pdf host:итог.pdf\n"
"Существующие файлы на хосте НЕ перезаписываются — такие файлы\n"
"пропускаются с предупреждением, остальные копируются. Раскрытие пути\n"
"хоста — ~, $VAR, %VAR%. Табуляция дополняет пути с обеих сторон.\n" },
{ "glob",
"Маски в put, get, cat и grep (раскрываются в имени файла, не в каталогах):\n"
"  *        любая последовательность символов     *.txt, отчёт-*\n"
"  ?        ровно один символ                     файл?.log\n"
"  [abc]    один символ из набора                 [ab]*.csv\n"
"  [a-z]    один символ из диапазона              img[0-9].png\n"
"  [!abc]   любой символ, кроме перечисленных\n"
"Подходят только файлы (каталоги пропускаются). Файлы, начинающиеся\n"
"с точки, подходят, только если шаблон тоже начинается с точки.\n"
"В контейнере регистр букв различается, на диске Windows — нет.\n"
"Чтобы передать *, ? или [ буквально, возьмите аргумент в кавычки:\n"
"  put \"странное*имя.txt\"\n"
"Если ничего не подошло — ошибка, а не копирование чего-то лишнего.\n" },
{ "lls",
"lls [путь] — список каталога ХОСТА (компьютера, куда вставлена флешка).\n"
"Формат вывода совпадает с ls. Текущий каталог хоста меняется командой\n"
"lcd, показывается lpwd. Пути можно раскрывать: lls ~/документы.\n" },
{ "lcd",
"lcd [путь] — сменить текущий каталог ХОСТА (для put/get/lls).\n"
"  lcd /tmp          каталог хоста\n"
"  lcd ~             домашний каталог\n"
"  lcd               в домашний каталог\n"
"Не путать с cd — та команда меняет каталог внутри контейнера.\n" },
{ "lpwd",
"lpwd — напечатать текущий каталог хоста.\n"
"Именно сюда попадут файлы при get без явного пути.\n" },
{ "info",
"info — сведения о контейнере: uuid, формат, число итераций PBKDF2,\n"
"поколения заголовка и индекса, число файлов/каталогов и суммарный\n"
"размер содержимого. Без пароля часть этих полей показывает и внешний\n"
"`foxvault info` (без содержимого).\n" },
{ "passwd",
"passwd — сменить пароль контейнера.\n"
"Запрашивает новый пароль дважды; мастер-ключ переобворачивается новым\n"
"ключом из пароля — САМИ ДАННЫЕ НЕ ПЕРЕШИФРОВЫВАЮТСЯ, смена мгновенна.\n"
"Короткий пароль (меньше 8 символов) — только предупреждение.\n" },
{ "edit",
"edit <файл> — открыть файл контейнера в редакторе (или создать новый).\n"
"Текст правится только в памяти: на диск компьютера ничего не пишется,\n"
"^S кладёт файл прямо в зашифрованный контейнер.\n"
"  стрелки, Home/End, PgUp/PgDn   перемещение\n"
"  ввод текста, Enter, Backspace, Delete, Tab   правка\n"
"  ^S (или ^O)                    сохранить\n"
"  ^X                             выйти (при несохранённых правках спросит)\n"
"Редактор занимает весь экран; после выхода текст файла не остаётся\n"
"ни на экране, ни в прокрутке. Окончания строк CRLF сохраняются как были.\n"
"При автоблокировке экран очищается и спрашивается пароль — правки\n"
"не теряются; без пароля они стираются вместе с ключами.\n"
"Если терминал не поддерживает полноэкранный режим (пайп, скрипт),\n"
"edit работает построчно: l e i d a s q — подсказка по h.\n"
"Ограничения: файл до 16 МиБ, только текст.\n" },
{ "grep",
"grep [-ivncF] <шаблон> <файл|маска>... — строки, подходящие под шаблон.\n"
"  grep долг отчёт.txt\n"
"  grep -in \"ошибка|warn\" /логи/*.log\n"
"  grep -c TODO *.md                 число совпавших строк по файлам\n"
"  cat отчёт.txt | grep \"enth|blobs\"   то же через конвейер (help pipe)\n"
"Ключи (можно слитно: -in):\n"
"  -i   без учёта регистра (латиница и кириллица)\n"
"  -v   строки, которые НЕ подходят\n"
"  -n   номера строк\n"
"  -c   только число совпавших строк\n"
"  -F   шаблон — обычная строка, без спецсимволов\n"
"Шаблон — регулярное выражение (как grep -E):\n"
"  a|b  или      (…) группа       .  любой символ\n"
"  *  0 и более  +  1 и более      ?  0 или 1\n"
"  ^  начало строки   $  конец    [abc] [а-я] [^0-9]  наборы\n"
"  \\d цифра  \\w буква/цифра/_  \\s пробел   \\. \\| \\( — сами символы\n"
"Шаблон с | или пробелами берите в кавычки. Для нескольких файлов\n"
"перед строкой печатается имя файла. Совпадения подсвечиваются.\n" },
{ "pipe",
"Конвейер | передаёт строки одной команды в grep — всё в памяти,\n"
"без временных файлов:\n"
"  cat отчёт.txt | grep \"enth|blobs\"\n"
"  cat /логи/*.log | grep -i ошибка | grep -v debug\n"
"  ls -l /документы | grep 2026\n"
"  grep -n TODO *.c | grep -v test\n"
"Слева от | — cat, ls или grep с файлами, справа — только grep\n"
"(можно несколько подряд). | внутри кавычек — часть шаблона.\n" },
{ "history",
"history [N | -c] — команды, набранные в этом сеансе.\n"
"  history        все (до 500 последних)\n"
"  history 10     последние 10\n"
"  history -c     очистить\n"
"Стрелки ↑/↓ (или Ctrl+P/Ctrl+N) подставляют прежние команды в строку\n"
"ввода — их можно поправить и выполнить снова.\n"
"История живёт только в памяти: на диск она не пишется никогда и\n"
"затирается при выходе. Строка, начатая с пробела, в историю не попадает\n"
"(удобно для команд, которые не хочется оставлять даже в памяти).\n" },
{ "keys",
"Редактирование строки ввода:\n"
"  ←  →                символ влево/вправо (Ctrl+B / Ctrl+F)\n"
"  Ctrl+←  Ctrl+→      слово влево/вправо (в Linux также Alt+B / Alt+F)\n"
"  Home  End           в начало/конец строки (Ctrl+A / Ctrl+E)\n"
"  Backspace  Delete   удалить символ слева/под курсором\n"
"  Ctrl+W              удалить слово слева (Windows: Ctrl+Backspace,\n"
"                      Linux: Alt+Backspace)\n"
"  Ctrl+U  Ctrl+K      удалить всё слева/справа от курсора\n"
"  ↑  ↓                предыдущая/следующая команда (Ctrl+P / Ctrl+N)\n"
"  Tab                 дополнить команду или путь (по тексту до курсора)\n"
"  Enter               выполнить (курсор может быть где угодно)\n"
"  Ctrl+D              удалить символ под курсором; на пустой строке — выход\n"
"  Ctrl+C              выход из shell\n" },
{ "help",
"help [<тема>] — справка. Без аргумента: список команд.\n"
"С аргументом — подробности по команде: help put, help edit, help host.\n"
"Отдельные темы: help keys (клавиши), help glob (маски файлов),\n"
"help grep, help pipe, help history. То же самое: <команда> --help.\n" },
{ "exit",
"exit (или quit) — выйти из shell. Ключи и история стираются из памяти.\n"
"Ctrl+C и Ctrl+D на пустой строке делают то же самое.\n" },
{ "host",
"host: — префикс пути хоста. Пути контейнера и пути компьютера живут\n"
"в двух разных пространствах имён; префикс снимает неоднозначность там,\n"
"где обе стороны возможны:\n"
"  put host:отчёт.txt /документы/отчёт.txt\n"
"  get /документы/отчёт.txt host:отчёт.txt\n"
"В командах lls/lcd/put первая сторона и так хост, префикс не обязателен.\n" },
{ NULL, NULL }
};

static int sh_print_topic(const char *name)
{
    for (int i = 0; SH_TOPICS[i].name; i++)
        if (!strcmp(SH_TOPICS[i].name, name)) {
            fputs(SH_TOPICS[i].text, stdout);
            return 0;
        }
    fprintf(stderr, "help: нет справки для '%s' (help — список команд)\n", name);
    return 1;
}

static int cmd_help(shctx *s, int argc, char **argv)
{
    (void)s;
    if (argc >= 1) return sh_print_topic(argv[0]);
    fputs(HELP_TEXT, stdout);
    return 0;
}

/* ---------- встроенный редактор (только память, без диска хоста) ---------- */

#define FV_EDIT_MAX_BYTES (16u * 1024u * 1024u)
#define FV_EDIT_LINE_MAX  4096

static const char *EDIT_HELP_TEXT =
    "правка идёт целиком в памяти; на диск хоста ничего не пишется.\n"
    "  l [a b]        показать строки\n"
    "  e <N> <текст>  заменить строку N\n"
    "  i <N> [текст]  вставить строку перед N (N может быть n+1)\n"
    "  d <a> [b]      удалить строки a..b (или одну)\n"
    "  a [текст]      добавить строку в конец\n"
    "  s | w          сохранить в контейнер\n"
    "  q              выход (при изменениях — повторить), q! — без вопросов\n"
    "  h              эта справка\n";

static int edit_push(char ***arrp, size_t *n, size_t *cap,
                     const char *s, size_t len)
{
    if (*n == *cap) {
        size_t nc = *cap ? *cap * 2 : 16;
        char **na = (char **)realloc(*arrp, nc * sizeof(char *));
        if (!na) return FV_ERR_NOMEM;
        *arrp = na;
        *cap = nc;
    }
    char *cp = (char *)malloc(len + 1);
    if (!cp) return FV_ERR_NOMEM;
    memcpy(cp, s, len);
    cp[len] = '\0';
    (*arrp)[(*n)++] = cp;
    return FV_OK;
}

static void edit_free_all(char **lines, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        if (lines[i]) {
            fv_wipe(lines[i], strlen(lines[i]));
            free(lines[i]);
        }
    }
    free(lines);
}

/* пропустить пробелы, прочитать положительное число; сдвинуть *pp за число
 * и за один следующий пробел. Возврат 0 — числа на позиции нет. */
static int edit_num(const char **pp, long *out)
{
    const char *p = *pp;
    while (*p == ' ' || *p == '\t') p++;
    if (*p < '0' || *p > '9') return 0;
    long v = 0;
    while (*p >= '0' && *p <= '9') {
        v = v * 10 + (*p - '0');
        if (v > 100000000) v = 100000000;
        p++;
    }
    if (*p == ' ' || *p == '\t') p++;
    *pp = p;
    *out = v;
    return 1;
}

/* обратные вызовы полноэкранного редактора */
typedef struct {
    shctx      *s;
    const char *path;
} edit_ctx;

static int ed_save_cb(void *ctx, const uint8_t *data, size_t len)
{
    edit_ctx *c = (edit_ctx *)ctx;
    return fv_vault_write_mem(c->s->v, c->path, data, len);
}

static int ed_check_cb(void *ctx)
{
    edit_ctx *c = (edit_ctx *)ctx;
    fv_vault *v = c->s->v;
    if (plat_stat_kind(fv_vault_dir(v)) != 2) return FV_EDIT_GONE;
    if (c->s->timeout && !fv_vault_is_locked(v) &&
        fv_vault_idle_seconds(v) > c->s->timeout)
        return FV_EDIT_LOCK;
    return FV_EDIT_OK;
}

static int reauth(shctx *s);

static int ed_unlock_cb(void *ctx)
{
    edit_ctx *c = (edit_ctx *)ctx;
    fv_vault_lock(c->s->v);
    printf("автоблокировка после %llu с бездействия, ключи стёрты\n"
           "текст в редакторе сохранится, если ввести пароль\n",
           (unsigned long long)c->s->timeout);
    return reauth(c->s);
}

static void ed_touch_cb(void *ctx)
{
    edit_ctx *c = (edit_ctx *)ctx;
    fv_vault_touch(c->s->v);
}

static int cmd_edit(shctx *s, int argc, char **argv)
{
    if (argc != 1) {
        fprintf(stderr, "использование: edit <файл>\n");
        return 1;
    }
    char path[FV_PATH_MAX];
    vault_join(s, argv[0], path, sizeof path);

    fv_vstat st;
    int exists = (fv_vault_stat(s->v, path, &st) == FV_OK);
    if (exists && st.type == FV_NODE_DIR) {
        fprintf(stderr, "edit: %s: это каталог\n", argv[0]);
        return 1;
    }
    if (exists && st.size > FV_EDIT_MAX_BYTES) {
        fprintf(stderr, "edit: %s: файл больше 16 МиБ — редактор его не берёт\n",
                argv[0]);
        return 1;
    }

    uint8_t *data = NULL;
    size_t dlen = 0;
    int rc = FV_OK;
    if (exists) {
        rc = fv_vault_read_mem(s->v, path, &data, &dlen);
        if (rc != FV_OK) {
            sh_err("edit", path, rc);
            return 1;
        }
        if (dlen && memchr(data, 0, dlen)) {
            fv_wipe(data, dlen);
            free(data);
            fprintf(stderr, "edit: двоичные файлы редактор не правит\n");
            return 1;
        }
    }

    /* полноэкранный режим, если stdin и stdout — терминал */
    edit_ctx ec = { s, path };
    fv_edit_hooks hk = { &ec, ed_save_cb, ed_check_cb, ed_unlock_cb, ed_touch_cb, fv_strerror };
    rc = fv_edit_run(argv[0], data, dlen, !exists, &hk);
    if (rc != FV_ERR_ARG) {
        if (data) {
            fv_wipe(data, dlen);
            free(data);
        }
        if (rc == FV_ERR_AUTH) {
            fprintf(stderr, "foxvault: пароль не введён, несохранённые правки стёрты, выход\n");
            s->quit = 1;
        } else if (rc == FV_ERR_NOTFOUND) {
            fv_vault_lock(s->v);
            fprintf(stderr, "foxvault: носитель с контейнером недоступен, ключи стёрты\n");
            s->quit = 1;
        } else if (rc != FV_OK) {
            sh_err("edit", path, rc);
        }
        return rc == FV_OK ? 0 : 1;
    }

    /* запасной строчный режим: пайпы, скрипты, консоль без ESC-последовательностей */
    char **lines = NULL;
    size_t nlines = 0, cap = 0;
    int had_nl = 1;
    rc = FV_OK;
    if (exists) {
        had_nl = (dlen > 0 && data[dlen - 1] == '\n');
        size_t i = 0;
        while (i < dlen && rc == FV_OK) {
            size_t j = i;
            while (j < dlen && data[j] != '\n') j++;
            size_t l = j - i;
            if (l && data[i + l - 1] == '\r') l--;
            if (l >= FV_EDIT_LINE_MAX) {
                fprintf(stderr, "edit: строка %zu длиннее %d байт — строчный режим её не берёт\n",
                        nlines + 1, FV_EDIT_LINE_MAX - 1);
                rc = FV_ERR_RANGE;
                break;
            }
            rc = edit_push(&lines, &nlines, &cap, (const char *)data + i, l);
            i = (j < dlen) ? j + 1 : dlen;
        }
        fv_wipe(data, dlen);
        free(data);
        if (rc != FV_OK) {
            edit_free_all(lines, nlines);
            return 1;
        }
    } else {
        printf("edit: новый файл %s\n", argv[0]);
    }

    int dirty = 0, quit_hint = 0;
    printf("строчный редактор (в памяти): %zu строк; h — команды\n", nlines);

    char line[FV_LINE_MAX];
    for (;;) {
        char prompt[FV_PATH_MAX + 40];
        snprintf(prompt, sizeof prompt, "edit:%s%s> ", argv[0], dirty ? " *" : "");
        rc = plat_readline(prompt, line, sizeof line);
        if (rc == FV_ERR_CANCEL) break;              /* Ctrl+C/Ctrl+D — выход */
        if (rc != FV_OK) continue;

        const char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        char cbuf[8];
        size_t cl = 0;
        while (p[cl] && p[cl] != ' ' && p[cl] != '\t') cl++;
        if (cl == 0) { fputs(EDIT_HELP_TEXT, stdout); continue; }
        if (cl >= sizeof cbuf) cl = sizeof cbuf - 1;
        memcpy(cbuf, p, cl);
        cbuf[cl] = '\0';
        p += cl;

        if (!strcmp(cbuf, "h") || !strcmp(cbuf, "?")) {
            fputs(EDIT_HELP_TEXT, stdout);
            continue;
        }
        if (!strcmp(cbuf, "l")) {
            if (nlines == 0) { printf("(пусто)\n"); continue; }
            long a = 1, b = (long)nlines;
            if (edit_num(&p, &a)) {
                b = a;
                (void)edit_num(&p, &b);
            }
            if (a < 1) a = 1;
            if (b > (long)nlines) b = (long)nlines;
            if (a > b) { printf("диапазон пуст\n"); continue; }
            if (b - a + 1 > 500) {
                printf("слишком много строк — укажите диапазон: l a b\n");
                continue;
            }
            for (long k = a; k <= b; k++)
                printf("%5ld| %s\n", k, lines[k - 1]);
            continue;
        }
        if (!strcmp(cbuf, "e")) {
            long N;
            if (!edit_num(&p, &N) || N < 1 || N > (long)nlines) {
                printf("e: нужна строка 1..%zu\n", nlines);
                continue;
            }
            if (strlen(p) >= FV_EDIT_LINE_MAX) {
                printf("e: строка слишком длинная\n");
                continue;
            }
            char *nu = strdup(p);
            if (!nu) { printf("e: нет памяти\n"); continue; }
            fv_wipe(lines[N - 1], strlen(lines[N - 1]));
            free(lines[N - 1]);
            lines[N - 1] = nu;
            dirty = 1;
            quit_hint = 0;
            continue;
        }
        if (!strcmp(cbuf, "i")) {
            long N;
            if (!edit_num(&p, &N) || N < 1 || N > (long)nlines + 1) {
                printf("i: нужно место вставки 1..%zu\n", nlines + 1);
                continue;
            }
            char buf2[FV_EDIT_LINE_MAX + 2];
            if (*p) {
                snprintf(buf2, sizeof buf2, "%s", p);
            } else {
                int rr = plat_readline("строка (пустая — отмена)> ",
                                       buf2, sizeof buf2);
                if (rr != FV_OK || !buf2[0]) continue;
            }
            if (edit_push(&lines, &nlines, &cap, "", 0) != FV_OK) {
                printf("i: нет памяти\n");
                continue;
            }
            free(lines[nlines - 1]);                 /* заглушка от edit_push */
            for (long k = (long)nlines - 1; k >= N; k--)
                lines[k] = lines[k - 1];
            lines[N - 1] = strdup(buf2);
            if (!lines[N - 1]) {
                for (long k = N - 1; k < (long)nlines - 1; k++)
                    lines[k] = lines[k + 1];
                nlines--;
                printf("i: нет памяти\n");
                continue;
            }
            dirty = 1;
            quit_hint = 0;
            continue;
        }
        if (!strcmp(cbuf, "d")) {
            long a, b;
            if (!edit_num(&p, &a)) { printf("d: нужен номер строки\n"); continue; }
            b = a;
            (void)edit_num(&p, &b);
            if (a < 1) a = 1;
            if (b > (long)nlines) b = (long)nlines;
            if (a > b || nlines == 0) { printf("d: диапазон пуст\n"); continue; }
            for (long k = a; k <= b; k++) {
                fv_wipe(lines[k - 1], strlen(lines[k - 1]));
                free(lines[k - 1]);
            }
            for (long k = a; k <= (long)nlines - (b - a) - 1; k++)
                lines[k - 1] = lines[k + (b - a)];
            nlines -= (size_t)(b - a + 1);
            dirty = 1;
            quit_hint = 0;
            continue;
        }
        if (!strcmp(cbuf, "a")) {
            char buf2[FV_EDIT_LINE_MAX + 2];
            if (*p) {
                snprintf(buf2, sizeof buf2, "%s", p);
            } else {
                int rr = plat_readline("строка (пустая — отмена)> ",
                                       buf2, sizeof buf2);
                if (rr != FV_OK || !buf2[0]) continue;
            }
            if (edit_push(&lines, &nlines, &cap, buf2, strlen(buf2)) != FV_OK) {
                printf("a: нет памяти\n");
                continue;
            }
            dirty = 1;
            quit_hint = 0;
            continue;
        }
        if (!strcmp(cbuf, "s") || !strcmp(cbuf, "w")) {
            size_t total = 0;
            for (size_t k = 0; k < nlines; k++) total += strlen(lines[k]) + 1;
            if (nlines && !had_nl) total--;          /* без хвостового перевода */
            uint8_t *out = (uint8_t *)malloc(total ? total : 1);
            if (!out) { printf("s: нет памяти\n"); continue; }
            size_t o = 0;
            for (size_t k = 0; k < nlines; k++) {
                size_t l = strlen(lines[k]);
                memcpy(out + o, lines[k], l);
                o += l;
                if (k + 1 < nlines || had_nl) out[o++] = '\n';
            }
            rc = fv_vault_write_mem(s->v, path, out, total);
            fv_wipe(out, total);
            free(out);
            if (rc != FV_OK) {
                sh_err("edit", path, rc);
                continue;
            }
            printf("сохранено: %zu строк, %zu байт\n", nlines, total);
            dirty = 0;
            continue;
        }
        if (!strcmp(cbuf, "q!")) break;
        if (!strcmp(cbuf, "q")) {
            if (dirty && !quit_hint) {
                printf("есть несохранённые изменения: s — сохранить, "
                       "q — выйти всё же, q! — без сохранения\n");
                quit_hint = 1;
                continue;
            }
            break;
        }
        printf("не понял; команды: h l e i d a s q q!\n");
    }

    edit_free_all(lines, nlines);
    return 0;
}

/* ---------- автоблокировка ---------- */

static int reauth(shctx *s)
{
    for (int i = 0; i < 3; i++) {
        char pass[FV_PASS_MAX];
        int rc = plat_read_password("пароль: ", pass, sizeof pass);
        if (rc != FV_OK) return rc;
        rc = fv_vault_unlock(s->v, pass);
        fv_wipe(pass, sizeof pass);
        if (rc == FV_OK) return FV_OK;
        printf("неверный пароль (%d/3)\n", i + 1);
    }
    return FV_ERR_AUTH;
}

static uint64_t idle_timeout(void)
{
    const char *e = getenv("FV_IDLE_TIMEOUT");
    if (!e || !*e) return IDLE_DEFAULT;
    long v = atol(e);
    if (v < 0) return IDLE_DEFAULT;
    return (uint64_t)v;
}

/* ---------- главный цикл ---------- */

int fv_shell_run(fv_vault *v)
{
    shctx s;
    memset(&s, 0, sizeof s);
    s.v = v;
    strcpy(s.cwd, "/");
    s.timeout = idle_timeout();
    plat_history_init(&s.hist, HISTORY_MAX);

    char line[FV_LINE_MAX];
    char *argv[FV_SHELL_MAX_ARGS];
    unsigned char wild[FV_SHELL_MAX_ARGS];
    int ret = 0;

    for (;;) {
        /* носитель ещё на месте? */
        if (plat_stat_kind(fv_vault_dir(v)) != 2) {
            fprintf(stderr, "foxvault: носитель с контейнером недоступен, ключи стёрты\n");
            fv_vault_lock(v);
            ret = 1;
            break;
        }
        /* простой до приглашения? */
        if (s.timeout && !fv_vault_is_locked(v) &&
            fv_vault_idle_seconds(v) > s.timeout) {
            fv_vault_lock(v);
            printf("\nавтоблокировка после %llu с бездействия, ключи стёрты\n",
                   (unsigned long long)s.timeout);
            if (reauth(&s) != FV_OK) {
                fprintf(stderr, "foxvault: выход\n");
                ret = 1;
                break;
            }
        }

        char prompt[FV_PATH_MAX + 32];
        snprintf(prompt, sizeof prompt, "foxvault:%s> ", s.cwd);
        int rc = plat_readline_hist(prompt, line, sizeof line,
                                    sh_tab_complete, &s, &s.hist);
        if (rc == FV_ERR_CANCEL) {
            printf("выход\n");
            break;
        }
        if (rc != FV_OK) {
            fprintf(stderr, "foxvault: %s\n", fv_strerror(rc));
            continue;
        }
        /* долго сидели на приглашении? ключи стёрты, набранная строка
         * будет исполнена сразу после повторной разблокировки */
        if (s.timeout && !fv_vault_is_locked(v) &&
            fv_vault_idle_seconds(v) > s.timeout) {
            fv_vault_lock(v);
            printf("автоблокировка после %llu с бездействия, ключи стёрты\n",
                   (unsigned long long)s.timeout);
            if (reauth(&s) != FV_OK) {
                fprintf(stderr, "foxvault: выход\n");
                ret = 1;
                break;
            }
        }

        plat_history_add(&s.hist, line);             /* до tokenize: он режет строку */

        /* конвейер: cat/ls/grep | grep ... */
        char *segs[16];
        int nseg = split_pipes(line, segs, 16);
        if (nseg < 0) {
            fprintf(stderr, "foxvault: слишком длинный конвейер (до 16 команд)\n");
            continue;
        }
        if (nseg > 1) {
            (void)run_pipeline(&s, segs, nseg);
            fv_vault_touch(v);
            continue;
        }

        int argc = tokenize(line, argv, FV_SHELL_MAX_ARGS, wild);
        if (argc < 0) {
            fprintf(stderr, "foxvault: некорректная строка\n");
            continue;
        }
        if (argc == 0) continue;
        s.wild = wild + 1;                           /* флаги для argv + 1 */

        /* справка по команде: <команда> --help / -h */
        if (argc >= 2 && (!strcmp(argv[1], "--help") || !strcmp(argv[1], "-h"))) {
            (void)sh_print_topic(argv[0]);
            fv_vault_touch(v);
            continue;
        }

        int cmd_rc = 0;
        if (!strcmp(argv[0], "exit") || !strcmp(argv[0], "quit") ||
            !strcmp(argv[0], "q"))
            break;
        else if (!strcmp(argv[0], "ls"))      cmd_rc = cmd_ls(&s, argc - 1, argv + 1);
        else if (!strcmp(argv[0], "cd"))      cmd_rc = cmd_cd(&s, argc - 1, argv + 1);
        else if (!strcmp(argv[0], "pwd"))     cmd_rc = cmd_pwd(&s, argc - 1, argv + 1);
        else if (!strcmp(argv[0], "mkdir"))   cmd_rc = cmd_mkdir(&s, argc - 1, argv + 1);
        else if (!strcmp(argv[0], "rm"))      cmd_rc = cmd_rm(&s, argc - 1, argv + 1);
        else if (!strcmp(argv[0], "mv"))      cmd_rc = cmd_mv(&s, argc - 1, argv + 1);
        else if (!strcmp(argv[0], "cat"))     cmd_rc = cmd_cat(&s, argc - 1, argv + 1);
        else if (!strcmp(argv[0], "stat"))    cmd_rc = cmd_stat(&s, argc - 1, argv + 1);
        else if (!strcmp(argv[0], "put"))     cmd_rc = cmd_put(&s, argc - 1, argv + 1);
        else if (!strcmp(argv[0], "get"))     cmd_rc = cmd_get(&s, argc - 1, argv + 1);
        else if (!strcmp(argv[0], "lls"))     cmd_rc = cmd_lls(&s, argc - 1, argv + 1);
        else if (!strcmp(argv[0], "lcd"))     cmd_rc = cmd_lcd(&s, argc - 1, argv + 1);
        else if (!strcmp(argv[0], "lpwd"))    cmd_rc = cmd_lpwd(&s, argc - 1, argv + 1);
        else if (!strcmp(argv[0], "info"))    cmd_rc = cmd_info(&s, argc - 1, argv + 1);
        else if (!strcmp(argv[0], "passwd"))  cmd_rc = cmd_passwd(&s, argc - 1, argv + 1);
        else if (!strcmp(argv[0], "edit"))    cmd_rc = cmd_edit(&s, argc - 1, argv + 1);
        else if (!strcmp(argv[0], "history")) cmd_rc = cmd_history(&s, argc - 1, argv + 1);
        else if (!strcmp(argv[0], "grep"))    cmd_rc = cmd_grep(&s, argc - 1, argv + 1);
        else if (!strcmp(argv[0], "help"))    cmd_rc = cmd_help(&s, argc - 1, argv + 1);
        else {
            fprintf(stderr, "неизвестная команда '%s' (help — список команд)\n", argv[0]);
            cmd_rc = 1;
        }
        (void)cmd_rc;
        s.wild = NULL;
        if (s.quit) {
            ret = 1;
            break;
        }
        fv_vault_touch(v);
    }

    fv_wipe(line, sizeof line);
    plat_history_clear(&s.hist);
    return ret;
}
