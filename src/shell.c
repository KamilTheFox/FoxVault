/* shell.c — команды в стиле bash/sftp внутри контейнера.
 *
 * Пути хоста помечаются префиксом host: (его можно писать явно, а можно
 * опускать — команды lls/lcd/lpwd/put/get и так знают, какая сторона хост).
 */
#include "shell.h"
#include "crypto.h"
#include "platform.h"
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

typedef struct {
    fv_vault *v;
    char     cwd[FV_PATH_MAX];           /* текущий каталог внутри контейнера */
    uint64_t timeout;                    /* автоблокировка, 0 = выключена */
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

static int tokenize(char *line, char **argv, int max)
{
    int argc = 0;
    char *p = line;
    for (;;) {
        while (*p == ' ' || *p == '\t') p++;
        if (!*p) break;
        if (argc + 1 >= max) return -1;
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
                    if (*p == '\\' && (p[1] == '"' || p[1] == '\\')) p++;
                    *w++ = *p++;
                }
                if (*p) p++;
                else return -1;
                continue;
            }
            if (c == '\\') {
                p++;
                if (!*p) break;
                *w++ = *p++;
                continue;
            }
            *w++ = *p++;
        }
        *w = '\0';
    }
    argv[argc] = NULL;
    return argc;
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

/* ---------- ls / lls ---------- */

typedef struct {
    int longfmt;
} ls_ctx;

static int ls_cb(const fv_node *n, void *ctx)
{
    ls_ctx *c = (ls_ctx *)ctx;
    if (c->longfmt) {
        char when[20];
        fmt_time(n->mtime, when, sizeof when);
        if (n->type == FV_NODE_DIR)
            printf("d %10s  %s %s/\n", "-", when, n->name);
        else
            printf("- %10" PRIu64 "  %s %s\n", n->size, when, n->name);
    } else {
        printf("%s%s\n", n->name, n->type == FV_NODE_DIR ? "/" : "");
    }
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

static int cmd_ls(shctx *s, int argc, char **argv)
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

    ls_ctx c = { longfmt };
    int rc = fv_vault_list(s->v, path, ls_cb, &c);
    if (rc != FV_OK) {
        sh_err("ls", path, rc);
        return 1;
    }
    return 0;
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

static int cmd_cat(shctx *s, int argc, char **argv)
{
    if (!argc) {
        fprintf(stderr, "использование: cat <файл>...\n");
        return 1;
    }
    int bad = 0;
    for (int i = 0; i < argc; i++) {
        char path[FV_PATH_MAX];
        vault_join(s, argv[i], path, sizeof path);
        int rc = fv_vault_cat(s->v, path);
        if (rc != FV_OK) {
            sh_err("cat", path, rc);
            bad = 1;
        }
    }
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
    if (argc == 1) {
        strip_host_prefix(argv[0]);
        return fv_vault_put(s->v, argv[0], s->cwd) != FV_OK;
    }

    /* последний аргумент — путь назначения */
    char dst[FV_PATH_MAX];
    vault_join(s, argv[argc - 1], dst, sizeof dst);
    if (argc > 2) {
        /* несколько источников: назначение обязано быть каталогом */
        fv_vstat st;
        int rc = fv_vault_stat(s->v, dst, &st);
        if (rc != FV_OK || st.type != FV_NODE_DIR) {
            sh_err("put", dst, rc == FV_OK ? FV_ERR_ARG : rc);
            return 1;
        }
    }
    int bad = 0;
    for (int i = 0; i < argc - 1; i++) {
        strip_host_prefix(argv[i]);
        int rc = fv_vault_put(s->v, argv[i], dst);
        if (rc != FV_OK) {
            sh_err("put", argv[i], rc);
            bad = 1;
        }
    }
    return bad;
}

static int cmd_get(shctx *s, int argc, char **argv)
{
    if (argc < 1) {
        fprintf(stderr, "использование: get <путь контейнера>... [<путь хоста>]\n");
        return 1;
    }
    if (argc == 1)
        return fv_vault_get(s->v, argv[0], ".") != FV_OK;

    char dst[FV_PATH_MAX];
    strip_host_prefix(argv[argc - 1]);
    int rc = plat_expand_path(argv[argc - 1], dst, sizeof dst);
    if (rc != FV_OK) {
        sh_err("get", argv[argc - 1], rc);
        return 1;
    }
    if (argc > 2 && plat_stat_kind(dst) != 2) {
        fprintf(stderr, "get: %s: каталог назначения не найден\n", dst);
        return 1;
    }
    int bad = 0;
    for (int i = 0; i < argc - 1; i++) {
        char path[FV_PATH_MAX];
        vault_join(s, argv[i], path, sizeof path);
        int rc2 = fv_vault_get(s->v, path, dst);
        if (rc2 != FV_OK) {
            sh_err("get", path, rc2);
            bad = 1;
        }
    }
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
    "help", "exit", "quit", NULL
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
    int targc = tokenize(tmp, targv, FV_SHELL_MAX_ARGS);
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
    "  stat <путь>            сведения об объекте\n"
    "  put <хост>... [путь]   скопировать файл с компьютера в контейнер\n"
    "  get <путь>... [хост]   скопировать файл из контейнера на компьютер\n"
    "  lls [путь]             список каталога хоста\n"
    "  lcd [путь]             сменить каталог хоста\n"
    "  lpwd                   текущий каталог хоста\n"
    "  info                   сведения о контейнере\n"
    "  passwd                 сменить пароль контейнера\n"
    "  edit <файл>            редактор в памяти (h — команды внутри него)\n"
    "  help [<команда>]       справка по всем командам или по одной\n"
    "  exit | quit            выход\n"
    "\n"
    "Tab дополняет команды и пути (в т.ч. пути хоста для put/get/lcd/lls).\n"
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
"блобы удалённых файлов стираются с носителя сразу.\n" },
{ "cat",
"cat <файл>... — вывести файлы в stdout без искажений (бинарный вывод).\n"
"  cat заметка.md\n"
"  cat a.txt b.txt > host:сборка.txt   — так лучше через get\n"
"Поток идёт прямо в stdout; в Windows-консоли перевод строк не портится.\n" },
{ "stat",
"stat <путь> — сведения об объекте: тип, размер, размер чанка,\n"
"время изменения, имя блоба (для файлов). Для проверки целого пути\n"
"используйте stat, для содержимого каталога — ls.\n" },
{ "put",
"put <файл хоста>... [путь контейнера] — скопировать файлы с компьютера\n"
"в контейнер. Исходные файлы на хосте не изменяются и не удаляются.\n"
"  put отчёт.txt                  в текущий каталог контейнера\n"
"  put a.txt b.txt /документы     несколько файлов в каталог\n"
"  put host:данные.csv /база/     префикс host: можно писать явно\n"
"Последний аргумент — назначение: существующий каталог или путь файла.\n"
"Если файл с таким именем уже есть в контейнере, он заменяется целиком.\n"
"Табуляция дополняет пути хоста.\n" },
{ "get",
"get <путь>... [путь хоста] — скопировать файлы из контейнера на компьютер.\n"
"  get отчёт.txt                  в текущий каталог хоста\n"
"  get a.txt b.txt /tmp/экспорт   несколько файлов в каталог хоста\n"
"  get /документы/итог.pdf host:итог.pdf\n"
"Существующие файлы на хосте НЕ перезаписываются — выберите другое имя\n"
"или удалите файл сами. Раскрытие хоста — по plat_expand_path\n"
"(~, $VAR, %VAR%). Табуляция дополняет пути с обеих сторон.\n" },
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
"размер содержимого. Без пароля те же поля показывает и внешний\n"
"`foxvault info` (кроме содержимого).\n" },
{ "passwd",
"passwd — сменить пароль контейнера.\n"
"Запрашивает новый пароль дважды; мастер-ключ переобворачивается новым\n"
"ключом из пароля — САМИ ДАННЫЕ НЕ ПЕРЕШИФРОВЫВАЮТСЯ, смена мгновенна.\n"
"Короткий пароль (меньше 8 символов) — только предупреждение.\n" },
{ "edit",
"edit <файл> — правка текстового файла целиком в памяти.\n"
"На диск хоста ничего не пишется никогда; сохранение (s) кладёт текст\n"
"прямо в зашифрованный контейнер.\n"
"Команды редактора:\n"
"  l [a b]        показать строки\n"
"  e <N> <текст>  заменить строку N\n"
"  i <N> [текст]  вставить строку перед N (N может быть n+1)\n"
"  d <a> [b]      удалить строки a..b\n"
"  a [текст]      добавить в конец\n"
"  s | w          сохранить в контейнер\n"
"  q              выход (при изменениях — повторить), q! — без сохранения\n"
"Ограничения: файл до 1 МиБ, строки до 4095 байт, только текст\n"
"(файлы с нулевыми байтами редактор не открывает).\n" },
{ "help",
"help [<команда>] — справка. Без аргумента: список команд.\n"
"С аргументом — подробности по команде: help put, help edit, help host.\n"
"То же самое: <команда> --help. Tab дополняет имена команд.\n" },
{ "exit",
"exit (или quit) — выйти из shell. Ключи стираются из памяти.\n"
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

#define FV_EDIT_MAX_BYTES (1024u * 1024u)
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
        fprintf(stderr, "edit: %s: файл больше 1 МиБ — редактор его не берёт\n",
                argv[0]);
        return 1;
    }

    char **lines = NULL;
    size_t nlines = 0, cap = 0;
    int had_nl = 1;
    int rc = FV_OK;

    if (exists) {
        uint8_t *data = NULL;
        size_t dlen = 0;
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
        had_nl = (dlen > 0 && data[dlen - 1] == '\n');
        size_t i = 0;
        while (i < dlen && rc == FV_OK) {
            size_t j = i;
            while (j < dlen && data[j] != '\n') j++;
            size_t l = j - i;
            if (l && data[i + l - 1] == '\r') l--;
            if (l >= FV_EDIT_LINE_MAX) {
                fprintf(stderr, "edit: строка %zu длиннее %d байт — не берём\n",
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
    printf("редактор (в памяти): %zu строк; h — команды\n", nlines);

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
    s.v = v;
    strcpy(s.cwd, "/");
    s.timeout = idle_timeout();

    char line[FV_LINE_MAX];
    char *argv[FV_SHELL_MAX_ARGS];

    for (;;) {
        /* носитель ещё на месте? */
        if (plat_stat_kind(fv_vault_dir(v)) != 2) {
            fprintf(stderr, "foxvault: носитель с контейнером недоступен, ключи стёрты\n");
            fv_vault_lock(v);
            return 1;
        }
        /* простой до приглашения? */
        if (s.timeout && !fv_vault_is_locked(v) &&
            fv_vault_idle_seconds(v) > s.timeout) {
            fv_vault_lock(v);
            printf("\nавтоблокировка после %llu с бездействия, ключи стёрты\n",
                   (unsigned long long)s.timeout);
            if (reauth(&s) != FV_OK) {
                fprintf(stderr, "foxvault: выход\n");
                return 1;
            }
        }

        char prompt[FV_PATH_MAX + 32];
        snprintf(prompt, sizeof prompt, "foxvault:%s> ", s.cwd);
        int rc = plat_readline_ex(prompt, line, sizeof line,
                                  sh_tab_complete, &s);
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
                return 1;
            }
        }

        int argc = tokenize(line, argv, FV_SHELL_MAX_ARGS);
        if (argc < 0) {
            fprintf(stderr, "foxvault: некорректная строка\n");
            continue;
        }
        if (argc == 0) continue;

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
        else if (!strcmp(argv[0], "help"))    cmd_rc = cmd_help(&s, argc - 1, argv + 1);
        else {
            fprintf(stderr, "неизвестная команда '%s' (help — список команд)\n", argv[0]);
            cmd_rc = 1;
        }
        (void)cmd_rc;
        fv_vault_touch(v);
    }
    return 0;
}
