/* main.c — командная строка в стиле docker.
 *
 * Снаружи контейнера:
 *   foxvault create <каталог>         — создать контейнер
 *   foxvault open <контейнер>         — войти в shell (или: foxvault <контейнер>)
 *   foxvault cp <источник> <цель>     — копия без входа; сторона контейнера
 *                                       пишется как <имя>:<путь>
 *   foxvault info <контейнер>         — сведения без пароля
 *   foxvault passwd <контейнер>       — сменить пароль
 *   foxvault destroy <контейнер>      — мгновенно уничтожить
 *   foxvault alias / unalias          — короткие имена контейнеров
 */
#include "crypto.h"
#include "platform.h"
#include "shell.h"
#include "util.h"
#include "vault.h"

#include <mbedtls/version.h>

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#if defined(__GNUC__)
#pragma GCC diagnostic ignored "-Wformat-truncation"
#endif

#define FV_VERSION "1.1.0"
#define HDR_SIZE_FALLBACK 132u

static const char *USAGE =
    "foxvault " FV_VERSION " — зашифрованный контейнер на флешке\n"
    "\n"
    "Использование:\n"
    "  foxvault create <каталог>          создать контейнер\n"
    "  foxvault open <контейнер>          войти в shell (или: foxvault <контейнер>)\n"
    "  foxvault cp <источник> <цель>      копировать без входа в shell;\n"
    "                                     сторона контейнера: <имя>:<путь>,\n"
    "                                     сторона хоста: <путь> или host:<путь>\n"
    "  foxvault info <контейнер>          сведения (без пароля)\n"
    "  foxvault passwd <контейнер>        сменить пароль\n"
    "  foxvault destroy <контейнер>       мгновенно уничтожить контейнер\n"
    "  foxvault alias [<имя> [<путь>]]    короткие имена контейнеров\n"
    "  foxvault unalias <имя>             удалить короткое имя\n"
    "  foxvault help [<команда>]          справка: вся или по команде\n"
    "  foxvault version\n"
    "\n"
    "Справка по команде: foxvault help <команда> или <команда> --help.\n"
    "\n"
    "Внутри shell: ls, cd, pwd, mkdir, mv, rm, cat, stat, put, get,\n"
    "lls, lcd, lpwd, info, passwd, edit, help, exit.\n"
    "Tab дополняет команды и пути.\n";

/* ---------- темы справки по командам ---------- */

typedef struct {
    const char *name;
    const char *text;
} help_topic;

static const help_topic TOPICS[] = {
{ "create",
"foxvault create <каталог> — создать новый контейнер.\n"
"Каталог создаётся вместе с родителями; если в нём уже есть контейнер\n"
"(header.0/header.1) — отказ. Пароль запрашивается дважды; короче\n"
"8 символов — только предупреждение.\n"
"Из пароля выводится ключ (PBKDF2-HMAC-SHA256, 600 000 итераций —\n"
"поэтому создание занимает пару секунд), этим ключом обворачивается\n"
"случайный мастер-ключ. Смена пароля потом не перешифровывает данные.\n"
"Пример: foxvault create E:\\vaults\\work\n" },
{ "open",
"foxvault open <контейнер> — открыть контейнер и войти в shell.\n"
"<контейнер> — путь к каталогу или короткое имя (alias). Пароль —\n"
"до 3 попыток. Внутри: ls, cd, put, get, edit и пр. (help — список).\n"
"То же самое: foxvault shell <контейнер> или просто foxvault <контейнер>.\n"
"Ключи хранятся только в памяти под защитой от свопа; при автоблокировке\n"
"(по умолчанию 300 с бездействия, FV_IDLE_TIMEOUT) или извлечении\n"
"носителя они стираются.\n" },
{ "shell",
"foxvault shell <контейнер> — синоним foxvault open.\n" },
{ "cp",
"foxvault cp <источник> <цель> — скопировать файл без входа в shell.\n"
"Ровно одна из сторон — контейнер: <имя>:<путь> (имя — alias или путь).\n"
"Сторона хоста — обычный путь или с явным префиксом host:.\n"
"  foxvault cp отчёт.txt work:/документы/отчёт.txt\n"
"  foxvault cp work:/документы/отчёт.txt host:копия.txt\n"
"  foxvault cp C:\\temp\\a.bin work:/       (однобуквенное C: — это диск)\n"
"Пароль запрашивается на время копирования и сразу стирается.\n"
"get-сторона не перезаписывает существующие файлы хоста; в контейнере\n"
"файл при совпадении имени заменяется.\n" },
{ "info",
"foxvault info <контейнер> — сведения БЕЗ пароля.\n"
"Показывает: uuid, формат (foxvault 1, AES-256-GCM), число итераций\n"
"PBKDF2, поколение заголовка, число блобов и суммарный размер на диске.\n"
"Имена файлов, дерево каталогов и содержимое скрыты шифрованием.\n" },
{ "passwd",
"foxvault passwd <контейнер> — сменить пароль.\n"
"Старый пароль запрашивается для входа, новый — дважды. Мастер-ключ\n"
"переобворачивается; данные не перешифровываются, смена мгновенна.\n"
"Заголовок обновляется в обоих слотах с новым поколением.\n" },
{ "destroy",
"foxvault destroy <контейнер> — мгновенно уничтожить контейнер.\n"
"Затирает header.0/header.1 (и временные обрезки) случайными байтами\n"
"и удаляет их: мастер-ключ утрачивается безвозвратно, блобы остаются,\n"
"но нечитаемы. Для подтверждения нужно набрать YES.\n"
"Операция необратима.\n" },
{ "alias",
"foxvault alias [<имя> [<путь>]] — короткие имена контейнеров.\n"
"  foxvault alias               показать все\n"
"  foxvault alias work          куда указывает 'work'\n"
"  foxvault alias work E:\\vaults\\work   задать/обновить\n"
"Имя: латиница, цифры, _ - . ; до 63 символов. Хранится на текущей\n"
"машине: %APPDATA%\\foxvault\\aliases.txt (Windows) или\n"
"~/.config/foxvault/aliases.txt (Linux). После alias контейнер можно\n"
"открывать как foxvault work и копировать как foxvault cp x work:/путь.\n" },
{ "unalias",
"foxvault unalias <имя> — удалить короткое имя. Сам контейнер\n"
"не затрагивается.\n" },
{ "version",
"foxvault version — версия программы и формат контейнера.\n" },
{ "help",
"foxvault help [<команда>] — справка. Без аргумента: общая справка.\n"
"С аргументом: подробности по команде (create, open, cp, info, passwd,\n"
"destroy, alias, unalias, version). То же самое: <команда> --help.\n" },
{ NULL, NULL }
};

static int print_topic(const char *name)
{
    for (int i = 0; TOPICS[i].name; i++)
        if (!strcmp(TOPICS[i].name, name)) {
            fputs(TOPICS[i].text, stdout);
            return 0;
        }
    fprintf(stderr, "foxvault: нет справки для '%s'\n"
                    "команды: create open cp info passwd destroy alias unalias\n",
            name);
    return 1;
}

/* ---------- ввод пароля ---------- */

static int read_pass_twice(char *buf, size_t len)
{
    int rc = plat_read_password("Введите пароль: ", buf, len);
    if (rc != FV_OK) return rc;
    char p2[FV_PASS_MAX];
    rc = plat_read_password("Повторите пароль: ", p2, sizeof p2);
    if (rc != FV_OK) {
        fv_wipe(buf, len);
        return rc;
    }
    int ok = !strcmp(buf, p2);
    fv_wipe(p2, sizeof p2);
    if (!ok) {
        fv_wipe(buf, len);
        fprintf(stderr, "foxvault: пароли не совпадают\n");
        return FV_ERR_CANCEL;
    }
    if (strlen(buf) < 8)
        fprintf(stderr, "foxvault: предупреждение: короткий пароль\n");
    return FV_OK;
}

static int open_with_password(const char *dir, fv_vault **out)
{
    char pass[FV_PASS_MAX];
    int rc = FV_ERR_AUTH;
    for (int attempt = 0; attempt < 3 && rc == FV_ERR_AUTH; attempt++) {
        rc = plat_read_password("Пароль: ", pass, sizeof pass);
        if (rc != FV_OK) return rc;
        rc = fv_vault_open(out, dir, pass);
        fv_wipe(pass, sizeof pass);
        if (rc == FV_ERR_AUTH)
            fprintf(stderr, "foxvault: %s (%d/3)\n", fv_strerror(rc), attempt + 1);
    }
    return rc;
}

/* ---------- короткие имена (alias) ---------- */

typedef struct {
    char *name;
    char *path;
} alias_ent;

typedef struct {
    alias_ent *v;
    size_t n, cap;
} alias_list;

static int alias_file(char *out, size_t n)
{
    char dir[FV_PATH_MAX];
    int rc = plat_config_dir(dir, sizeof dir);
    if (rc != FV_OK) return rc;
    snprintf(out, n, "%s%caliases.txt", dir, FV_PATH_SEP);
    return FV_OK;
}

static int alias_name_ok(const char *s)
{
    size_t l = strlen(s);
    if (!l || l > 63) return 0;
    for (size_t i = 0; i < l; i++) {
        char c = s[i];
        int ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                 (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.';
        if (!ok) return 0;
    }
    return 1;
}

static void alias_load(alias_list *al)
{
    memset(al, 0, sizeof *al);
    char path[FV_PATH_MAX];
    if (alias_file(path, sizeof path) != FV_OK) return;
    FILE *f = plat_fopen(path, "rb");
    if (!f) return;
    char line[FV_PATH_MAX + 80];
    while (fgets(line, sizeof line, f)) {
        char *tab = strchr(line, '\t');
        if (!tab) continue;
        *tab = '\0';
        char *nm = line, *pth = tab + 1;
        char *nl = pth + strlen(pth);
        while (nl > pth && (nl[-1] == '\n' || nl[-1] == '\r')) *--nl = '\0';
        if (alias_name_ok(nm) && *pth) {
            if (al->n == al->cap) {
                size_t nc = al->cap ? al->cap * 2 : 8;
                alias_ent *nv = (alias_ent *)realloc(al->v, nc * sizeof(alias_ent));
                if (!nv) break;
                al->v = nv;
                al->cap = nc;
            }
            al->v[al->n].name = strdup(nm);
            al->v[al->n].path = strdup(pth);
            if (al->v[al->n].name && al->v[al->n].path) al->n++;
        }
    }
    fclose(f);
}

static void alias_free(alias_list *al)
{
    for (size_t i = 0; i < al->n; i++) {
        free(al->v[i].name);
        free(al->v[i].path);
    }
    free(al->v);
    memset(al, 0, sizeof *al);
}

static const char *alias_lookup(const alias_list *al, const char *name)
{
    for (size_t i = 0; i < al->n; i++)
        if (!strcmp(al->v[i].name, name)) return al->v[i].path;
    return NULL;
}

static int alias_save(const alias_list *al)
{
    char path[FV_PATH_MAX], dir[FV_PATH_MAX];
    int rc = alias_file(path, sizeof path);
    if (rc != FV_OK) return rc;
    rc = fv_dirname(path, dir, sizeof dir);
    if (rc != FV_OK) return rc;
    rc = plat_mkdir_p(dir);                      /* может уже существовать */
    if (rc != FV_OK && rc != FV_ERR_EXISTS) return rc;

    char tmp[FV_PATH_MAX];
    snprintf(tmp, sizeof tmp, "%s.tmp", path);
    FILE *f = plat_fopen(tmp, "wb");
    if (!f) return FV_ERR_IO;
    rc = FV_OK;
    for (size_t i = 0; i < al->n && rc == FV_OK; i++)
        if (fprintf(f, "%s\t%s\n", al->v[i].name, al->v[i].path) < 0)
            rc = FV_ERR_IO;
    if (rc == FV_OK) rc = plat_fsync(f);
    fclose(f);
    if (rc != FV_OK) {
        plat_remove(tmp);
        return rc;
    }
    rc = plat_atomic_replace(tmp, path);
    return rc;
}

static size_t alias_index_of(const alias_list *al, const char *name);

static int cmd_alias(int argc, char **argv)
{
    alias_list al;
    alias_load(&al);

    int rc = FV_OK;
    if (argc == 0) {
        for (size_t i = 0; i < al.n; i++)
            printf("%-20s %s\n", al.v[i].name, al.v[i].path);
    } else if (argc == 1) {
        const char *p = alias_lookup(&al, argv[0]);
        if (!p) {
            fprintf(stderr, "foxvault: короткое имя '%s' не задано\n", argv[0]);
            rc = 1;
        } else {
            printf("%s\n", p);
        }
    } else if (argc == 2) {
        if (!alias_name_ok(argv[0])) {
            fprintf(stderr, "foxvault: имя '%s' не годится (латиница, цифры, _ - .)\n",
                    argv[0]);
            alias_free(&al);
            return 1;
        }
        char exp[FV_PATH_MAX];
        if (plat_expand_path(argv[1], exp, sizeof exp) != FV_OK)
            snprintf(exp, sizeof exp, "%s", argv[1]);
        const char *old = alias_lookup(&al, argv[0]);
        if (old) {
            free(al.v[alias_index_of(&al, argv[0])].path);
            al.v[alias_index_of(&al, argv[0])].path = strdup(exp);
        } else {
            if (al.n == al.cap) {
                size_t nc = al.cap ? al.cap * 2 : 8;
                alias_ent *nv = (alias_ent *)realloc(al.v, nc * sizeof(alias_ent));
                if (!nv) {
                    alias_free(&al);
                    return 1;
                }
                al.v = nv;
                al.cap = nc;
            }
            al.v[al.n].name = strdup(argv[0]);
            al.v[al.n].path = strdup(exp);
            if (!al.v[al.n].name || !al.v[al.n].path) {
                alias_free(&al);
                return 1;
            }
            al.n++;
        }
        rc = alias_save(&al);
        if (rc != FV_OK) {
            fprintf(stderr, "foxvault: %s\n", fv_strerror(rc));
            alias_free(&al);
            return 1;
        }
        printf("'%s' -> %s\n", argv[0], exp);
    } else {
        fprintf(stderr, "использование: alias [<имя> [<путь>]]\n");
        rc = 1;
    }
    alias_free(&al);
    return rc;
}

static int cmd_unalias(int argc, char **argv)
{
    if (argc != 1) {
        fprintf(stderr, "использование: unalias <имя>\n");
        return 1;
    }
    alias_list al;
    alias_load(&al);
    size_t keep = 0;
    int removed = 0;
    for (size_t i = 0; i < al.n; i++) {
        if (!removed && !strcmp(al.v[i].name, argv[0])) {
            free(al.v[i].name);
            free(al.v[i].path);
            removed = 1;
            continue;
        }
        al.v[keep++] = al.v[i];
    }
    if (!removed) {
        fprintf(stderr, "foxvault: короткое имя '%s' не задано\n", argv[0]);
        alias_free(&al);
        return 1;
    }
    al.n = keep;
    int rc = alias_save(&al);
    alias_free(&al);
    if (rc != FV_OK) {
        fprintf(stderr, "foxvault: %s\n", fv_strerror(rc));
        return 1;
    }
    printf("'%s' удалено\n", argv[0]);
    return 0;
}

static size_t alias_index_of(const alias_list *al, const char *name)
{
    for (size_t i = 0; i < al->n; i++)
        if (!strcmp(al->v[i].name, name)) return i;
    return 0;
}

/* ---------- разрешение имени контейнера ---------- */

static int resolve_container(const char *arg, char *out, size_t n,
                             int require_container)
{
    alias_list al;
    alias_load(&al);
    const char *ap = alias_lookup(&al, arg);
    char src[FV_PATH_MAX];
    snprintf(src, sizeof src, "%s", ap ? ap : arg);
    alias_free(&al);

    char exp[FV_PATH_MAX];
    if (plat_expand_path(src, exp, sizeof exp) != FV_OK)
        snprintf(exp, sizeof exp, "%s", src);

    if (require_container) {
        if (plat_stat_kind(exp) != 2) {
            fprintf(stderr, "foxvault: контейнер '%s' не найден\n", arg);
            return FV_ERR_NOTFOUND;
        }
        char p[FV_PATH_MAX];
        int has = 0;
        fv_path_join(p, sizeof p, exp, "header.0");
        has |= (plat_stat_kind(p) == 1);
        fv_path_join(p, sizeof p, exp, "header.1");
        has |= (plat_stat_kind(p) == 1);
        if (!has) {
            fprintf(stderr, "foxvault: '%s' — это не контейнер foxvault\n", arg);
            return FV_ERR_FORMAT;
        }
    }
    if (strlen(exp) >= n) return FV_ERR_RANGE;
    strcpy(out, exp);
    return FV_OK;
}

/* ---------- команды ---------- */

/* ---------- анимация создания ---------- */

typedef struct {
    uint64_t last;
    int      dots;
    int      on;                        /* рисуем только на терминале */
} dots_ctx;

static void create_progress(void *ctx, uint32_t done, uint32_t total)
{
    (void)done;
    (void)total;
    dots_ctx *d = (dots_ctx *)ctx;
    if (!d->on) return;
    uint64_t now = plat_now_ms();
    if (d->last && now - d->last < 150) return;
    d->last = now;
    d->dots = d->dots % 3 + 1;
    fprintf(stdout, "\rСоздаю контейнер%.*s   ", d->dots, "...");
    fflush(stdout);
}

static int cmd_create(int argc, char **argv)
{
    if (argc != 1) {
        fprintf(stderr, "использование: foxvault create <каталог>\n");
        return 1;
    }
    char pass[FV_PASS_MAX];
    int rc = read_pass_twice(pass, sizeof pass);
    if (rc != FV_OK) {
        if (rc != FV_ERR_CANCEL)
            fprintf(stderr, "foxvault: %s\n", fv_strerror(rc));
        return 1;
    }
    dots_ctx d = { 0, 0, plat_isatty_stdout() };
    if (d.on) {
        fprintf(stdout, "Создаю контейнер");
        fflush(stdout);
    }
    rc = fv_vault_create_ex(argv[0], pass, create_progress, &d);
    if (d.on) fputc('\n', stdout);
    fv_wipe(pass, sizeof pass);
    if (rc != FV_OK) {
        fprintf(stderr, "foxvault: %s\n", fv_strerror(rc));
        return 1;
    }
    printf("контейнер создан: %s\n", argv[0]);
    return 0;
}

static int cmd_open(int argc, char **argv)
{
    if (argc != 1) {
        fprintf(stderr, "использование: foxvault open <контейнер>\n");
        return 1;
    }
    char dir[FV_PATH_MAX];
    int rc = resolve_container(argv[0], dir, sizeof dir, 1);
    if (rc != FV_OK) return 1;

    fv_vault *v = NULL;
    rc = open_with_password(dir, &v);
    if (rc != FV_OK) {
        if (rc != FV_ERR_CANCEL)
            fprintf(stderr, "foxvault: %s\n", fv_strerror(rc));
        return 1;
    }
    int shrc = fv_shell_run(v);
    fv_vault_free(v);
    return shrc ? 1 : 0;
}

/* Разбор стороны для cp: 1 — контейнер (имя:путь или путь:путь),
 * 0 — хост, -1 — ошибка. "host:..." всегда хост; "X:\..." — диск Windows. */
static int parse_side(const char *arg, char *cont, size_t cn, char *path, size_t pn)
{
    if (!strncmp(arg, "host:", 5)) {
        if (strlen(arg + 5) >= pn) return -1;
        strcpy(path, arg + 5);
        return 0;
    }
    const char *colon = strchr(arg, ':');
    if (!colon) {
        if (strlen(arg) >= pn) return -1;
        strcpy(path, arg);
        return 0;
    }
    size_t pl = (size_t)(colon - arg);
    /* диск Windows "C:\..." или "C:" */
    if (pl == 1 && (colon[1] == '\\' || colon[1] == '/' || colon[1] == '\0'))
        goto host;
    if (pl == 0) goto host;                          /* ":path" — не для нас */

    if (pl >= cn) return -1;
    memcpy(cont, arg, pl);
    cont[pl] = '\0';
    if (colon[1] == '/' || colon[1] == '\\')
        snprintf(path, pn, "%s", colon + 1);
    else if (colon[1] == '\0')
        snprintf(path, pn, "/");
    else
        snprintf(path, pn, "/%s", colon + 1);        /* "имя:относительный" */
    return 1;

host:
    {
        const char *a = arg;
        if (!strncmp(a, "host:", 5)) a += 5;
        if (strlen(a) >= pn) return -1;
        strcpy(path, a);
    }
    return 0;
}

static int cmd_cp(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr,
                "использование: foxvault cp <источник> <цель>\n"
                "  сторона контейнера: <имя>:<путь>, хоста: <путь> или host:<путь>\n");
        return 1;
    }
    char c1[FV_PATH_MAX], p1[FV_PATH_MAX], c2[FV_PATH_MAX], p2[FV_PATH_MAX];
    int s1 = parse_side(argv[0], c1, sizeof c1, p1, sizeof p1);
    int s2 = parse_side(argv[1], c2, sizeof c2, p2, sizeof p2);
    if (s1 < 0 || s2 < 0) {
        fprintf(stderr, "foxvault: неверный путь\n");
        return 1;
    }
    if (s1 == s2) {
        fprintf(stderr,
                "foxvault: ровно одна из сторон должна быть контейнером (<имя>:<путь>)\n");
        return 1;
    }

    const char *cont = s1 ? c1 : c2;
    const char *vpath = s1 ? p1 : p2;
    const char *hpath = s1 ? p2 : p1;

    char dir[FV_PATH_MAX];
    int rc = resolve_container(cont, dir, sizeof dir, 1);
    if (rc != FV_OK) return 1;

    fv_vault *v = NULL;
    rc = open_with_password(dir, &v);
    if (rc != FV_OK) {
        if (rc != FV_ERR_CANCEL)
            fprintf(stderr, "foxvault: %s\n", fv_strerror(rc));
        return 1;
    }
    rc = s1 ? fv_vault_get(v, vpath, hpath) : fv_vault_put(v, hpath, vpath);
    fv_vault_free(v);
    if (rc != FV_OK) {
        fprintf(stderr, "foxvault: cp: %s\n", fv_strerror(rc));
        return 1;
    }
    return 0;
}

static int cmd_passwd(int argc, char **argv)
{
    if (argc != 1) {
        fprintf(stderr, "использование: foxvault passwd <контейнер>\n");
        return 1;
    }
    char dir[FV_PATH_MAX];
    int rc = resolve_container(argv[0], dir, sizeof dir, 1);
    if (rc != FV_OK) return 1;

    fv_vault *v = NULL;
    rc = open_with_password(dir, &v);
    if (rc != FV_OK) {
        if (rc != FV_ERR_CANCEL)
            fprintf(stderr, "foxvault: %s\n", fv_strerror(rc));
        return 1;
    }
    char pass[FV_PASS_MAX];
    rc = read_pass_twice(pass, sizeof pass);
    if (rc == FV_OK) rc = fv_vault_change_password(v, pass);
    fv_wipe(pass, sizeof pass);
    fv_vault_free(v);
    if (rc != FV_OK) {
        if (rc != FV_ERR_CANCEL)
            fprintf(stderr, "foxvault: %s\n", fv_strerror(rc));
        return 1;
    }
    printf("пароль изменён, данные не перешифровывались\n");
    return 0;
}

static int cmd_destroy(int argc, char **argv)
{
    if (argc != 1) {
        fprintf(stderr, "использование: foxvault destroy <контейнер>\n");
        return 1;
    }
    char dir[FV_PATH_MAX];
    int rc = resolve_container(argv[0], dir, sizeof dir, 1);
    if (rc != FV_OK) return 1;

    printf("будет мгновенно уничтожен контейнер: %s\n", dir);
    char answer[32];
    int rrc = plat_readline("наберите YES для подтверждения: ", answer, sizeof answer);
    if (rrc != FV_OK || strcmp(answer, "YES") != 0) {
        printf("отменено\n");
        return 1;
    }

    static const char *names[] = { "header.0", "header.1",
                                   "header.0.tmp", "header.1.tmp", NULL };
    for (int i = 0; names[i]; i++) {
        char p[FV_PATH_MAX];
        fv_path_join(p, sizeof p, dir, names[i]);
        if (plat_stat_kind(p) != 1) continue;
        uint64_t sz = 0;
        if (plat_file_size(p, &sz) != FV_OK) sz = HDR_SIZE_FALLBACK;
        uint8_t *rnd = (uint8_t *)malloc(sz ? (size_t)sz : 1);
        if (rnd) {
            if (fv_random(rnd, (size_t)sz) == FV_OK) {
                FILE *f = plat_fopen(p, "rb+");
                if (f) {
                    if (fwrite(rnd, 1, (size_t)sz, f) == (size_t)sz) {
                        plat_fsync(f);
                    }
                    fclose(f);
                }
            }
            free(rnd);
        }
        plat_remove(p);
    }
    plat_fsync_dir(dir);
    printf("контейнер уничтожен: мастер-ключ утрачен, блобы остались, но нечитаемы\n");
    return 0;
}

/* счётчик блобов для info (без пароля) */
typedef struct {
    size_t   n;
    uint64_t bytes;
} bctx_t;

static void blobs_count_cb(const char *name, int is_dir, uint64_t size, void *ctx)
{
    (void)name;
    if (!is_dir) {
        bctx_t *b = (bctx_t *)ctx;
        b->n++;
        b->bytes += size;
    }
}

static int cmd_info(int argc, char **argv)
{
    if (argc != 1) {
        fprintf(stderr, "использование: foxvault info <контейнер>\n");
        return 1;
    }
    char dir[FV_PATH_MAX];
    int rc = resolve_container(argv[0], dir, sizeof dir, 1);
    if (rc != FV_OK) return 1;

    /* первый валидный слот заголовка — открытые поля доступны без пароля */
    int parsed = 0;
    uint32_t gen = 0, iters = 0;
    uint8_t uuid[16];
    for (int s = 0; s < 2 && !parsed; s++) {
        char p[FV_PATH_MAX];
        snprintf(p, sizeof p, "%s%cheader.%d", dir, FV_PATH_SEP, s);
        uint64_t sz = 0;
        if (plat_file_size(p, &sz) != FV_OK || sz != 132) continue;
        uint8_t hdr[132];
        FILE *f = plat_fopen(p, "rb");
        if (!f) continue;
        size_t got = fread(hdr, 1, sizeof hdr, f);
        fclose(f);
        if (got != sizeof hdr) continue;
        if (memcmp(hdr, "FOXVAULT", 8) != 0) continue;
        if (fv_get_u32(hdr + 8) != 1) continue;
        gen = fv_get_u32(hdr + 12);
        iters = fv_get_u32(hdr + 20);
        memcpy(uuid, hdr + 56, 16);
        parsed = 1;
    }
    if (!parsed) {
        fprintf(stderr, "foxvault: %s\n", fv_strerror(FV_ERR_FORMAT));
        return 1;
    }

    /* блобы: количество и суммарный размер на диске (примерные размеры файлов) */
    char blobs[FV_PATH_MAX];
    fv_path_join(blobs, sizeof blobs, dir, "blobs");
    bctx_t bc = { 0, 0 };
    plat_list_dir(blobs, blobs_count_cb, &bc);

    char hex[33], human[32];
    fv_hex(uuid, 16, hex);
    fv_human(bc.bytes, human, sizeof human);
    printf("контейнер : %s\n", dir);
    printf("uuid      : %s\n", hex);
    printf("формат    : foxvault 1, AES-256-GCM, PBKDF2-HMAC-SHA256 %" PRIu32 " итераций\n",
           iters);
    printf("поколение : заголовок %" PRIu32 "\n", gen);
    printf("на диске  : блобов %zu, суммарно %s (имена и структура скрыты)\n",
           bc.n, human);
    return 0;
}

static int cmd_version(void)
{
    printf("foxvault %s (формат контейнера 1, mbedTLS %s)\n",
           FV_VERSION, MBEDTLS_VERSION_STRING);
    return 0;
}

/* ---------- точка входа ---------- */

int fv_main(int argc, char **argv)
{
    plat_init();
    if (argc < 2) {
        fputs(USAGE, stdout);
        return 0;
    }
    const char *cmd = argv[1];

    if (!strcmp(cmd, "help") || !strcmp(cmd, "--help") || !strcmp(cmd, "-h")) {
        if (argc >= 3) return print_topic(argv[2]);
        fputs(USAGE, stdout);
        return 0;
    }
    if (!strcmp(cmd, "version") || !strcmp(cmd, "--version"))
        return cmd_version();

    /* справка по отдельной команде: foxvault <команда> --help / -h / help */
    if (argc >= 3 && (!strcmp(argv[2], "--help") || !strcmp(argv[2], "-h") ||
                      !strcmp(argv[2], "help")))
        return print_topic(cmd);

    int rc;
    if (!strcmp(cmd, "create"))    rc = cmd_create(argc - 2, argv + 2);
    else if (!strcmp(cmd, "open") || !strcmp(cmd, "shell"))
                                   rc = cmd_open(argc - 2, argv + 2);
    else if (!strcmp(cmd, "cp"))   rc = cmd_cp(argc - 2, argv + 2);
    else if (!strcmp(cmd, "passwd")) rc = cmd_passwd(argc - 2, argv + 2);
    else if (!strcmp(cmd, "destroy")) rc = cmd_destroy(argc - 2, argv + 2);
    else if (!strcmp(cmd, "info")) rc = cmd_info(argc - 2, argv + 2);
    else if (!strcmp(cmd, "alias")) rc = cmd_alias(argc - 2, argv + 2);
    else if (!strcmp(cmd, "unalias")) rc = cmd_unalias(argc - 2, argv + 2);
    else {
        /* возможно, это контейнер — открываем shell, как `foxvault <имя>` */
        char dir[FV_PATH_MAX];
        if (resolve_container(cmd, dir, sizeof dir, 1) == FV_OK) {
            char *argp[1];
            argp[0] = (char *)cmd;
            rc = cmd_open(1, argp);
        } else {
            fprintf(stderr, "foxvault: неизвестная команда '%s'\n"
                            "foxvault help — общая справка;\n"
                            "foxvault help <команда> — справка по команде\n", cmd);
            rc = 1;
        }
    }
    return rc;
}

#ifdef _WIN32
int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    /* argv от CRT в ANSI-кодировке — берём истинные UTF-16 аргументы
     * командной строки и переводим в UTF-8 в платформенном слое */
    int n = 0;
    char **u = plat_get_argv(&n);
    if (!u) {
        fprintf(stderr, "foxvault: не удалось получить аргументы\n");
        return 1;
    }
    int rc = fv_main(n, u);
    plat_free_argv(u, n);
    return rc;
}
#else
int main(int argc, char **argv)
{
    return fv_main(argc, argv);
}
#endif
