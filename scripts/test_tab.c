/* Юнит-тест Tab-автодополнения: подключаем shell.c ради static-функций.
 *
 * Сборка (из корня проекта, после cmake --build build-linux):
 *   gcc -std=gnu11 -Isrc -Iconfig -Ithird_party/mbedtls/include \
 *       -DMBEDTLS_CONFIG_FILE='"foxvault_mbedtls_config.h"' \
 *       scripts/test_tab.c src/editor.c src/rx.c src/vault.c src/index.c \
 *       src/blob.c src/crypto.c src/platform.c src/util.c \
 *       build-linux/libfv_mbedtls.a -o /tmp/test_tab
 */
#include "../src/shell.c"

#include <stdio.h>
#include <stdlib.h>

static int fails = 0;

static void expect_line(const char *what, const char *got, const char *want)
{
    if (strcmp(got, want) == 0) {
        printf("  ok  - %s -> '%s'\n", what, got);
    } else {
        printf("  FAIL- %s: получено '%s', ожидалось '%s'\n", what, got, want);
        fails++;
    }
}

static void expect_int(const char *what, int got, int want)
{
    if (got == want) {
        printf("  ok  - %s\n", what);
    } else {
        printf("  FAIL- %s: получено %d, ожидалось %d\n", what, got, want);
        fails++;
    }
}

int main(void)
{
    const char *dir = "/tmp/fv-tab-vault";
    char cmd[600];
    snprintf(cmd, sizeof cmd, "rm -rf %s", dir);
    if (system(cmd) != 0) {}
    snprintf(cmd, sizeof cmd, "mkdir -p %s/host", dir);
    if (system(cmd) != 0) {}

    if (fv_vault_create(dir, "tab-pass-123") != FV_OK) {
        printf("FAIL: контейнер не создан\n");
        return 1;
    }
    /* файлы в контейнере: /заметки.txt, /документы/ (каталог) */
    const char *txt = "строка\n";
    FILE *f = fopen("/tmp/fv-tab-vault-host-tmp.txt", "wb");
    fwrite(txt, 1, strlen(txt), f);
    fclose(f);

    fv_vault *v = NULL;
    if (fv_vault_open(&v, dir, "tab-pass-123") != FV_OK) {
        printf("FAIL: контейнер не открыт\n");
        return 1;
    }
    if (fv_vault_put(v, "/tmp/fv-tab-vault-host-tmp.txt", "/заметки.txt") != FV_OK ||
        fv_vault_mkdir(v, "/документы") != FV_OK ||
        fv_vault_put(v, "/tmp/fv-tab-vault-host-tmp.txt", "/документы/итог.txt") != FV_OK) {
        printf("FAIL: подготовка контейнера\n");
        return 1;
    }
    /* файлы хоста в текущем каталоге */
    f = fopen("tab-тест.txt", "wb");
    fwrite(txt, 1, strlen(txt), f);
    fclose(f);
    f = fopen("tab-тест2.txt", "wb");
    fwrite(txt, 1, strlen(txt), f);
    fclose(f);

    shctx s;
    memset(&s, 0, sizeof s);
    s.v = v;
    strcpy(s.cwd, "/");
    s.timeout = 0;

    char line[FV_LINE_MAX];
    size_t len;
    int rc;

    printf("== Tab-дополнение\n");
    /* 1. команды: уникальный префикс */
    strcpy(line, "pu"); len = strlen(line);
    rc = sh_tab_complete(line, &len, &s);
    expect_line("команда 'pu'", line, "put ");
    if (rc != 1) { printf("  FAIL- rc=%d, ожидался 1\n", rc); fails++; }

    /* 2. команды: несколько вариантов — список */
    strcpy(line, "l"); len = strlen(line);
    rc = sh_tab_complete(line, &len, &s);
    if (rc == 2 && strcmp(line, "l") == 0)
        printf("  ok  - 'l' показывает список (ls/lcd/lpwd)\n");
    else { printf("  FAIL- 'l': rc=%d line='%s'\n", rc, line); fails++; }

    /* 3. путь контейнера: файл, уникально */
    strcpy(line, "cat /за"); len = strlen(line);
    rc = sh_tab_complete(line, &len, &s);
    expect_line("cat /за", line, "cat /заметки.txt ");

    /* 4. путь контейнера: каталог дополняется слэшем */
    strcpy(line, "cd /до"); len = strlen(line);
    rc = sh_tab_complete(line, &len, &s);
    expect_line("cd /до", line, "cd /документы/ ");

    /* 5. относительный путь из корня */
    strcpy(line, "ls до"); len = strlen(line);
    rc = sh_tab_complete(line, &len, &s);
    expect_line("ls до", line, "ls документы/ ");

    /* 6. host: путь через put: два файла с общим префиксом "tab-тест" ->
     *      частичное дополнение до общего префикса (как в bash) */
    strcpy(line, "put host:tab-те"); len = strlen(line);
    rc = sh_tab_complete(line, &len, &s);
    expect_line("put host:tab-те", line, "put host:tab-тест");

    /* 7. кавычка сохраняется при дополнении */
    strcpy(line, "cat \"/за"); len = strlen(line);
    rc = sh_tab_complete(line, &len, &s);
    expect_line("cat \"/за", line, "cat \"/заметки.txt\" ");

    /* 8. get без host: — путь контейнера */
    strcpy(line, "get /документы/и"); len = strlen(line);
    rc = sh_tab_complete(line, &len, &s);
    expect_line("get /документы/и", line, "get /документы/итог.txt ");

    /* 9. history не дополняется путями */
    strcpy(line, "history /"); len = strlen(line);
    rc = sh_tab_complete(line, &len, &s);
    expect_int("history: Tab ничего не делает", rc, 0);

    printf("== шаблоны\n");
    expect_int("*.txt ~ отчёт.txt",           glob_match("*.txt", "отчёт.txt", 0), 1);
    expect_int("*.txt !~ отчёт.csv",          glob_match("*.txt", "отчёт.csv", 0), 0);
    expect_int("?.txt ~ ё.txt (один символ UTF-8)", glob_match("?.txt", "ё.txt", 0), 1);
    expect_int("?.txt !~ ёё.txt",             glob_match("?.txt", "ёё.txt", 0), 0);
    expect_int("[а-я]* ~ мир",                glob_match("[а-я]*", "мир", 0), 1);
    expect_int("[!0-9]* !~ 1.txt",            glob_match("[!0-9]*", "1.txt", 0), 0);
    expect_int("a*b*c ~ aXXbYYc (возврат)",   glob_match("a*b*c", "aXXbYYc", 0), 1);
    expect_int("a*b*c !~ aXXbYY",             glob_match("a*b*c", "aXXbYY", 0), 0);
    expect_int("[z без ']' — буквально",      glob_match("[z", "[z", 0), 1);
    expect_int("регистр: *.TXT ~ a.txt (fold)", glob_match("*.TXT", "a.txt", 1), 1);
    expect_int("регистр: ОТЧЁТ* ~ отчёт (fold)", glob_match("ОТЧЁТ*", "отчёт.txt", 1), 1);
    expect_int("регистр: *.TXT !~ a.txt (без fold)", glob_match("*.TXT", "a.txt", 0), 0);
    expect_int("скрытый .x не под *",         name_matches("*", ".secret", 0), 0);
    expect_int("скрытый .x под .*",           name_matches(".*", ".secret", 0), 1);

    printf("== токенизатор\n");
    {
        char t[256];
        char *av[16];
        unsigned char wild[16];
        strcpy(t, "put *.txt \"a*b\" 'c?d' e[1] f");
        int n = tokenize(t, av, 16, wild);
        expect_int("6 аргументов", n, 6);
        expect_int("*.txt — шаблон", wild[1], 1);
        expect_int("\"a*b\" — буквально", wild[2], 0);
        expect_int("'c?d' — буквально", wild[3], 0);
        expect_int("e[1] — шаблон", wild[4], 1);
        expect_int("f — не шаблон", wild[5], 0);
    }

    printf("== регулярные выражения (grep)\n");
    {
        struct { const char *pat; int ic, fx; const char *s; int want; const char *sub; } T[] = {
            { "enth|blobs", 0, 0, "the blobs dir", 1, "blobs" },
            { "enth|blobs", 0, 0, "nothing",       0, NULL },
            { "a+b",        0, 0, "xxaaab",        1, "aaab" },
            { "colou?r",    0, 0, "color",         1, "color" },
            { "^abc",       0, 0, "xabc",          0, NULL },
            { "c$",         0, 0, "abc",           1, "c" },
            { "a.c",        0, 0, "aЖc",           1, "aЖc" },
            { "[а-я]+",     0, 0, "abc мир!",      1, "мир" },
            { "ПРИВЕТ",     1, 0, "скажи привет",  1, "привет" },
            { "ёж",         1, 0, "ЁЖИК",          1, "ЁЖ" },
            { "\\d+",       0, 0, "abc 2026 x",    1, "2026" },
            { "\\w+",       0, 0, "  Слово_1 ",    1, "Слово_1" },
            { "a.b",        0, 1, "axb a.b",       1, "a.b" },
            { "(ab|cd)+e",  0, 0, "xxabcdabe",     1, "abcdabe" },
            { "(a*)*b",     0, 0, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaac", 0, NULL },
            { "[^0-9]+",    0, 0, "123abc456",     1, "abc" },
        };
        for (size_t i = 0; i < sizeof T / sizeof T[0]; i++) {
            fv_rx *r = NULL;
            const char *err = NULL;
            char what[160];
            snprintf(what, sizeof what, "/%s/%s%s на '%s'", T[i].pat,
                     T[i].ic ? "i" : "", T[i].fx ? "F" : "", T[i].s);
            if (fv_rx_compile(&r, T[i].pat, T[i].ic, T[i].fx, &err) != FV_OK) {
                printf("  FAIL- %s: не скомпилировался (%s)\n", what, err);
                fails++;
                continue;
            }
            size_t a = 0, b = 0;
            int m = fv_rx_search(r, T[i].s, strlen(T[i].s), 0, &a, &b);
            char sub[128] = "";
            if (m) { memcpy(sub, T[i].s + a, b - a); sub[b - a] = '\0'; }
            if (m == T[i].want && (!m || !strcmp(sub, T[i].sub)))
                printf("  ok  - %s\n", what);
            else {
                printf("  FAIL- %s: m=%d '%s'\n", what, m, sub);
                fails++;
            }
            fv_rx_free(r);
        }
        const char *badp[] = { "(abc", "abc)", "[abc", "*a", "a\\", "[z-a]" };
        for (size_t i = 0; i < sizeof badp / sizeof badp[0]; i++) {
            fv_rx *r = NULL;
            const char *err = NULL;
            int rc2 = fv_rx_compile(&r, badp[i], 0, 0, &err);
            expect_int(badp[i], rc2 != FV_OK, 1);
            if (rc2 == FV_OK) fv_rx_free(r);
        }
    }

    printf("== конвейер: разрез по |\n");
    {
        char t1[] = "cat a.txt | grep \"x|y\" | grep -v 'q|w'";
        char *seg[8];
        expect_int("три части, | в кавычках не режет", split_pipes(t1, seg, 8), 3);
        expect_line("часть 2", seg[1], " grep \"x|y\" ");
    }

    fv_vault_free(v);
    remove("tab-тест.txt");
    remove("tab-тест2.txt");
    remove("/tmp/fv-tab-vault-host-tmp.txt");
    snprintf(cmd, sizeof cmd, "rm -rf %s", dir);
    if (system(cmd) != 0) {}

    printf(fails ? "FAIL: %d\n" : "PASS: табуляция, шаблоны и токенизатор работают (%d)\n", fails);
    return fails ? 1 : 0;
}
