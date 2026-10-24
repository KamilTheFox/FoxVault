/* Юнит-тест Tab-автодополнения: подключаем shell.c ради static-функций. */
#include "../foxvault/src/shell.c"

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

    fv_vault_free(v);
    remove("tab-тест.txt");
    remove("tab-тест2.txt");
    remove("/tmp/fv-tab-vault-host-tmp.txt");
    snprintf(cmd, sizeof cmd, "rm -rf %s", dir);
    if (system(cmd) != 0) {}

    printf(fails ? "FAIL: %d\n" : "PASS: табуляция работает (%d)\n", fails);
    return fails ? 1 : 0;
}
