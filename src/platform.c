/* platform.c — всё, что зависит от ОС.
 *
 * Windows: пути внутри переводятся из UTF-8 в UTF-16 и идут в *W-функции,
 *          поэтому кириллица работает во всех путях. Консоль переводится
 *          в UTF-8; строка shell читается посимвольно через ReadConsoleInputW
 *          (UTF-16), а рисуется только через WriteConsoleW.
 * POSIX:   предполагается UTF-8 локаль; пароль вводится без эха через termios.
 */
#include "platform.h"
#include "util.h"
#include "crypto.h"

#include <stdlib.h>
#include <string.h>

#ifdef _WIN32

/* ============================== Windows ============================== */

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif

#include <windows.h>
#include <bcrypt.h>
#include <shellapi.h>
#include <direct.h>
#include <errno.h>
#include <signal.h>
#include <sys/stat.h>

#ifndef NT_SUCCESS
#define NT_SUCCESS(s) (((NTSTATUS)(s)) >= 0)
#endif

/* ---------- UTF-8 <-> UTF-16 ---------- */

static int utf8_to_utf16(const char *s, wchar_t **out)
{
    if (!s || !out) return FV_ERR_ARG;
    int n = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
    if (n <= 0) return FV_ERR_ARG;
    wchar_t *w = (wchar_t *)malloc((size_t)n * sizeof(wchar_t));
    if (!w) return FV_ERR_NOMEM;
    if (MultiByteToWideChar(CP_UTF8, 0, s, -1, w, n) != n) {
        free(w);
        return FV_ERR_ARG;
    }
    *out = w;
    return FV_OK;
}

char *plat_wchar_to_utf8(const wchar_t *ws)
{
    if (!ws) return NULL;
    int n = WideCharToMultiByte(CP_UTF8, 0, ws, -1, NULL, 0, NULL, NULL);
    if (n <= 0) return NULL;
    char *s = (char *)malloc((size_t)n);
    if (!s) return NULL;
    if (WideCharToMultiByte(CP_UTF8, 0, ws, -1, s, n, NULL, NULL) != n) {
        free(s);
        return NULL;
    }
    return s;
}

char **plat_get_argv(int *argc)
{
    if (!argc) return NULL;
    int n = 0;
    LPWSTR *w = CommandLineToArgvW(GetCommandLineW(), &n);
    if (!w || n <= 0) return NULL;
    char **u = (char **)calloc((size_t)n + 1, sizeof(char *));
    if (!u) {
        LocalFree(w);
        return NULL;
    }
    for (int i = 0; i < n; i++) {
        u[i] = plat_wchar_to_utf8(w[i]);
        if (!u[i]) {
            plat_free_argv(u, i);
            LocalFree(w);
            return NULL;
        }
    }
    LocalFree(w);
    *argc = n;
    return u;
}

void plat_free_argv(char **argv, int argc)
{
    if (!argv) return;
    for (int i = 0; i < argc; i++) free(argv[i]);
    free(argv);
}

void plat_init(void)
{
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    SetErrorMode(SEM_FAILCRITICALERRORS);
    signal(SIGINT, SIG_IGN);    /* выход — только по команде exit/quit */
    signal(SIGBREAK, SIG_IGN);
}

int plat_random(void *buf, size_t len)
{
    if (len && !buf) return FV_ERR_ARG;
    if (!len) return FV_OK;
    if (NT_SUCCESS(BCryptGenRandom(NULL, (PUCHAR)buf, (ULONG)len,
                                   BCRYPT_USE_SYSTEM_PREFERRED_RNG)))
        return FV_OK;
    return FV_ERR_IO;
}

/* чтение одной строки из перенаправленного stdin (когда это не консоль) */
static int read_line_common(char *buf, size_t len)
{
    if (len < 2) return FV_ERR_ARG;
    if (!fgets(buf, (int)len, stdin)) {
        clearerr(stdin);
        return FV_ERR_CANCEL;
    }
    size_t n = strlen(buf);
    if (n && buf[n - 1] == '\n') {
        buf[--n] = '\0';
        if (n && buf[n - 1] == '\r') buf[--n] = '\0';
    } else if (n == len - 1) {
        int c;
        while ((c = fgetc(stdin)) != '\n' && c != EOF) {}
        clearerr(stdin);
        return FV_ERR_RANGE;
    }
    return FV_OK;
}

int plat_read_password(const char *prompt, char *buf, size_t len)
{
    if (!buf || len < 2) return FV_ERR_ARG;
    buf[0] = '\0';
    if (prompt && *prompt) {
        fputs(prompt, stdout);
        fflush(stdout);
    }

    int rc = FV_OK;
    wchar_t *wacc = NULL;
    size_t wlen = 0, wcap = 0;

    HANDLE h = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;
    int is_con = GetConsoleMode(h, &mode) != 0;

    if (is_con) {
        /* посимвольный ввод без эха: backspace работает, на экран ничего не выводится */
        wcap = len + 16;
        wacc = (wchar_t *)malloc(wcap * sizeof(wchar_t));
        if (!wacc) return FV_ERR_NOMEM;
        SetConsoleMode(h, mode & ~((DWORD)ENABLE_ECHO_INPUT | (DWORD)ENABLE_LINE_INPUT));
        for (;;) {
            wchar_t wc;
            DWORD rd = 0;
            if (!ReadConsoleW(h, &wc, 1, &rd, NULL) || rd == 0) {
                rc = FV_ERR_CANCEL;
                break;
            }
            if (wc == L'\r' || wc == L'\n') break;
            if (wc == 0x03 || wc == 0x1A) {            /* Ctrl+C / Ctrl+Z */
                rc = FV_ERR_CANCEL;
                break;
            }
            if (wc == L'\b' || wc == 0x7F) {
                if (wlen) wlen--;
                continue;
            }
            if (wlen + 1 < wcap) wacc[wlen++] = wc;
        }
        SetConsoleMode(h, mode);
        fputs("\n", stdout);
        fflush(stdout);

        if (rc == FV_OK) {
            wacc[wlen] = L'\0';
            char *u = plat_wchar_to_utf8(wacc);
            if (!u) {
                rc = FV_ERR_NOMEM;
            } else {
                if (strlen(u) >= len) rc = FV_ERR_RANGE;
                else { size_t n = strlen(u); memcpy(buf, u, n + 1); }
                fv_wipe(u, strlen(u));                 /* пароль — затираем копию */
                free(u);
            }
        }
    } else {
        rc = read_line_common(buf, len);               /* пароль пришёл по пайпу */
    }

    if (wacc) {
        fv_wipe(wacc, wcap * sizeof(wchar_t));
        free(wacc);
    }
    if (rc != FV_OK) fv_wipe(buf, len);
    return rc;
}

int plat_readline(const char *prompt, char *buf, size_t len)
{
    return plat_readline_ex(prompt, buf, len, NULL, NULL);
}

int plat_isatty_stdin(void)
{
    DWORD m = 0;
    return GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), &m) != 0;
}

int plat_isatty_stdout(void)
{
    DWORD m = 0;
    return GetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE), &m) != 0;
}

uint64_t plat_now_ms(void)
{
    return (uint64_t)GetTickCount64();
}

/* ---------- строчный редактор с Tab (Windows-консоль) ---------- */

/* Нарисовать приглашение + строку, начиная с позиции *org.
 *
 * Приглашение рисуется ТОЛЬКО здесь (через WriteConsoleW). Раньше оно
 * сначала печаталось через fputs, а *org бралась уже после него, и каждая
 * перерисовка дописывала второе приглашение справа от первого.
 *
 * *lastw — сколько ячеек занимал прошлый вывод: их затираем пробелами.
 * Если вывод упёрся в низ буфера и консоль прокрутилась, начало строки
 * сдвигается вверх — *org пересчитывается по фактической позиции курсора. */
static void con_redraw(HANDLE hOut, COORD *org, const char *prompt,
                       const char *line, DWORD *lastw)
{
    DWORD wr = 0;
    if (*lastw)
        FillConsoleOutputCharacterW(hOut, L' ', *lastw, *org, &wr);
    SetConsoleCursorPosition(hOut, *org);

    char both[FV_PATH_MAX + 256];
    snprintf(both, sizeof both, "%s%s", prompt ? prompt : "", line);
    DWORD cells = 0;
    int n = MultiByteToWideChar(CP_UTF8, 0, both, -1, NULL, 0);
    if (n > 1) {
        wchar_t *w = (wchar_t *)malloc((size_t)n * sizeof(wchar_t));
        if (w && MultiByteToWideChar(CP_UTF8, 0, both, -1, w, n) == n) {
            WriteConsoleW(hOut, w, (DWORD)n - 1, &wr, NULL);
            cells = (DWORD)n - 1;
        }
        free(w);
    }
    *lastw = cells;

    CONSOLE_SCREEN_BUFFER_INFO csbi;
    if (cells && GetConsoleScreenBufferInfo(hOut, &csbi) && csbi.dwSize.X > 0) {
        long width  = csbi.dwSize.X;
        long last_y = (long)org->Y + ((long)org->X + (long)cells - 1) / width;
        long cur_y  = csbi.dwCursorPosition.Y;
        if (cur_y < last_y) {                        /* буфер прокрутился */
            long ny = (long)org->Y - (last_y - cur_y);
            org->Y = (SHORT)(ny < 0 ? 0 : ny);
        }
    }
}

int plat_readline_ex(const char *prompt, char *buf, size_t len,
                     plat_complete_fn fn, void *fn_ctx)
{
    if (!buf || len < 2) return FV_ERR_ARG;
    buf[0] = '\0';

    HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD inmode = 0, outmode = 0;
    int con_in = GetConsoleMode(hIn, &inmode) != 0;
    int con_out = GetConsoleMode(hOut, &outmode) != 0;

    if (!con_in) {                                   /* пайп: как раньше */
        if (prompt && *prompt) {
            fputs(prompt, stdout);
            fflush(stdout);
        }
        return read_line_common(buf, len);
    }

    /* всё, что CRT накопил в буфере stdout, должно оказаться на экране
     * раньше, чем мы запомним позицию курсора */
    fflush(stdout);

    COORD org = { 0, 0 };
    DWORD lastw = 0;
    if (con_out) {
        CONSOLE_SCREEN_BUFFER_INFO csbi;
        if (GetConsoleScreenBufferInfo(hOut, &csbi))
            org = csbi.dwCursorPosition;
        else
            con_out = 0;
    }
    if (con_out) {
        con_redraw(hOut, &org, prompt, "", &lastw);  /* приглашение — один раз */
    } else if (prompt && *prompt) {
        fputs(prompt, stdout);
        fflush(stdout);
    }

    /* посимвольный ввод без линейного буфера и без эха (эхо рисуем сами) */
    SetConsoleMode(hIn, inmode & ~((DWORD)ENABLE_LINE_INPUT |
                                   (DWORD)ENABLE_ECHO_INPUT |
                                   (DWORD)ENABLE_PROCESSED_INPUT));

    size_t n = 0;
    int rc = FV_OK;
    wchar_t pend_hi = 0;                             /* верхняя половина суррогатной пары */

    for (;;) {
        INPUT_RECORD ir;
        DWORD rd = 0;
        if (!ReadConsoleInputW(hIn, &ir, 1, &rd) || rd == 0) {
            rc = FV_ERR_CANCEL;
            break;
        }
        if (ir.EventType != KEY_EVENT || !ir.Event.KeyEvent.bKeyDown)
            continue;

        /* Символ — только из UnicodeChar. Раньше читался AsciiChar (младший
         * байт UTF-16 с расширением знака): кириллица превращалась в цифры,
         * латиницу и управляющие коды, а байты >= 0x80 — в U+FF80..U+FFFF
         * (полуширинные катакана/хангыль — те самые «иероглифы»). */
        wchar_t wc = ir.Event.KeyEvent.uChar.UnicodeChar;
        WORD vk = ir.Event.KeyEvent.wVirtualKeyCode;
        WORD rep = ir.Event.KeyEvent.wRepeatCount ? ir.Event.KeyEvent.wRepeatCount : 1;

        if (wc == L'\r' || wc == L'\n' || vk == VK_RETURN) break;
        if (wc == 0x03) { rc = FV_ERR_CANCEL; break; }          /* Ctrl+C */
        if (wc == 0x04 && n == 0) { rc = FV_ERR_CANCEL; break; }/* Ctrl+D на пустой */
        if (wc == L'\t' || (vk == VK_TAB && !wc)) {
            if (fn) {
                buf[n] = '\0';
                size_t nl = n;
                int act = fn(buf, &nl, fn_ctx);
                if (act) {
                    n = nl;
                    buf[n] = '\0';
                    if (act == 2) {                  /* варианты напечатаны: новая позиция */
                        fflush(stdout);
                        if (con_out) {
                            CONSOLE_SCREEN_BUFFER_INFO csbi;
                            if (GetConsoleScreenBufferInfo(hOut, &csbi))
                                org = csbi.dwCursorPosition;
                            org.X = 0;
                        }
                        lastw = 0;
                    }
                    if (con_out) con_redraw(hOut, &org, prompt, buf, &lastw);
                    else { fputs("\r", stdout); fputs(prompt, stdout); fputs(buf, stdout); fflush(stdout); }
                }
            }
            continue;
        }
        if (wc == L'\b' || wc == 0x7F || vk == VK_BACK) {
            int changed = 0;
            for (WORD r = 0; r < rep && n; r++) {
                while (n > 0 && (buf[n - 1] & 0xC0) == 0x80) n--;   /* хвост UTF-8 */
                if (n) n--;
                changed = 1;
            }
            if (changed) {
                buf[n] = '\0';
                if (con_out) con_redraw(hOut, &org, prompt, buf, &lastw);
                else { fputs("\r", stdout); fputs(prompt, stdout); fputs(buf, stdout); fflush(stdout); }
            }
            continue;
        }
        if (wc == 0x15) {                            /* Ctrl+U — очистить строку */
            n = 0;
            buf[0] = '\0';
            if (con_out) con_redraw(hOut, &org, prompt, buf, &lastw);
            else { fputs("\r", stdout); fputs(prompt, stdout); fflush(stdout); }
            continue;
        }
        if (!wc) continue;                           /* стрелки/F-клавиши и пр. */
        if (wc < L' ') continue;                     /* прочие управляющие */

        /* wchar -> UTF-8 (с суррогатными парами) */
        wchar_t pair[2];
        int wn = 1;
        if (pend_hi) {
            if (wc >= 0xDC00 && wc <= 0xDFFF) {
                pair[0] = pend_hi;
                pair[1] = wc;
                wn = 2;
                pend_hi = 0;
                rep = 1;
            } else {
                pend_hi = 0;                         /* битая пара — пропускаем старшую */
                if (wc >= 0xD800 && wc <= 0xDBFF) { pend_hi = wc; continue; }
                pair[0] = wc;
            }
        } else if (wc >= 0xD800 && wc <= 0xDBFF) {
            pend_hi = wc;
            continue;
        } else if (wc >= 0xDC00 && wc <= 0xDFFF) {
            continue;                                /* одинокая младшая половина */
        } else {
            pair[0] = wc;
        }
        char u8[8];
        int m = WideCharToMultiByte(CP_UTF8, 0, pair, wn, u8, (int)sizeof u8, NULL, NULL);
        if (m <= 0) continue;
        int added = 0;
        for (WORD r = 0; r < rep; r++) {             /* автоповтор клавиши */
            if (n + (size_t)m + 1 >= len) break;     /* буфер полон */
            memcpy(buf + n, u8, (size_t)m);
            n += (size_t)m;
            added++;
        }
        if (!added) continue;
        buf[n] = '\0';
        if (con_out) con_redraw(hOut, &org, prompt, buf, &lastw);
        else {
            for (int r = 0; r < added; r++) fwrite(u8, 1, (size_t)m, stdout);
            fflush(stdout);
        }
    }

    SetConsoleMode(hIn, inmode);
    fputs("\n", stdout);
    fflush(stdout);
    if (rc != FV_OK) buf[0] = '\0';
    else if (n >= len) rc = FV_ERR_RANGE;
    return rc;
}

/* ---------- защита памяти ---------- */

int plat_lock_mem(void *p, size_t len)
{
    if (!p || !len) return FV_OK;
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    uintptr_t a = (uintptr_t)p;
    uintptr_t e = a + len;
    uintptr_t pg = (uintptr_t)si.dwPageSize;
    a &= ~(pg - 1);
    e = (e + pg - 1) & ~(pg - 1);
    return VirtualLock((LPVOID)a, (SIZE_T)(e - a)) ? FV_OK : FV_ERR_IO;
}

void plat_unlock_mem(void *p, size_t len)
{
    if (!p || !len) return;
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    uintptr_t a = (uintptr_t)p;
    uintptr_t e = a + len;
    uintptr_t pg = (uintptr_t)si.dwPageSize;
    a &= ~(pg - 1);
    e = (e + pg - 1) & ~(pg - 1);
    VirtualUnlock((LPVOID)a, (SIZE_T)(e - a));   /* неудача не интересна */
}

/* ---------- файлы ---------- */

FILE *plat_fopen(const char *path, const char *mode)
{
    wchar_t *w = NULL;
    FILE *f = NULL;
    if (utf8_to_utf16(path, &w) != FV_OK) return NULL;
    wchar_t wmode[16];
    size_t ml = strlen(mode);
    if (ml >= sizeof(wmode) / sizeof(wmode[0])) {
        free(w);
        return NULL;
    }
    for (size_t i = 0; i <= ml; i++) wmode[i] = (wchar_t)mode[i];
    f = _wfopen(w, wmode);
    free(w);
    return f;
}

int plat_fsync(FILE *f)
{
    if (!f) return FV_ERR_ARG;
    if (fflush(f) != 0) return FV_ERR_IO;
    return _commit(_fileno(f)) == 0 ? FV_OK : FV_ERR_IO;
}

int plat_fsync_dir(const char *dir)
{
    (void)dir;                                   /* на Windows гарантий нет */
    return FV_OK;
}

int plat_atomic_replace(const char *tmp, const char *dst)
{
    wchar_t *wt = NULL, *wd = NULL;
    int rc = FV_OK;
    if (utf8_to_utf16(tmp, &wt) != FV_OK || utf8_to_utf16(dst, &wd) != FV_OK) {
        rc = FV_ERR_ARG;
        goto done;
    }
    if (!MoveFileExW(wt, wd, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
        rc = FV_ERR_IO;
done:
    free(wt);
    free(wd);
    return rc;
}

int plat_mkdir(const char *path)
{
    wchar_t *w = NULL;
    int rc;
    if (utf8_to_utf16(path, &w) != FV_OK) return FV_ERR_ARG;
    if (_wmkdir(w) == 0) rc = FV_OK;
    else                 rc = (errno == EEXIST) ? FV_ERR_EXISTS : FV_ERR_IO;
    free(w);
    return rc;
}

int plat_mkdir_p(const char *path)
{
    char tmp[FV_PATH_MAX];
    size_t l = strlen(path);
    if (l >= sizeof tmp) return FV_ERR_RANGE;
    strcpy(tmp, path);
    while (l > 1 && (tmp[l - 1] == '/' || tmp[l - 1] == '\\')) tmp[--l] = '\0';

    size_t i = 0;
    if (tmp[0] == '/' || tmp[0] == '\\') {
        i = 1;
        if (tmp[1] == '\\' || tmp[1] == '/') {          /* UNC: \\server\share */
            i = 2;
            while (tmp[i] && tmp[i] != '\\' && tmp[i] != '/') i++;
            if (tmp[i]) i++;
            while (tmp[i] && tmp[i] != '\\' && tmp[i] != '/') i++;
            if (tmp[i]) i++;
        }
    } else if (((tmp[0] >= 'A' && tmp[0] <= 'Z') ||
                (tmp[0] >= 'a' && tmp[0] <= 'z')) && tmp[1] == ':') {
        i = 2;
        if (tmp[2] == '\\' || tmp[2] == '/') i = 3;
    }

    for (; tmp[i]; i++) {
        if (tmp[i] == '/' || tmp[i] == '\\') {
            char c = tmp[i];
            tmp[i] = '\0';
            if (tmp[0] && plat_mkdir(tmp) != FV_OK && plat_stat_kind(tmp) != 2)
                return FV_ERR_IO;
            tmp[i] = c;
        }
    }
    if (tmp[0] && plat_mkdir(tmp) != FV_OK && plat_stat_kind(tmp) != 2)
        return FV_ERR_IO;
    return plat_stat_kind(tmp) == 2 ? FV_OK : FV_ERR_IO;
}

int plat_remove(const char *path)
{
    int k = plat_stat_kind(path);
    if (k == 0) return FV_ERR_NOTFOUND;
    wchar_t *w = NULL;
    int rc;
    if (utf8_to_utf16(path, &w) != FV_OK) return FV_ERR_ARG;
    BOOL ok = (k == 2) ? RemoveDirectoryW(w) : DeleteFileW(w);
    rc = ok ? FV_OK : FV_ERR_IO;
    free(w);
    return rc;
}

int plat_stat_kind(const char *path)
{
    wchar_t *w = NULL;
    int rc = 0;
    if (utf8_to_utf16(path, &w) != FV_OK) return 0;
    DWORD a = GetFileAttributesW(w);
    if (a != INVALID_FILE_ATTRIBUTES)
        rc = (a & FILE_ATTRIBUTE_DIRECTORY) ? 2 : 1;
    free(w);
    return rc;
}

int plat_file_size(const char *path, uint64_t *size)
{
    wchar_t *w = NULL;
    int rc = FV_OK;
    if (utf8_to_utf16(path, &w) != FV_OK) return FV_ERR_ARG;
    struct __stat64 st;
    if (_wstat64(w, &st) != 0) rc = FV_ERR_NOTFOUND;
    else *size = (uint64_t)st.st_size;
    free(w);
    return rc;
}

int plat_getcwd(char *buf, size_t len)
{
    wchar_t *w = _wgetcwd(NULL, 0);
    if (!w) return FV_ERR_IO;
    char *u = plat_wchar_to_utf8(w);
    free(w);
    if (!u) return FV_ERR_NOMEM;
    int rc = FV_OK;
    if (strlen(u) >= len) rc = FV_ERR_RANGE;
    else strcpy(buf, u);
    free(u);
    return rc;
}

int plat_chdir(const char *path)
{
    wchar_t *w = NULL;
    int rc;
    if (utf8_to_utf16(path, &w) != FV_OK) return FV_ERR_ARG;
    rc = (_wchdir(w) == 0) ? FV_OK : FV_ERR_IO;
    free(w);
    return rc;
}

int plat_list_dir(const char *path, plat_dir_cb cb, void *ctx)
{
    wchar_t *wdir = NULL;
    wchar_t *wpath = NULL;
    int rc = FV_OK;
    if (utf8_to_utf16(path, &wdir) != FV_OK) return FV_ERR_ARG;

    size_t dl = wcslen(wdir);
    wpath = (wchar_t *)malloc((dl + 3) * sizeof(wchar_t));
    if (!wpath) {
        free(wdir);
        return FV_ERR_NOMEM;
    }
    wcscpy(wpath, wdir);
    if (dl && wdir[dl - 1] != L'\\' && wdir[dl - 1] != L'/') wcscat(wpath, L"\\");
    wcscat(wpath, L"*");

    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(wpath, &fd);
    if (h == INVALID_HANDLE_VALUE) {
        free(wpath);
        free(wdir);
        return FV_ERR_IO;
    }
    do {
        if (!wcscmp(fd.cFileName, L".") || !wcscmp(fd.cFileName, L"..")) continue;
        char *u = plat_wchar_to_utf8(fd.cFileName);
        if (!u) continue;
        int isdir = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
        uint64_t sz = ((uint64_t)fd.nFileSizeHigh << 32) | (uint64_t)fd.nFileSizeLow;
        cb(u, isdir, isdir ? 0 : sz, ctx);
        free(u);
    } while (FindNextFileW(h, &fd));
    FindClose(h);

    free(wpath);
    free(wdir);
    return rc;
}

int plat_expand_path(const char *in, char *out, size_t len)
{
    if (!in || !out || len < 2) return FV_ERR_ARG;

    char step1[FV_PATH_MAX];
    if (in[0] == '~' && (in[1] == '\0' || in[1] == '/' || in[1] == '\\')) {
        const char *home = getenv("USERPROFILE");
        if (!home || !*home) return FV_ERR_NOTFOUND;
        if (snprintf(step1, sizeof step1, "%s%s", home, in + 1) >= (int)sizeof step1)
            return FV_ERR_RANGE;
    } else {
        if (snprintf(step1, sizeof step1, "%s", in) >= (int)sizeof step1)
            return FV_ERR_RANGE;
    }

    wchar_t *w1 = NULL;
    int rc = FV_OK;
    if (utf8_to_utf16(step1, &w1) != FV_OK) return FV_ERR_ARG;
    wchar_t *w2 = (wchar_t *)malloc(FV_PATH_MAX * sizeof(wchar_t));
    if (!w2) {
        free(w1);
        return FV_ERR_NOMEM;
    }
    if (ExpandEnvironmentStringsW(w1, w2, FV_PATH_MAX) == 0 || w2[0] == L'\0') {
        rc = FV_ERR_ARG;
        goto done;
    }
    {
        char *u = plat_wchar_to_utf8(w2);
        if (!u) {
            rc = FV_ERR_NOMEM;
            goto done;
        }
        if (strlen(u) >= len) rc = FV_ERR_RANGE;
        else strcpy(out, u);
        free(u);
    }
done:
    free(w1);
    free(w2);
    return rc;
}

int plat_config_dir(char *buf, size_t len)
{
    const char *app = getenv("APPDATA");
    if (!app || !*app) return FV_ERR_NOTFOUND;
    if (snprintf(buf, len, "%s\\foxvault", app) >= (int)len) return FV_ERR_RANGE;
    return FV_OK;
}

void plat_write_stdout(const void *buf, size_t len)
{
    fflush(stdout);
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    const BYTE *p = (const BYTE *)buf;
    DWORD total = (DWORD)len;
    while (total) {
        DWORD done = 0;
        if (!WriteFile(h, p, total, &done, NULL) || done == 0) break;
        p += done;
        total -= done;
    }
}

#else /* !_WIN32 */

/* =============================== POSIX =============================== */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

void plat_init(void)
{
    signal(SIGINT, SIG_IGN);
    signal(SIGQUIT, SIG_IGN);
    signal(SIGPIPE, SIG_IGN);
}

int plat_random(void *buf, size_t len)
{
    if (len && !buf) return FV_ERR_ARG;
    if (!len) return FV_OK;
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return FV_ERR_IO;
    size_t got = 0;
    while (got < len) {
        ssize_t r = read(fd, (char *)buf + got, len - got);
        if (r < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return FV_ERR_IO;
        }
        if (r == 0) {
            close(fd);
            return FV_ERR_IO;
        }
        got += (size_t)r;
    }
    close(fd);
    return FV_OK;
}

static int read_line_common(char *buf, size_t len)
{
    if (len < 2) return FV_ERR_ARG;
    if (!fgets(buf, (int)len, stdin)) {
        clearerr(stdin);
        return FV_ERR_CANCEL;
    }
    size_t n = strlen(buf);
    if (n && buf[n - 1] == '\n') {
        buf[--n] = '\0';
        if (n && buf[n - 1] == '\r') buf[--n] = '\0';
    } else if (n == len - 1) {
        int c;
        while ((c = fgetc(stdin)) != '\n' && c != EOF) {}
        clearerr(stdin);
        return FV_ERR_RANGE;
    }
    return FV_OK;
}

int plat_read_password(const char *prompt, char *buf, size_t len)
{
    if (!buf || len < 2) return FV_ERR_ARG;
    buf[0] = '\0';
    if (prompt && *prompt) {
        fputs(prompt, stdout);
        fflush(stdout);
    }

    if (!isatty(STDIN_FILENO))
        return read_line_common(buf, len);          /* пароль пришёл по пайпу */

    struct termios old, noecho;
    if (tcgetattr(STDIN_FILENO, &old) != 0) return FV_ERR_IO;
    noecho = old;
    noecho.c_lflag &= ~(tcflag_t)ECHO;              /* ICANON оставляем */
    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &noecho) != 0) return FV_ERR_IO;
    int rc = read_line_common(buf, len);
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &old);
    fputs("\n", stdout);
    fflush(stdout);
    if (rc != FV_OK) fv_wipe(buf, len);
    return rc;
}

int plat_readline(const char *prompt, char *buf, size_t len)
{
    return plat_readline_ex(prompt, buf, len, NULL, NULL);
}

int plat_isatty_stdin(void)
{
    return isatty(STDIN_FILENO);
}

int plat_isatty_stdout(void)
{
    return isatty(STDOUT_FILENO);
}

uint64_t plat_now_ms(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
    return (uint64_t)ts.tv_sec * 1000ull + (uint64_t)ts.tv_nsec / 1000000ull;
}

/* ---------- строчный редактор с Tab (терминал POSIX) ---------- */

/* перерисовать строку: на начало, стереть до конца, напечатать заново */
static void tty_redraw(const char *prompt, const char *line)
{
    fputs("\r\033[K", stdout);
    if (prompt) fputs(prompt, stdout);
    fputs(line, stdout);
    fflush(stdout);
}

int plat_readline_ex(const char *prompt, char *buf, size_t len,
                     plat_complete_fn fn, void *fn_ctx)
{
    if (!buf || len < 2) return FV_ERR_ARG;
    buf[0] = '\0';
    if (prompt && *prompt) {
        fputs(prompt, stdout);
        fflush(stdout);
    }
    if (!isatty(STDIN_FILENO))
        return read_line_common(buf, len);           /* пайп: как раньше */

    struct termios old, raw;
    if (tcgetattr(STDIN_FILENO, &old) != 0) return FV_ERR_IO;
    raw = old;
    raw.c_lflag &= ~(tcflag_t)(ECHO | ICANON | ISIG);
    raw.c_iflag &= ~(tcflag_t)IXON;
    raw.c_cc[VMIN]  = 1;
    raw.c_cc[VTIME] = 0;
    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw) != 0) return FV_ERR_IO;

    size_t n = 0;
    int rc = FV_OK;
    int esc = 0;                                     /* проглот ESC[.. (стрелки) */

    for (;;) {
        char c;
        ssize_t r = read(STDIN_FILENO, &c, 1);
        if (r <= 0) { rc = FV_ERR_CANCEL; break; }   /* EOF (Ctrl+D на пустой) */

        if (esc) {                                   /* хвост escape-последовательности */
            if (esc == 1 && c == '[') { esc = 2; continue; }
            if (esc == 2) {
                if ((c >= '@' && c <= '~')) esc = 0; /* финальный байт CSI */
                continue;
            }
            esc = 0;
            continue;
        }
        if (c == 0x1b) { esc = 1; continue; }

        if (c == '\r' || c == '\n') break;
        if (c == 0x03) { rc = FV_ERR_CANCEL; break; }        /* Ctrl+C */
        if (c == 0x04) { if (n == 0) rc = FV_ERR_CANCEL; break; } /* Ctrl+D */

        if (c == '\t') {
            if (fn) {
                buf[n] = '\0';
                size_t nl = n;
                int act = fn(buf, &nl, fn_ctx);
                if (act) {
                    n = nl;
                    buf[n] = '\0';
                    tty_redraw(prompt, buf);
                }
            }
            continue;
        }
        if (c == 0x7f || c == 0x08) {                /* Backspace */
            if (n) {
                while (n > 0 && (buf[n - 1] & 0xC0) == 0x80) n--;  /* хвост UTF-8 */
                if (n) n--;
                buf[n] = '\0';
                tty_redraw(prompt, buf);
            }
            continue;
        }
        if (c == 0x15) {                             /* Ctrl+U — очистить строку */
            n = 0;
            buf[0] = '\0';
            tty_redraw(prompt, buf);
            continue;
        }
        unsigned char uc = (unsigned char)c;
        if (uc < 0x20) continue;                     /* прочие управляющие — игнор */
        size_t need = (uc >= 0x80) ? 4u : 1u;
        if (n + need + 1 > len) continue;            /* буфер полон (запас на UTF-8) */
        buf[n++] = c;
        buf[n] = '\0';
        fputc(c, stdout);                            /* эхо ввода */
        fflush(stdout);
    }

    tcsetattr(STDIN_FILENO, TCSAFLUSH, &old);
    fputs("\n", stdout);
    fflush(stdout);
    if (rc != FV_OK) buf[0] = '\0';
    else if (n >= len) rc = FV_ERR_RANGE;
    return rc;
}

int plat_lock_mem(void *p, size_t len)
{
    if (!p || !len) return FV_OK;
    long ps = sysconf(_SC_PAGESIZE);
    if (ps <= 0) ps = 4096;
    uintptr_t pg = (uintptr_t)ps;
    uintptr_t a = (uintptr_t)p;
    uintptr_t e = a + len;
    a &= ~(pg - 1);
    e = (e + pg - 1) & ~(pg - 1);
    return mlock((void *)a, (size_t)(e - a)) == 0 ? FV_OK : FV_ERR_IO;
}

void plat_unlock_mem(void *p, size_t len)
{
    if (!p || !len) return;
    long ps = sysconf(_SC_PAGESIZE);
    if (ps <= 0) ps = 4096;
    uintptr_t pg = (uintptr_t)ps;
    uintptr_t a = (uintptr_t)p;
    uintptr_t e = a + len;
    a &= ~(pg - 1);
    e = (e + pg - 1) & ~(pg - 1);
    munlock((void *)a, (size_t)(e - a));
}

FILE *plat_fopen(const char *path, const char *mode)
{
    return fopen(path, mode);
}

int plat_fsync(FILE *f)
{
    if (!f) return FV_ERR_ARG;
    if (fflush(f) != 0) return FV_ERR_IO;
    return fsync(fileno(f)) == 0 ? FV_OK : FV_ERR_IO;
}

int plat_fsync_dir(const char *dir)
{
    int fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) return FV_ERR_IO;
    (void)fsync(fd);          /* некоторые ФС (tmpfs) не умеют — это не ошибка */
    close(fd);
    return FV_OK;
}

int plat_atomic_replace(const char *tmp, const char *dst)
{
    return rename(tmp, dst) == 0 ? FV_OK : FV_ERR_IO;
}

int plat_mkdir(const char *path)
{
    if (mkdir(path, 0777) == 0) return FV_OK;
    return errno == EEXIST ? FV_ERR_EXISTS : FV_ERR_IO;
}

int plat_mkdir_p(const char *path)
{
    char tmp[FV_PATH_MAX];
    size_t l = strlen(path);
    if (l >= sizeof tmp) return FV_ERR_RANGE;
    strcpy(tmp, path);
    while (l > 1 && (tmp[l - 1] == '/')) tmp[--l] = '\0';

    size_t i = (tmp[0] == '/') ? 1 : 0;
    for (; tmp[i]; i++) {
        if (tmp[i] == '/') {
            tmp[i] = '\0';
            if (tmp[0] && plat_mkdir(tmp) != FV_OK && plat_stat_kind(tmp) != 2)
                return FV_ERR_IO;
            tmp[i] = '/';
        }
    }
    if (tmp[0] && plat_mkdir(tmp) != FV_OK && plat_stat_kind(tmp) != 2)
        return FV_ERR_IO;
    return plat_stat_kind(tmp) == 2 ? FV_OK : FV_ERR_IO;
}

int plat_remove(const char *path)
{
    int k = plat_stat_kind(path);
    if (k == 0) return FV_ERR_NOTFOUND;
    int rc = (k == 2) ? rmdir(path) : unlink(path);
    return rc == 0 ? FV_OK : FV_ERR_IO;
}

int plat_stat_kind(const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0) return 0;
    if (S_ISDIR(st.st_mode)) return 2;
    if (S_ISREG(st.st_mode)) return 1;
    return 0;
}

int plat_file_size(const char *path, uint64_t *size)
{
    struct stat st;
    if (stat(path, &st) != 0) return FV_ERR_NOTFOUND;
    *size = (uint64_t)st.st_size;
    return FV_OK;
}

int plat_getcwd(char *buf, size_t len)
{
    if (!getcwd(buf, len)) return FV_ERR_IO;
    return FV_OK;
}

int plat_chdir(const char *path)
{
    return chdir(path) == 0 ? FV_OK : FV_ERR_IO;
}

int plat_list_dir(const char *path, plat_dir_cb cb, void *ctx)
{
    DIR *d = opendir(path);
    if (!d) return FV_ERR_IO;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;
        int isdir = 0;
        uint64_t sz = 0;
        if (de->d_type == DT_DIR) {
            isdir = 1;
        } else if (de->d_type == DT_REG) {
            char *full = (char *)malloc(strlen(path) + strlen(de->d_name) + 2);
            if (full) {
                snprintf(full, strlen(path) + strlen(de->d_name) + 2,
                         "%s/%s", path, de->d_name);
                struct stat st;
                if (stat(full, &st) == 0) sz = (uint64_t)st.st_size;
                free(full);
            }
        } else if (de->d_type == DT_UNKNOWN) {
            char *full = (char *)malloc(strlen(path) + strlen(de->d_name) + 2);
            if (full) {
                snprintf(full, strlen(path) + strlen(de->d_name) + 2,
                         "%s/%s", path, de->d_name);
                struct stat st;
                if (stat(full, &st) == 0) {
                    if (S_ISDIR(st.st_mode)) isdir = 1;
                    else if (S_ISREG(st.st_mode)) sz = (uint64_t)st.st_size;
                }
                free(full);
            }
        }
        cb(de->d_name, isdir, isdir ? 0 : sz, ctx);
    }
    closedir(d);
    return FV_OK;
}

int plat_expand_path(const char *in, char *out, size_t len)
{
    if (!in || !out || len < 2) return FV_ERR_ARG;

    char tmp[FV_PATH_MAX];
    if (in[0] == '~' && (in[1] == '\0' || in[1] == '/')) {
        const char *home = getenv("HOME");
        if (!home || !*home) return FV_ERR_NOTFOUND;
        if (snprintf(tmp, sizeof tmp, "%s%s", home, in + 1) >= (int)sizeof tmp)
            return FV_ERR_RANGE;
        in = tmp;
    }

    size_t o = 0;
    for (size_t i = 0; in[i]; ) {
        if (in[i] == '$') {
            size_t j = i + 1;
            char name[128];
            size_t nl = 0;
            int braces = 0;
            if (in[j] == '{') {
                braces = 1;
                j++;
            }
            while (in[j] && (in[j] == '_' ||
                   (in[j] >= 'A' && in[j] <= 'Z') ||
                   (in[j] >= 'a' && in[j] <= 'z') ||
                   (in[j] >= '0' && in[j] <= '9')) && nl < sizeof name - 1)
                name[nl++] = in[j++];
            if (braces) {
                if (in[j] != '}') return FV_ERR_ARG;
                j++;
            }
            if (nl == 0) {                      /* одиночный $ — как символ */
                if (o + 1 >= len) return FV_ERR_RANGE;
                out[o++] = '$';
                i++;
                continue;
            }
            name[nl] = '\0';
            const char *v = getenv(name);
            size_t vl = v ? strlen(v) : 0;
            if (o + vl >= len) return FV_ERR_RANGE;
            if (vl) memcpy(out + o, v, vl);
            o += vl;
            i = j;
        } else {
            if (o + 1 >= len) return FV_ERR_RANGE;
            out[o++] = in[i++];
        }
    }
    out[o] = '\0';
    return FV_OK;
}

int plat_config_dir(char *buf, size_t len)
{
    const char *xdg = getenv("XDG_CONFIG_HOME");
    if (xdg && *xdg && xdg[0] == '/') {
        if (snprintf(buf, len, "%s/foxvault", xdg) >= (int)len) return FV_ERR_RANGE;
        return FV_OK;
    }
    const char *home = getenv("HOME");
    if (home && *home) {
        if (snprintf(buf, len, "%s/.config/foxvault", home) >= (int)len)
            return FV_ERR_RANGE;
        return FV_OK;
    }
    return FV_ERR_NOTFOUND;
}

void plat_write_stdout(const void *buf, size_t len)
{
    fflush(stdout);
    size_t off = 0;
    while (off < len) {
        ssize_t r = write(STDOUT_FILENO, (const char *)buf + off, len - off);
        if (r < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (r == 0) break;
        off += (size_t)r;
    }
}

#endif /* _WIN32 / POSIX */