/* platform.c — всё, что зависит от ОС.
 *
 * Windows: пути внутри переводятся из UTF-8 в UTF-16 и идут в *W-функции,
 *          поэтому кириллица работает во всех путях. Консоль переводится
 *          в UTF-8; строка shell читается посимвольно через ReadConsoleInputW
 *          (UTF-16), а рисуется только через WriteConsoleW.
 *          Общий для обеих ОС строчный редактор (курсор, история, Tab)
 *          — в начале файла; ниже только чтение клавиш и отрисовка.
 * POSIX:   предполагается UTF-8 локаль; пароль вводится без эха через termios.
 */
#include "platform.h"
#include "util.h"
#include "crypto.h"

#include <stdlib.h>
#include <string.h>

/* ===================== общий строчный редактор ======================
 *
 * Здесь — всё, что не зависит от ОС: буфер строки с курсором, правка
 * UTF-8 по целым символам, история, Tab-дополнение в середине строки.
 * Платформенные части ниже только читают клавиши и рисуют строку.
 */

#define FV_HISTORY_DEFAULT 500u

void plat_history_init(plat_history *h, size_t max)
{
    if (!h) return;
    h->items = NULL;
    h->n = h->cap = 0;
    h->max = max ? max : FV_HISTORY_DEFAULT;
}

static void wipe_str(char *s)
{
    if (s) {
        fv_wipe(s, strlen(s));
        free(s);
    }
}

void plat_history_add(plat_history *h, const char *line)
{
    if (!h || !line || !*line) return;
    if (line[0] == ' ' || line[0] == '\t') return;   /* «не запоминать» */
    if (h->n && !strcmp(h->items[h->n - 1], line)) return;
    size_t max = h->max ? h->max : FV_HISTORY_DEFAULT;
    if (h->n >= max) {                               /* выкинуть самую старую */
        wipe_str(h->items[0]);
        memmove(h->items, h->items + 1, (h->n - 1) * sizeof(char *));
        h->n--;
    }
    if (h->n == h->cap) {
        size_t nc = h->cap ? h->cap * 2 : 32;
        char **ni = (char **)realloc(h->items, nc * sizeof(char *));
        if (!ni) return;
        h->items = ni;
        h->cap = nc;
    }
    size_t l = strlen(line) + 1;
    char *cp = (char *)malloc(l);
    if (!cp) return;
    memcpy(cp, line, l);
    h->items[h->n++] = cp;
}

void plat_history_clear(plat_history *h)
{
    if (!h) return;
    for (size_t i = 0; i < h->n; i++) wipe_str(h->items[i]);
    free(h->items);
    h->items = NULL;
    h->n = h->cap = 0;
}

typedef enum {
    K_NONE, K_CHAR, K_ENTER, K_TAB, K_CANCEL, K_EOF_OR_DEL,
    K_BACK, K_DEL, K_LEFT, K_RIGHT, K_HOME, K_END, K_UP, K_DOWN,
    K_WORD_LEFT, K_WORD_RIGHT, K_KILL_BOL, K_KILL_EOL, K_KILL_WORD
} le_key;

typedef struct {
    char         *buf;
    size_t        cap;          /* размер буфера вызывающего, вместе с NUL */
    size_t        len, cur;     /* байты UTF-8; cur всегда на границе символа */
    plat_history *hist;
    size_t        hpos;         /* == hist->n — редактируется новая строка */
    char         *draft;        /* новая строка, отложенная при листании */
} le_state;

static size_t u8_prev(const char *s, size_t i)
{
    if (!i) return 0;
    i--;
    while (i > 0 && ((unsigned char)s[i] & 0xC0) == 0x80) i--;
    return i;
}

static size_t u8_next(const char *s, size_t len, size_t i)
{
    if (i >= len) return len;
    i++;
    while (i < len && ((unsigned char)s[i] & 0xC0) == 0x80) i++;
    return i;
}

#ifndef _WIN32
/* число символов (= ячеек экрана для латиницы и кириллицы);
 * на Windows то же считает w_units() в UTF-16 */
static size_t u8_cells(const char *s, size_t n)
{
    size_t c = 0;
    for (size_t i = 0; i < n; i++)
        if (((unsigned char)s[i] & 0xC0) != 0x80) c++;
    return c;
}
#endif

static void le_init(le_state *e, char *buf, size_t cap, plat_history *hist)
{
    e->buf = buf;
    e->cap = cap;
    e->len = e->cur = 0;
    e->buf[0] = '\0';
    e->hist = hist;
    e->hpos = hist ? hist->n : 0;
    e->draft = NULL;
}

static void le_free(le_state *e)
{
    wipe_str(e->draft);
    e->draft = NULL;
}

static int le_insert(le_state *e, const char *s, size_t m)
{
    if (!m || e->len + m + 1 > e->cap) return 0;
    memmove(e->buf + e->cur + m, e->buf + e->cur, e->len - e->cur);
    memcpy(e->buf + e->cur, s, m);
    e->len += m;
    e->cur += m;
    e->buf[e->len] = '\0';
    return 1;
}

static int le_cut(le_state *e, size_t a, size_t b)
{
    if (a >= b) return 0;
    memmove(e->buf + a, e->buf + b, e->len - b);
    e->len -= b - a;
    if (e->cur >= b)     e->cur -= b - a;
    else if (e->cur > a) e->cur = a;
    e->buf[e->len] = '\0';
    return 1;
}

static size_t le_word_left(const le_state *e)
{
    size_t i = e->cur;
    while (i > 0 && e->buf[i - 1] == ' ') i--;
    while (i > 0 && e->buf[i - 1] != ' ') i--;
    return i;
}

static size_t le_word_right(const le_state *e)
{
    size_t i = e->cur;
    while (i < e->len && e->buf[i] == ' ') i++;
    while (i < e->len && e->buf[i] != ' ') i++;
    return i;
}

/* заменить содержимое строкой s (обрезая по границе символа) */
static void le_set(le_state *e, const char *s)
{
    size_t l = strlen(s);
    if (l + 1 > e->cap) {
        l = e->cap - 1;
        while (l > 0 && ((unsigned char)s[l] & 0xC0) == 0x80) l--;
    }
    memcpy(e->buf, s, l);
    e->buf[l] = '\0';
    e->len = e->cur = l;
}

static int le_hist_prev(le_state *e)
{
    if (!e->hist || !e->hist->n || e->hpos == 0) return 0;
    if (e->hpos > e->hist->n) e->hpos = e->hist->n;
    if (e->hpos == e->hist->n) {                     /* уходим с новой строки */
        wipe_str(e->draft);
        e->draft = (char *)malloc(e->len + 1);
        if (e->draft) memcpy(e->draft, e->buf, e->len + 1);
    }
    e->hpos--;
    le_set(e, e->hist->items[e->hpos]);
    return 1;
}

static int le_hist_next(le_state *e)
{
    if (!e->hist || e->hpos >= e->hist->n) return 0;
    e->hpos++;
    if (e->hpos == e->hist->n) {                     /* вернулись к новой строке */
        le_set(e, e->draft ? e->draft : "");
        wipe_str(e->draft);
        e->draft = NULL;
    } else {
        le_set(e, e->hist->items[e->hpos]);
    }
    return 1;
}

/* Tab: дополнение видит только текст до курсора, хвост приклеивается обратно */
static int le_tab(le_state *e, plat_complete_fn fn, void *ctx)
{
    if (!fn) return 0;
    size_t tl = e->len - e->cur;
    char *tail = (char *)malloc(tl + 1);
    char *orig = (char *)malloc(e->len + 1);
    if (!tail || !orig) {
        free(tail);
        free(orig);
        return 0;
    }
    memcpy(tail, e->buf + e->cur, tl + 1);
    memcpy(orig, e->buf, e->len + 1);

    e->buf[e->cur] = '\0';
    size_t nl = e->cur;
    int act = fn(e->buf, &nl, ctx);
    if (act && nl + tl + 1 <= e->cap) {
        memcpy(e->buf + nl, tail, tl + 1);
        e->len = nl + tl;
        e->cur = nl;
    } else {                                         /* не влезло или нечего делать */
        memcpy(e->buf, orig, e->len + 1);
        if (act == 1) act = 0;
    }
    fv_wipe(tail, tl + 1);
    fv_wipe(orig, e->len + 1);
    free(tail);
    free(orig);
    return act;
}

/* Применить клавишу (кроме Tab). Возврат: 1 — Enter, -1 — отмена,
 * 0 — продолжать; *changed — строку или курсор нужно перерисовать. */
static int le_apply(le_state *e, le_key k, const char *ch, size_t chlen, int *changed)
{
    int ch_ = 0;
    switch (k) {
    case K_ENTER:  return 1;
    case K_CANCEL: return -1;
    case K_EOF_OR_DEL:                               /* Ctrl+D */
        if (e->len == 0) return -1;
        ch_ = le_cut(e, e->cur, u8_next(e->buf, e->len, e->cur));
        break;
    case K_CHAR:      ch_ = le_insert(e, ch, chlen); break;
    case K_BACK:      ch_ = le_cut(e, u8_prev(e->buf, e->cur), e->cur); break;
    case K_DEL:       ch_ = le_cut(e, e->cur, u8_next(e->buf, e->len, e->cur)); break;
    case K_LEFT:
        if (e->cur) { e->cur = u8_prev(e->buf, e->cur); ch_ = 1; }
        break;
    case K_RIGHT:
        if (e->cur < e->len) { e->cur = u8_next(e->buf, e->len, e->cur); ch_ = 1; }
        break;
    case K_HOME:      if (e->cur) { e->cur = 0; ch_ = 1; } break;
    case K_END:       if (e->cur < e->len) { e->cur = e->len; ch_ = 1; } break;
    case K_WORD_LEFT: { size_t p = le_word_left(e);  ch_ = (p != e->cur); e->cur = p; } break;
    case K_WORD_RIGHT:{ size_t p = le_word_right(e); ch_ = (p != e->cur); e->cur = p; } break;
    case K_KILL_BOL:  ch_ = le_cut(e, 0, e->cur); break;
    case K_KILL_EOL:  ch_ = le_cut(e, e->cur, e->len); break;
    case K_KILL_WORD: ch_ = le_cut(e, le_word_left(e), e->cur); break;
    case K_UP:        ch_ = le_hist_prev(e); break;
    case K_DOWN:      ch_ = le_hist_next(e); break;
    default: break;
    }
    if (ch_) *changed = 1;
    return 0;
}

/* клавиша платформы -> действие строки ввода */
static le_key le_map(const plat_key *k)
{
    switch (k->code) {
    case PK_CHAR:       return K_CHAR;
    case PK_ENTER:      return K_ENTER;
    case PK_TAB:        return K_TAB;
    case PK_BACK:       return K_BACK;
    case PK_DEL:        return K_DEL;
    case PK_LEFT:       return K_LEFT;
    case PK_RIGHT:      return K_RIGHT;
    case PK_UP:         return K_UP;
    case PK_DOWN:       return K_DOWN;
    case PK_HOME:       return K_HOME;
    case PK_END:        return K_END;
    case PK_WORD_LEFT:  return K_WORD_LEFT;
    case PK_WORD_RIGHT: return K_WORD_RIGHT;
    case PK_KILL_WORD:  return K_KILL_WORD;
    case PK_CTRL:
        switch (k->ctrl) {
        case 'c': return K_CANCEL;
        case 'd': return K_EOF_OR_DEL;
        case 'a': return K_HOME;
        case 'e': return K_END;
        case 'b': return K_LEFT;
        case 'f': return K_RIGHT;
        case 'p': return K_UP;
        case 'n': return K_DOWN;
        case 'u': return K_KILL_BOL;
        case 'k': return K_KILL_EOL;
        case 'w': return K_KILL_WORD;
        default:  return K_NONE;
        }
    default:            return K_NONE;
    }
}

int plat_readline_ex(const char *prompt, char *buf, size_t len,
                     plat_complete_fn fn, void *fn_ctx)
{
    return plat_readline_hist(prompt, buf, len, fn, fn_ctx, NULL);
}

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

/* ---------- клавиши Windows-консоли ---------- */

#ifndef ENABLE_VIRTUAL_TERMINAL_PROCESSING
#define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x0004
#endif

/* KEY_EVENT -> plat_key. Возврат 1 — клавиша есть, 0 — пропустить
 * (отпускание, Shift/Alt сами по себе, первая половина суррогатной пары).
 * Символ берётся только из UnicodeChar: AsciiChar — это младший байт
 * UTF-16, из-за него кириллица превращалась в мусор и «иероглифы». */
static int con_decode(const KEY_EVENT_RECORD *ke, plat_key *k, wchar_t *pend_hi)
{
    memset(k, 0, sizeof *k);
    k->rep = ke->wRepeatCount ? ke->wRepeatCount : 1;
    if (!ke->bKeyDown) return 0;

    wchar_t wc = ke->uChar.UnicodeChar;
    WORD vk = ke->wVirtualKeyCode;
    int ctrl = (ke->dwControlKeyState & (LEFT_CTRL_PRESSED | RIGHT_CTRL_PRESSED)) != 0;

    if (vk == VK_RETURN || wc == L'\r' || wc == L'\n') { k->code = PK_ENTER; return 1; }
    switch (vk) {
    case VK_LEFT:   k->code = ctrl ? PK_WORD_LEFT : PK_LEFT;   return 1;
    case VK_RIGHT:  k->code = ctrl ? PK_WORD_RIGHT : PK_RIGHT; return 1;
    case VK_HOME:   k->code = PK_HOME;  return 1;
    case VK_END:    k->code = PK_END;   return 1;
    case VK_UP:     k->code = PK_UP;    return 1;
    case VK_DOWN:   k->code = PK_DOWN;  return 1;
    case VK_PRIOR:  k->code = PK_PGUP;  return 1;
    case VK_NEXT:   k->code = PK_PGDN;  return 1;
    case VK_DELETE: k->code = PK_DEL;   return 1;
    case VK_BACK:   k->code = ctrl ? PK_KILL_WORD : PK_BACK; return 1;
    case VK_TAB:    k->code = PK_TAB;   return 1;
    case VK_ESCAPE: k->code = PK_ESC;   return 1;
    default: break;
    }
    if (wc == 0x08 || wc == 0x7F) { k->code = PK_BACK; return 1; }
    if (wc == 0x09) { k->code = PK_TAB; return 1; }
    if (wc == 0x1B) { k->code = PK_ESC; return 1; }
    if (wc >= 1 && wc <= 26) {                       /* Ctrl+буква */
        k->code = PK_CTRL;
        k->ctrl = (char)('a' + wc - 1);
        return 1;
    }
    if (wc < 0x20) return 0;                         /* F-клавиши, Shift и прочее */

    /* UTF-16 (с суррогатными парами) -> UTF-8 */
    wchar_t pair[2];
    int wn = 1;
    if (*pend_hi) {
        if (wc >= 0xDC00 && wc <= 0xDFFF) {
            pair[0] = *pend_hi;
            pair[1] = wc;
            wn = 2;
            *pend_hi = 0;
            k->rep = 1;
        } else {
            *pend_hi = 0;                            /* битая пара — старшую выкидываем */
            if (wc >= 0xD800 && wc <= 0xDBFF) { *pend_hi = wc; return 0; }
            pair[0] = wc;
        }
    } else if (wc >= 0xD800 && wc <= 0xDBFF) {
        *pend_hi = wc;
        return 0;
    } else if (wc >= 0xDC00 && wc <= 0xDFFF) {
        return 0;                                    /* одинокая младшая половина */
    } else {
        pair[0] = wc;
    }
    int r = WideCharToMultiByte(CP_UTF8, 0, pair, wn, k->ch, (int)sizeof k->ch - 1, NULL, NULL);
    if (r <= 0) return 0;
    k->chlen = (size_t)r;
    k->code = PK_CHAR;
    return 1;
}

/* ---------- строчный редактор (Windows-консоль) ---------- */

/* число UTF-16 единиц (= ячеек консоли для BMP) в первых n байтах UTF-8 */
static DWORD w_units(const char *s, size_t n)
{
    if (!s || !n) return 0;
    int r = MultiByteToWideChar(CP_UTF8, 0, s, (int)n, NULL, 0);
    return r > 0 ? (DWORD)r : 0;
}

/* Нарисовать приглашение + строку от позиции *org и поставить курсор
 * на e->cur.
 *
 * Приглашение рисуется только здесь (WriteConsoleW), поэтому оно
 * не дублируется и не смешивается с байтовым выводом CRT.
 * *lastw — сколько ячеек занимал прошлый вывод: их затираем пробелами.
 * Если вывод упёрся в низ буфера и консоль прокрутилась, начало строки
 * сдвигается вверх — *org пересчитывается по фактической позиции курсора. */
static void con_refresh(HANDLE hOut, COORD *org, const char *prompt,
                        const le_state *e, DWORD *lastw)
{
    DWORD wr = 0;
    if (*lastw)
        FillConsoleOutputCharacterW(hOut, L' ', *lastw, *org, &wr);
    SetConsoleCursorPosition(hOut, *org);

    char both[FV_PATH_MAX + 256];
    snprintf(both, sizeof both, "%s%s", prompt ? prompt : "", e->buf);
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
    if (!GetConsoleScreenBufferInfo(hOut, &csbi) || csbi.dwSize.X <= 0) return;
    long width = csbi.dwSize.X;

    /* прокрутка: где курсор должен был оказаться и где он на самом деле */
    if (cells) {
        long ex  = (long)org->X + (long)cells;
        long exy = (long)org->Y + ex / width;
        long exx = ex % width;
        long shift = 0;
        if (csbi.dwCursorPosition.X == exx)
            shift = exy - csbi.dwCursorPosition.Y;
        else if (exx == 0 && csbi.dwCursorPosition.X == width - 1)
            shift = (exy - 1) - csbi.dwCursorPosition.Y;   /* отложенный перенос */
        if (shift > 0) {
            long ny = (long)org->Y - shift;
            org->Y = (SHORT)(ny < 0 ? 0 : ny);
        }
    }

    /* курсор на позицию e->cur */
    size_t plen = prompt ? strlen(prompt) : 0;
    long pc  = (long)w_units(prompt, plen) + (long)w_units(e->buf, e->cur);
    long pos = (long)org->X + pc;
    COORD c;
    long cy = (long)org->Y + pos / width;
    long cx = pos % width;
    if (cy > csbi.dwSize.Y - 1) {
        cy = csbi.dwSize.Y - 1;
        cx = width - 1;
    }
    c.X = (SHORT)cx;
    c.Y = (SHORT)cy;
    SetConsoleCursorPosition(hOut, c);
}

/* перерисовка, когда stdout — не консоль: курсор не показать, только текст */
static void plain_refresh(const char *prompt, const le_state *e)
{
    fputs("\r", stdout);
    if (prompt) fputs(prompt, stdout);
    fwrite(e->buf, 1, e->len, stdout);
    fflush(stdout);
}

int plat_readline_hist(const char *prompt, char *buf, size_t len,
                       plat_complete_fn fn, void *fn_ctx, plat_history *hist)
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

    /* всё, что CRT накопил в stdout, — на экран раньше, чем мы запомним
     * позицию курсора */
    fflush(stdout);

    le_state e;
    le_init(&e, buf, len, hist);

    COORD org = { 0, 0 };
    DWORD lastw = 0;
    if (con_out) {
        CONSOLE_SCREEN_BUFFER_INFO csbi;
        if (GetConsoleScreenBufferInfo(hOut, &csbi))
            org = csbi.dwCursorPosition;
        else
            con_out = 0;
    }
    if (con_out) con_refresh(hOut, &org, prompt, &e, &lastw);   /* приглашение */
    else if (prompt && *prompt) { fputs(prompt, stdout); fflush(stdout); }

    /* посимвольный ввод без линейного буфера и без эха (эхо рисуем сами) */
    SetConsoleMode(hIn, inmode & ~((DWORD)ENABLE_LINE_INPUT |
                                   (DWORD)ENABLE_ECHO_INPUT |
                                   (DWORD)ENABLE_PROCESSED_INPUT));

    int rc = FV_OK;
    wchar_t pend_hi = 0;                             /* верхняя половина суррогатной пары */

    for (;;) {
        INPUT_RECORD ir;
        DWORD rd = 0;
        if (!ReadConsoleInputW(hIn, &ir, 1, &rd) || rd == 0) {
            rc = FV_ERR_CANCEL;
            break;
        }
        if (ir.EventType != KEY_EVENT) continue;

        plat_key pk;
        if (!con_decode(&ir.Event.KeyEvent, &pk, &pend_hi)) continue;
        le_key k = le_map(&pk);
        if (k == K_NONE) continue;

        if (k == K_TAB) {
            if (!fn) continue;
            if (con_out) {                           /* курсор в конец строки */
                size_t sc = e.cur;
                e.cur = e.len;
                con_refresh(hOut, &org, prompt, &e, &lastw);
                e.cur = sc;
            }
            int act = le_tab(&e, fn, fn_ctx);
            if (act == 2) {                          /* варианты напечатаны: новая строка */
                fflush(stdout);
                if (con_out) {
                    CONSOLE_SCREEN_BUFFER_INFO csbi;
                    if (GetConsoleScreenBufferInfo(hOut, &csbi))
                        org = csbi.dwCursorPosition;
                    org.X = 0;
                }
                lastw = 0;
            }
            if (con_out) con_refresh(hOut, &org, prompt, &e, &lastw);
            else if (act) plain_refresh(prompt, &e);
            continue;
        }

        int changed = 0, done = 0;
        for (unsigned r = 0; r < pk.rep && !done; r++)     /* автоповтор клавиши */
            done = le_apply(&e, k, pk.ch, pk.chlen, &changed);
        if (done) {
            if (done < 0) rc = FV_ERR_CANCEL;
            break;
        }
        if (changed) {
            if (con_out) con_refresh(hOut, &org, prompt, &e, &lastw);
            else plain_refresh(prompt, &e);
        }
    }

    /* курсор в конец, чтобы вывод команды не наложился на хвост строки */
    if (con_out && e.cur != e.len) {
        e.cur = e.len;
        con_refresh(hOut, &org, prompt, &e, &lastw);
    }
    SetConsoleMode(hIn, inmode);
    fputs("\n", stdout);
    fflush(stdout);
    le_free(&e);
    if (rc != FV_OK) buf[0] = '\0';
    return rc;
}

/* ---------- полноэкранный режим (Windows: отдельный буфер консоли) ----------
 *
 * Без ESC-последовательностей: отдельный экранный буфер
 * (CreateConsoleScreenBuffer) + запись сетки ячеек WriteConsoleOutputW.
 * Работает в любой консоли Windows (и до 10-й версии), не зависит от
 * правил переноса, а текст файла не попадает в прокрутку основного окна. */

static DWORD  t_inmode;
static HANDLE t_alt = INVALID_HANDLE_VALUE;
static WORD   t_attr = 0x07;
static int    t_active;
static wchar_t t_pend_hi;

int plat_term_begin(void)
{
    HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (t_active) return FV_OK;
    DWORD om = 0;
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    if (!GetConsoleMode(hIn, &t_inmode) || !GetConsoleMode(hOut, &om) ||
        !GetConsoleScreenBufferInfo(hOut, &csbi))
        return FV_ERR_ARG;
    t_attr = (WORD)(csbi.wAttributes & 0xFF);
    t_alt = CreateConsoleScreenBuffer(GENERIC_READ | GENERIC_WRITE,
                                      FILE_SHARE_READ | FILE_SHARE_WRITE,
                                      NULL, CONSOLE_TEXTMODE_BUFFER, NULL);
    if (t_alt == INVALID_HANDLE_VALUE) return FV_ERR_ARG;
    COORD sz;
    sz.X = (SHORT)(csbi.srWindow.Right - csbi.srWindow.Left + 1);
    sz.Y = (SHORT)(csbi.srWindow.Bottom - csbi.srWindow.Top + 1);
    SetConsoleScreenBufferSize(t_alt, sz);           /* без полосы прокрутки */
    fflush(stdout);
    if (!SetConsoleActiveScreenBuffer(t_alt)) {
        CloseHandle(t_alt);
        t_alt = INVALID_HANDLE_VALUE;
        return FV_ERR_ARG;
    }
    SetConsoleMode(hIn, (t_inmode & ~((DWORD)ENABLE_LINE_INPUT |
                                      (DWORD)ENABLE_ECHO_INPUT |
                                      (DWORD)ENABLE_PROCESSED_INPUT)) |
                        ENABLE_WINDOW_INPUT);
    t_active = 1;
    t_pend_hi = 0;
    return FV_OK;
}

void plat_term_end(void)
{
    if (!t_active) return;
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    if (GetConsoleScreenBufferInfo(t_alt, &csbi)) {       /* затереть текст в буфере */
        COORD o = { 0, 0 };
        DWORD wr = 0;
        FillConsoleOutputCharacterW(t_alt, L' ',
                                    (DWORD)csbi.dwSize.X * (DWORD)csbi.dwSize.Y, o, &wr);
    }
    SetConsoleActiveScreenBuffer(GetStdHandle(STD_OUTPUT_HANDLE));
    CloseHandle(t_alt);
    t_alt = INVALID_HANDLE_VALUE;
    SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), t_inmode);
    t_active = 0;
}

void plat_term_size(int *rows, int *cols)
{
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    HANDLE h = t_active ? t_alt : GetStdHandle(STD_OUTPUT_HANDLE);
    *rows = 24;
    *cols = 80;
    if (GetConsoleScreenBufferInfo(h, &csbi)) {
        *cols = csbi.srWindow.Right - csbi.srWindow.Left + 1;
        *rows = csbi.srWindow.Bottom - csbi.srWindow.Top + 1;
        if (t_active && (csbi.dwSize.X != *cols || csbi.dwSize.Y != *rows)) {
            COORD sz = { (SHORT)*cols, (SHORT)*rows };   /* окно изменили — подогнать буфер */
            SetConsoleScreenBufferSize(t_alt, sz);
        }
    }
    if (*rows < 1) *rows = 1;
    if (*cols < 1) *cols = 1;
}

void plat_term_draw(const plat_cell *cells, int rows, int cols, int cur_row, int cur_col)
{
    if (!t_active || rows <= 0 || cols <= 0) return;
    size_t n = (size_t)rows * (size_t)cols;
    CHAR_INFO *ci = (CHAR_INFO *)calloc(n, sizeof(CHAR_INFO));
    if (!ci) return;
    WORD inv = (WORD)(((t_attr & 0x0F) << 4) | ((t_attr & 0xF0) >> 4));
    for (size_t i = 0; i < n; i++) {
        uint32_t c = cells[i].ch;
        WORD a = cells[i].inv ? inv : t_attr;
        if (c == 0) {                                /* правая половина широкого */
            uint32_t pc = i ? cells[i - 1].ch : ' ';
            ci[i].Char.UnicodeChar = (WCHAR)(pc > 0xFFFF ? '?' : pc);
            ci[i].Attributes = (WORD)(a | COMMON_LVB_TRAILING_BYTE);
            if (i) ci[i - 1].Attributes |= COMMON_LVB_LEADING_BYTE;
            continue;
        }
        ci[i].Char.UnicodeChar = (WCHAR)(c > 0xFFFF ? '?' : c);
        ci[i].Attributes = a;
    }
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    SHORT ox = 0, oy = 0;
    if (GetConsoleScreenBufferInfo(t_alt, &csbi)) {
        ox = csbi.srWindow.Left;
        oy = csbi.srWindow.Top;
    }
    COORD bsz = { (SHORT)cols, (SHORT)rows }, bpos = { 0, 0 };
    SMALL_RECT rect = { ox, oy, (SHORT)(ox + cols - 1), (SHORT)(oy + rows - 1) };
    WriteConsoleOutputW(t_alt, ci, bsz, bpos, &rect);
    COORD cp = { (SHORT)(ox + cur_col), (SHORT)(oy + cur_row) };
    SetConsoleCursorPosition(t_alt, cp);
    fv_wipe(ci, n * sizeof(CHAR_INFO));              /* в кадре — текст файла */
    free(ci);
}

int plat_term_key(plat_key *k, int timeout_ms)
{
    HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);
    DWORD wait = timeout_ms < 0 ? INFINITE : (DWORD)timeout_ms;
    memset(k, 0, sizeof *k);
    k->rep = 1;
    for (;;) {
        DWORD w = WaitForSingleObject(hIn, wait);
        if (w == WAIT_TIMEOUT) { k->code = PK_TIMEOUT; return FV_OK; }
        if (w != WAIT_OBJECT_0) { k->code = PK_EOF; return FV_OK; }
        INPUT_RECORD ir;
        DWORD rd = 0;
        if (!ReadConsoleInputW(hIn, &ir, 1, &rd) || rd == 0) { k->code = PK_EOF; return FV_OK; }
        if (ir.EventType == WINDOW_BUFFER_SIZE_EVENT) { k->code = PK_NONE; return FV_OK; }
        if (ir.EventType != KEY_EVENT) continue;
        if (con_decode(&ir.Event.KeyEvent, k, &t_pend_hi)) return FV_OK;
    }
}

int plat_color_ok(void)
{
    static int st = -1;
    if (st < 0) {
        HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
        DWORD m = 0;
        st = GetConsoleMode(h, &m) &&
             SetConsoleMode(h, m | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    }
    return st;
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
#include <poll.h>
#include <signal.h>
#include <sys/ioctl.h>
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

/* ---------- клавиши терминала POSIX ---------- */

/* прочитать байт с таймаутом (для хвоста escape-последовательности) */
static int tty_getc_timeout(unsigned char *c, int ms)
{
    struct pollfd p;
    p.fd = STDIN_FILENO;
    p.events = POLLIN;
    p.revents = 0;
    if (poll(&p, 1, ms) <= 0) return 0;
    return read(STDIN_FILENO, c, 1) == 1;
}

/* Прочитать одну клавишу: ESC-последовательности стрелок и т.п.,
 * Ctrl+буква, целый символ UTF-8. timeout_ms < 0 — ждать бесконечно. */
static void tty_decode(plat_key *k, int timeout_ms)
{
    memset(k, 0, sizeof *k);
    k->rep = 1;
    if (timeout_ms >= 0) {
        struct pollfd p;
        p.fd = STDIN_FILENO;
        p.events = POLLIN;
        p.revents = 0;
        if (poll(&p, 1, timeout_ms) == 0) { k->code = PK_TIMEOUT; return; }
    }
    unsigned char c;
    ssize_t r = read(STDIN_FILENO, &c, 1);
    if (r <= 0) { k->code = PK_EOF; return; }

    if (c == 0x1b) {                                 /* ESC-последовательности */
        unsigned char c2;
        if (!tty_getc_timeout(&c2, 50)) { k->code = PK_ESC; return; }   /* одиночный Esc */
        if (c2 == '[' || c2 == 'O') {
            char par[16];
            size_t np = 0;
            unsigned char f = 0;
            for (;;) {
                if (!tty_getc_timeout(&f, 50)) return;       /* оборванная — PK_NONE */
                if (f >= 0x40 && f <= 0x7e) break;           /* финальный байт CSI */
                if (np < sizeof par - 1) par[np++] = (char)f;
            }
            par[np] = '\0';
            int mod = (strstr(par, ";5") || strstr(par, ";3")) != 0;  /* Ctrl/Alt */
            switch (f) {
            case 'A': k->code = PK_UP;    return;
            case 'B': k->code = PK_DOWN;  return;
            case 'C': k->code = mod ? PK_WORD_RIGHT : PK_RIGHT; return;
            case 'D': k->code = mod ? PK_WORD_LEFT : PK_LEFT;   return;
            case 'H': k->code = PK_HOME;  return;
            case 'F': k->code = PK_END;   return;
            case '~':
                switch (atoi(par)) {
                case 1: case 7: k->code = PK_HOME; return;
                case 4: case 8: k->code = PK_END;  return;
                case 3:         k->code = PK_DEL;  return;
                case 5:         k->code = PK_PGUP; return;
                case 6:         k->code = PK_PGDN; return;
                default:        return;
                }
            default: return;
            }
        }
        if (c2 == 'b') { k->code = PK_WORD_LEFT;  return; }  /* Alt+B */
        if (c2 == 'f') { k->code = PK_WORD_RIGHT; return; }  /* Alt+F */
        if (c2 == 0x7f || c2 == 0x08) { k->code = PK_KILL_WORD; return; }  /* Alt+Backspace */
        return;
    }

    if (c == '\r' || c == '\n') { k->code = PK_ENTER; return; }
    if (c == '\t')              { k->code = PK_TAB;   return; }
    if (c == 0x7f || c == 0x08) { k->code = PK_BACK;  return; }
    if (c >= 1 && c <= 26)      { k->code = PK_CTRL; k->ctrl = (char)('a' + c - 1); return; }
    if (c < 0x20) return;

    /* печатный символ целиком: ведущий байт + продолжения UTF-8 */
    size_t need;
    if (c < 0x80)              need = 0;
    else if ((c >> 5) == 0x6)  need = 1;
    else if ((c >> 4) == 0xE)  need = 2;
    else if ((c >> 3) == 0x1E) need = 3;
    else return;                                     /* мусорный байт */
    k->ch[0] = (char)c;
    for (size_t i = 1; i <= need; i++) {
        unsigned char cc;
        if (read(STDIN_FILENO, &cc, 1) != 1) { k->code = PK_EOF; return; }
        if ((cc & 0xC0) != 0x80) return;             /* битая последовательность */
        k->ch[i] = (char)cc;
    }
    k->chlen = need + 1;
    k->code = PK_CHAR;
}

/* ---------- строчный редактор (терминал POSIX) ---------- */

static size_t tty_cols(void)
{
    struct winsize ws;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0)
        return ws.ws_col;
    return 80;
}

/* Перерисовать приглашение + строку и поставить курсор на e->cur.
 * Строка может занимать несколько экранных строк: *cur_row — на какой
 * из них (от начала приглашения) сейчас стоит курсор. */
static void tty_refresh(const char *prompt, const le_state *e, size_t *cur_row)
{
    size_t cols  = tty_cols();
    size_t plen  = prompt ? u8_cells(prompt, strlen(prompt)) : 0;
    size_t total = plen + u8_cells(e->buf, e->len);
    size_t curc  = plen + u8_cells(e->buf, e->cur);

    if (*cur_row) printf("\033[%zuA", *cur_row);     /* к началу приглашения */
    fputs("\r\033[J", stdout);                       /* стереть всё ниже */
    if (prompt) fputs(prompt, stdout);
    fwrite(e->buf, 1, e->len, stdout);

    /* где курсор остался после печати */
    size_t end_row;
    if (total && total % cols == 0) {
        if (curc == total) {                         /* выйти из «отложенного» переноса */
            fputs("\r\n", stdout);
            end_row = total / cols;
        } else {
            end_row = (total - 1) / cols;
        }
    } else {
        end_row = total / cols;
    }

    size_t trow = curc / cols, tcol = curc % cols;
    if (end_row > trow) printf("\033[%zuA", end_row - trow);
    fputs("\r", stdout);
    if (tcol) printf("\033[%zuC", tcol);
    fflush(stdout);
    *cur_row = trow;
}

int plat_readline_hist(const char *prompt, char *buf, size_t len,
                       plat_complete_fn fn, void *fn_ctx, plat_history *hist)
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
    raw.c_iflag &= ~(tcflag_t)(IXON | ICRNL);
    raw.c_cc[VMIN]  = 1;
    raw.c_cc[VTIME] = 0;
    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw) != 0) return FV_ERR_IO;

    le_state e;
    le_init(&e, buf, len, hist);
    size_t cur_row = 0;
    int rc = FV_OK;

    for (;;) {
        plat_key pk;
        tty_decode(&pk, -1);
        if (pk.code == PK_EOF) { rc = FV_ERR_CANCEL; break; }
        le_key k = le_map(&pk);
        if (k == K_NONE) continue;

        if (k == K_TAB) {
            if (!fn) continue;
            size_t sc = e.cur;                       /* курсор в конец строки */
            e.cur = e.len;
            tty_refresh(prompt, &e, &cur_row);
            e.cur = sc;
            int act = le_tab(&e, fn, fn_ctx);
            if (act == 2) cur_row = 0;               /* варианты напечатаны ниже */
            tty_refresh(prompt, &e, &cur_row);
            continue;
        }

        int changed = 0;
        int done = le_apply(&e, k, pk.ch, pk.chlen, &changed);
        if (done) {
            if (done < 0) rc = FV_ERR_CANCEL;
            break;
        }
        if (changed) tty_refresh(prompt, &e, &cur_row);
    }

    if (e.cur != e.len) {                            /* курсор в конец строки */
        e.cur = e.len;
        tty_refresh(prompt, &e, &cur_row);
    }
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &old);
    fputs("\n", stdout);
    fflush(stdout);
    le_free(&e);
    if (rc != FV_OK) buf[0] = '\0';
    return rc;
}

/* ---------- полноэкранный режим (терминал POSIX) ---------- */

static struct termios t_old;
static int t_active;

static void term_write(const char *s, size_t n)
{
    size_t off = 0;
    while (off < n) {
        ssize_t r = write(STDOUT_FILENO, s + off, n - off);
        if (r < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (r == 0) break;
        off += (size_t)r;
    }
}

int plat_term_begin(void)
{
    if (t_active) return FV_OK;
    if (!isatty(STDIN_FILENO) || !isatty(STDOUT_FILENO)) return FV_ERR_ARG;
    const char *term = getenv("TERM");
    if (term && !strcmp(term, "dumb")) return FV_ERR_ARG;
    if (tcgetattr(STDIN_FILENO, &t_old) != 0) return FV_ERR_ARG;
    struct termios raw = t_old;
    raw.c_lflag &= ~(tcflag_t)(ECHO | ICANON | ISIG | IEXTEN);
    raw.c_iflag &= ~(tcflag_t)(IXON | ICRNL);       /* IXON: иначе Ctrl+S «замораживает» */
    raw.c_cc[VMIN]  = 1;
    raw.c_cc[VTIME] = 0;
    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw) != 0) return FV_ERR_ARG;
    fflush(stdout);
    t_active = 1;
    static const char enter[] = "\033[?1049h\033[H\033[2J";
    term_write(enter, sizeof enter - 1);
    return FV_OK;
}

void plat_term_end(void)
{
    if (!t_active) return;
    static const char leave[] = "\033[2J\033[?25h\033[?1049l";
    term_write(leave, sizeof leave - 1);
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &t_old);
    t_active = 0;
}

void plat_term_size(int *rows, int *cols)
{
    struct winsize ws;
    *rows = 24;
    *cols = 80;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0 && ws.ws_row > 0) {
        *rows = ws.ws_row;
        *cols = ws.ws_col;
    }
}

void plat_term_draw(const plat_cell *cells, int rows, int cols, int cur_row, int cur_col)
{
    if (rows <= 0 || cols <= 0) return;
    fv_buf b;
    fv_buf_init(&b);
    fv_buf_add(&b, "\033[?25l", 6);
    char seq[32];
    for (int r = 0; r < rows; r++) {
        int n = snprintf(seq, sizeof seq, "\033[%d;1H", r + 1);   /* каждая строка — явно */
        fv_buf_add(&b, seq, (size_t)n);
        int inv = 0;
        for (int c = 0; c < cols; c++) {
            if (r == rows - 1 && c == cols - 1) break;           /* угол: не прокрутить экран */
            const plat_cell *cl = &cells[(size_t)r * (size_t)cols + (size_t)c];
            if (!cl->ch) continue;                               /* правая половина широкого */
            if (cl->inv != inv) {
                fv_buf_add(&b, cl->inv ? "\033[7m" : "\033[m", cl->inv ? 4 : 3);
                inv = cl->inv;
            }
            uint32_t ch = cl->ch;
            unsigned char u[4];
            size_t ul;
            if (ch >= 0xD800 && ch <= 0xDFFF) ch = '?';
            if (ch < 0x80)         { u[0] = (unsigned char)ch; ul = 1; }
            else if (ch < 0x800)   { u[0] = (unsigned char)(0xC0 | (ch >> 6));
                                     u[1] = (unsigned char)(0x80 | (ch & 0x3F)); ul = 2; }
            else if (ch < 0x10000) { u[0] = (unsigned char)(0xE0 | (ch >> 12));
                                     u[1] = (unsigned char)(0x80 | ((ch >> 6) & 0x3F));
                                     u[2] = (unsigned char)(0x80 | (ch & 0x3F)); ul = 3; }
            else                   { u[0] = (unsigned char)(0xF0 | (ch >> 18));
                                     u[1] = (unsigned char)(0x80 | ((ch >> 12) & 0x3F));
                                     u[2] = (unsigned char)(0x80 | ((ch >> 6) & 0x3F));
                                     u[3] = (unsigned char)(0x80 | (ch & 0x3F)); ul = 4; }
            fv_buf_add(&b, u, ul);
        }
        if (inv) fv_buf_add(&b, "\033[m", 3);
    }
    int n = snprintf(seq, sizeof seq, "\033[%d;%dH\033[?25h", cur_row + 1, cur_col + 1);
    fv_buf_add(&b, seq, (size_t)n);
    term_write((const char *)b.data, b.len);
    if (b.data) fv_wipe(b.data, b.cap);              /* в кадре — текст файла */
    fv_buf_free(&b);
}

int plat_term_key(plat_key *k, int timeout_ms)
{
    tty_decode(k, timeout_ms);
    return FV_OK;
}

int plat_color_ok(void)
{
    if (!isatty(STDOUT_FILENO)) return 0;
    const char *term = getenv("TERM");
    return !(term && !strcmp(term, "dumb"));
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
