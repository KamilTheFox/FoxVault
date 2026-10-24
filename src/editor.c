/* editor.c — минимальный полноэкранный редактор (в духе nano).
 *
 * Клавиши: стрелки, Home/End, PgUp/PgDn, ввод текста, Enter, Backspace,
 * Delete, Tab; ^S (или ^O) — сохранить, ^X — выйти. Больше ничего.
 * Рисуется ESC-последовательностями VT100 (Linux-терминалы, консоль
 * Windows 10+), строки длиннее экрана прокручиваются по горизонтали.
 * Все буферы с текстом затираются перед освобождением.
 */
#include "editor.h"
#include "crypto.h"
#include "platform.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__GNUC__)
#pragma GCC diagnostic ignored "-Wformat-truncation"
#endif

#define TAB_STOP   4
#define TICK_MS    400

typedef struct {
    char  *s;
    size_t len, cap;
} erow;

typedef struct {
    erow   *r;
    size_t  n, cap;
    size_t  cy, cx;             /* строка и байт в ней */
    size_t  want;               /* желаемая экранная колонка для ↑/↓ */
    size_t  rowoff, coloff;     /* прокрутка */
    int     rows, cols;
    int     dirty, crlf, final_nl, is_new;
    char    msg[200];
    const char *title;
    const fv_edit_hooks *h;
} ed;

/* ---------- строки ---------- */

/* вырасти без realloc: старый буфер с текстом затирается, а не бросается */
static int row_reserve(erow *r, size_t need)
{
    if (need + 1 <= r->cap) return 1;
    size_t nc = r->cap ? r->cap : 16;
    while (nc < need + 1) nc *= 2;
    char *ns = (char *)malloc(nc);
    if (!ns) return 0;
    if (r->len) memcpy(ns, r->s, r->len);
    ns[r->len] = '\0';
    if (r->s) {
        fv_wipe(r->s, r->cap);
        free(r->s);
    }
    r->s = ns;
    r->cap = nc;
    return 1;
}

static int row_insert(erow *r, size_t at, const char *s, size_t n)
{
    if (!row_reserve(r, r->len + n)) return 0;
    memmove(r->s + at + n, r->s + at, r->len - at);
    memcpy(r->s + at, s, n);
    r->len += n;
    r->s[r->len] = '\0';
    return 1;
}

static void row_cut(erow *r, size_t a, size_t b)
{
    if (a >= b) return;
    memmove(r->s + a, r->s + b, r->len - b);
    r->len -= b - a;
    fv_wipe(r->s + r->len, b - a);
    r->s[r->len] = '\0';
}

static void row_free(erow *r)
{
    if (r->s) {
        fv_wipe(r->s, r->cap);
        free(r->s);
    }
    memset(r, 0, sizeof *r);
}

static int ed_insert_row(ed *e, size_t at, const char *s, size_t len)
{
    if (e->n == e->cap) {
        size_t nc = e->cap ? e->cap * 2 : 64;
        erow *nr = (erow *)realloc(e->r, nc * sizeof(erow));   /* тут только указатели */
        if (!nr) return 0;
        e->r = nr;
        e->cap = nc;
    }
    memmove(e->r + at + 1, e->r + at, (e->n - at) * sizeof(erow));
    memset(&e->r[at], 0, sizeof(erow));
    if (!row_insert(&e->r[at], 0, s, len)) {         /* всегда выделяет буфер, даже для "" */
        memmove(e->r + at, e->r + at + 1, (e->n - at) * sizeof(erow));
        return 0;
    }
    e->n++;
    return 1;
}

static void ed_del_row(ed *e, size_t at)
{
    row_free(&e->r[at]);
    memmove(e->r + at, e->r + at + 1, (e->n - at - 1) * sizeof(erow));
    e->n--;
}

static void ed_free(ed *e)
{
    for (size_t i = 0; i < e->n; i++) row_free(&e->r[i]);
    free(e->r);
    e->r = NULL;
    e->n = e->cap = 0;
}

/* ---------- символы и колонки ---------- */

static int is_bad_cp(uint32_t c)
{
    return c < 0x20 || c == 0x7f || (c >= 0xDC80 && c <= 0xDCFF);
}

/* ширина символа на экране; управляющие и битые байты рисуются как «?» */
static size_t cp_cells(uint32_t c, size_t col)
{
    if (c == '\t') return TAB_STOP - col % TAB_STOP;
    if (is_bad_cp(c)) return 1;
    return (size_t)fv_cp_width(c);
}

static size_t rx_of(const erow *r, size_t cx)
{
    size_t rx = 0;
    const char *p = r->s, *end = r->s + cx, *lim = r->s + r->len;
    while (p < end) {
        uint32_t c = fv_u8_decode(&p, lim);
        rx += cp_cells(c, rx);
    }
    return rx;
}

/* байт, на котором окажется курсор при экранной колонке want */
static size_t cx_of_rx(const erow *r, size_t want)
{
    size_t rx = 0;
    const char *p = r->s, *lim = r->s + r->len;
    while (p < lim) {
        const char *q = p;
        uint32_t c = fv_u8_decode(&p, lim);
        size_t w = cp_cells(c, rx);
        if (rx + w > want) return (size_t)(q - r->s);
        rx += w;
    }
    return r->len;
}

static size_t prev_cp(const erow *r, size_t cx)
{
    size_t last = 0;
    const char *p = r->s, *lim = r->s + r->len;
    while ((size_t)(p - r->s) < cx) {
        last = (size_t)(p - r->s);
        (void)fv_u8_decode(&p, lim);
    }
    return last;
}

static size_t next_cp(const erow *r, size_t cx)
{
    const char *p = r->s + cx;
    if (cx >= r->len) return r->len;
    (void)fv_u8_decode(&p, r->s + r->len);
    return (size_t)(p - r->s);
}

/* ---------- отрисовка: сетка ячеек ---------- */

typedef struct {
    plat_cell *c;
    int        rows, cols;
} grid;

static void g_put(grid *g, int y, int x, uint32_t ch, uint8_t inv)
{
    if (y < 0 || y >= g->rows || x < 0 || x >= g->cols) return;
    plat_cell *cl = &g->c[(size_t)y * (size_t)g->cols + (size_t)x];
    cl->ch = ch;
    cl->inv = inv;
}

/* строка UTF-8 с позиции x, не дальше max_x (не включая); вернуть новый x */
static int g_text(grid *g, int y, int x, const char *s, int max_x, uint8_t inv)
{
    const char *p = s, *lim = s + strlen(s);
    while (p < lim && x < max_x) {
        uint32_t c = fv_u8_decode(&p, lim);
        int w = is_bad_cp(c) ? 1 : fv_cp_width(c);
        if (w == 0) continue;
        if (x + w > max_x) break;
        g_put(g, y, x, is_bad_cp(c) ? '?' : c, inv);
        if (w == 2) g_put(g, y, x + 1, 0, inv);
        x += w;
    }
    return x;
}

static void draw_row(grid *g, int y, const erow *r, size_t coloff)
{
    size_t cols = (size_t)g->cols;
    size_t col = 0;
    const char *p = r->s, *lim = r->s + r->len;
    while (p < lim) {
        uint32_t c = fv_u8_decode(&p, lim);
        size_t w = cp_cells(c, col);
        if (w == 0) continue;                        /* комбинирующие не рисуем отдельно */
        if (col + w <= coloff) { col += w; continue; }       /* левее окна */
        if (col >= coloff + cols) break;                     /* правее окна */
        int x = (int)(col - (col < coloff ? col : coloff));
        if (c == '\t' || col < coloff || col + w > coloff + cols) {
            /* табуляция или широкий символ на краю окна — пробелы (уже есть) */
        } else if (is_bad_cp(c)) {
            g_put(g, y, x, '?', 1);
        } else {
            g_put(g, y, x, c, 0);
            if (w == 2) g_put(g, y, x + 1, 0, 0);
        }
        col += w;
    }
}

static int text_rows(const ed *e)
{
    return e->rows >= 3 ? e->rows - 2 : e->rows;
}

static void ed_scroll(ed *e)
{
    size_t tr = (size_t)text_rows(e);
    if (e->cy < e->rowoff) e->rowoff = e->cy;
    if (e->cy >= e->rowoff + tr) e->rowoff = e->cy - tr + 1;
    size_t rx = rx_of(&e->r[e->cy], e->cx);
    size_t cols = (size_t)e->cols;
    if (rx < e->coloff) e->coloff = rx;
    if (rx >= e->coloff + cols) e->coloff = rx - cols + 1;
}

static void ed_draw(ed *e)
{
    plat_term_size(&e->rows, &e->cols);
    ed_scroll(e);
    grid g;
    g.rows = e->rows;
    g.cols = e->cols;
    size_t n = (size_t)g.rows * (size_t)g.cols;
    g.c = (plat_cell *)calloc(n, sizeof(plat_cell));
    if (!g.c) return;
    for (size_t i = 0; i < n; i++) g.c[i].ch = ' ';

    int tr = text_rows(e);
    for (int y = 0; y < tr; y++) {
        size_t fr = e->rowoff + (size_t)y;
        if (fr < e->n) draw_row(&g, y, &e->r[fr], e->coloff);
    }

    if (e->rows >= 3) {
        int sy = e->rows - 2;                        /* строка состояния — инверсией */
        for (int x = 0; x < g.cols; x++) g_put(&g, sy, x, ' ', 1);
        char left[FV_PATH_MAX + 64], right[96];
        snprintf(left, sizeof left, " %s%s%s", e->title,
                 e->is_new ? "  [новый]" : "", e->dirty ? "  [изменён]" : "");
        snprintf(right, sizeof right, "строка %zu/%zu ", e->cy + 1, e->n);
        int rcells = 0;
        for (const char *pr = right; *pr; ) {
            (void)fv_u8_decode(&pr, right + strlen(right));
            rcells++;
        }
        int rx0 = g.cols - rcells;
        int lx = g_text(&g, sy, 0, left, rx0 > 0 ? rx0 - 1 : g.cols, 1);
        if (rx0 > lx) g_text(&g, sy, rx0, right, g.cols, 1);
        /* подсказка или сообщение; в последнюю колонку не пишем */
        g_text(&g, e->rows - 1, 0,
               e->msg[0] ? e->msg : " ^S Сохранить   ^X Выход   стрелки, Home/End, PgUp/PgDn",
               g.cols - 1, 0);
    }

    size_t rx = rx_of(&e->r[e->cy], e->cx);
    plat_term_draw(g.c, g.rows, g.cols, (int)(e->cy - e->rowoff), (int)(rx - e->coloff));
    fv_wipe(g.c, n * sizeof(plat_cell));             /* в сетке — текст файла */
    free(g.c);
}

/* ---------- загрузка и сохранение ---------- */

static int ed_load(ed *e, const uint8_t *data, size_t len)
{
    const char *s = (const char *)data;
    size_t nl = 0, cr = 0;
    for (size_t i = 0; i < len; i++)
        if (s[i] == '\n') {
            nl++;
            if (i && s[i - 1] == '\r') cr++;
        }
    e->crlf = (nl && cr == nl);
    e->final_nl = (len == 0) || s[len - 1] == '\n';

    size_t i = 0;
    while (i < len) {
        size_t j = i;
        while (j < len && s[j] != '\n') j++;
        size_t l = j - i;
        if (e->crlf && j < len && l && s[i + l - 1] == '\r') l--;
        if (!ed_insert_row(e, e->n, s + i, l)) return 0;
        i = j + 1;
    }
    if (e->n == 0 && !ed_insert_row(e, 0, "", 0)) return 0;
    return 1;
}

static int ed_save(ed *e)
{
    const char *nl = e->crlf ? "\r\n" : "\n";
    size_t nll = strlen(nl);
    size_t total = 0;
    int empty = (e->n == 1 && e->r[0].len == 0);
    if (!empty) {
        for (size_t i = 0; i < e->n; i++) total += e->r[i].len;
        total += (e->n - 1) * nll + (e->final_nl ? nll : 0);
    }
    uint8_t *out = (uint8_t *)malloc(total ? total : 1);
    if (!out) {
        snprintf(e->msg, sizeof e->msg, " нет памяти — не сохранено");
        return 0;
    }
    size_t o = 0;
    if (!empty) {
        for (size_t i = 0; i < e->n; i++) {
            memcpy(out + o, e->r[i].s, e->r[i].len);
            o += e->r[i].len;
            if (i + 1 < e->n || e->final_nl) {
                memcpy(out + o, nl, nll);
                o += nll;
            }
        }
    }
    int rc = e->h->save(e->h->ctx, out, total);
    fv_wipe(out, total ? total : 1);
    free(out);
    if (rc != FV_OK) {
        snprintf(e->msg, sizeof e->msg, " не сохранено: %s",
                 e->h->strerror ? e->h->strerror(rc) : "ошибка");
        return 0;
    }
    e->dirty = 0;
    e->is_new = 0;
    snprintf(e->msg, sizeof e->msg, " сохранено: %zu строк, %zu байт", e->n, total);
    return 1;
}

/* ---------- ожидание клавиши с проверками безопасности ---------- */

/* FV_OK — в *k настоящая клавиша; иначе код выхода из редактора */
static int ed_wait_key(ed *e, plat_key *k)
{
    for (;;) {
        plat_term_key(k, TICK_MS);
        if (k->code == PK_EOF) return FV_ERR_IO;
        if (k->code != PK_TIMEOUT && k->code != PK_NONE) {
            if (e->h->touch) e->h->touch(e->h->ctx);
            return FV_OK;
        }
        int st = e->h->check ? e->h->check(e->h->ctx) : FV_EDIT_OK;
        if (st == FV_EDIT_GONE) return FV_ERR_NOTFOUND;
        if (st == FV_EDIT_LOCK) {
            plat_term_end();                         /* текст файла уходит с экрана */
            if (!e->h->unlock || e->h->unlock(e->h->ctx) != FV_OK) return FV_ERR_AUTH;
            if (plat_term_begin() != FV_OK) return FV_ERR_IO;
            ed_draw(e);
            continue;
        }
        int r, c;                                    /* окно изменилось — перерисовать */
        plat_term_size(&r, &c);
        if (r != e->rows || c != e->cols || k->code == PK_NONE) ed_draw(e);
    }
}

static int is_answer(const plat_key *k, const char *lat, const char *cyr)
{
    if (k->code != PK_CHAR) return 0;
    return (k->chlen == 1 && (k->ch[0] == lat[0] || k->ch[0] == lat[1])) ||
           (k->chlen == strlen(cyr) / 2 && (!strncmp(k->ch, cyr, k->chlen) ||
                                           !strncmp(k->ch, cyr + k->chlen, k->chlen)));
}

/* ---------- главный цикл ---------- */

int fv_edit_run(const char *title, const uint8_t *data, size_t len, int is_new,
                const fv_edit_hooks *h)
{
    if (!h || !h->save) return FV_ERR_ARG;
    if (plat_term_begin() != FV_OK) return FV_ERR_ARG;

    ed e;
    memset(&e, 0, sizeof e);
    e.title = title;
    e.h = h;
    e.is_new = is_new;
    if (!ed_load(&e, data, len)) {
        ed_free(&e);
        plat_term_end();
        return FV_ERR_NOMEM;
    }

    int rc = FV_OK;
    ed_draw(&e);
    for (;;) {
        plat_key k;
        int wr = ed_wait_key(&e, &k);
        if (wr != FV_OK) { rc = wr; break; }
        e.msg[0] = '\0';
        erow *row = &e.r[e.cy];
        int hmove = 0, quit = 0;

        for (unsigned rep = 0; rep < k.rep; rep++) {
            row = &e.r[e.cy];
            switch (k.code) {
            case PK_CHAR:
                if (row_insert(row, e.cx, k.ch, k.chlen)) { e.cx += k.chlen; e.dirty = 1; }
                hmove = 1;
                break;
            case PK_TAB:
                if (row_insert(row, e.cx, "\t", 1)) { e.cx++; e.dirty = 1; }
                hmove = 1;
                break;
            case PK_ENTER:
                if (ed_insert_row(&e, e.cy + 1, row->s + e.cx, row->len - e.cx)) {
                    row = &e.r[e.cy];                /* массив мог переехать */
                    row_cut(row, e.cx, row->len);
                    e.cy++;
                    e.cx = 0;
                    e.dirty = 1;
                }
                hmove = 1;
                break;
            case PK_BACK:
                if (e.cx > 0) {
                    size_t p = prev_cp(row, e.cx);
                    row_cut(row, p, e.cx);
                    e.cx = p;
                    e.dirty = 1;
                } else if (e.cy > 0) {
                    erow *up = &e.r[e.cy - 1];
                    size_t ul = up->len;
                    if (row_insert(up, ul, row->s, row->len)) {
                        ed_del_row(&e, e.cy);
                        e.cy--;
                        e.cx = ul;
                        e.dirty = 1;
                    }
                }
                hmove = 1;
                break;
            case PK_DEL:
                if (e.cx < row->len) {
                    row_cut(row, e.cx, next_cp(row, e.cx));
                    e.dirty = 1;
                } else if (e.cy + 1 < e.n) {
                    erow *dn = &e.r[e.cy + 1];
                    if (row_insert(row, row->len, dn->s, dn->len)) {
                        ed_del_row(&e, e.cy + 1);
                        e.dirty = 1;
                    }
                }
                hmove = 1;
                break;
            case PK_LEFT:
                if (e.cx > 0) e.cx = prev_cp(row, e.cx);
                else if (e.cy > 0) { e.cy--; e.cx = e.r[e.cy].len; }
                hmove = 1;
                break;
            case PK_RIGHT:
                if (e.cx < row->len) e.cx = next_cp(row, e.cx);
                else if (e.cy + 1 < e.n) { e.cy++; e.cx = 0; }
                hmove = 1;
                break;
            case PK_HOME: e.cx = 0; hmove = 1; break;
            case PK_END:  e.cx = row->len; hmove = 1; break;
            case PK_UP:
                if (e.cy > 0) e.cy--;
                e.cx = cx_of_rx(&e.r[e.cy], e.want);
                break;
            case PK_DOWN:
                if (e.cy + 1 < e.n) e.cy++;
                e.cx = cx_of_rx(&e.r[e.cy], e.want);
                break;
            case PK_PGUP:
            case PK_PGDN: {
                size_t step = (size_t)(text_rows(&e) > 1 ? text_rows(&e) - 1 : 1);
                if (k.code == PK_PGUP) {
                    e.cy = e.cy > step ? e.cy - step : 0;
                    e.rowoff = e.rowoff > step ? e.rowoff - step : 0;
                } else {
                    e.cy = (e.cy + step < e.n) ? e.cy + step : e.n - 1;
                    e.rowoff += step;
                    if (e.rowoff > e.cy) e.rowoff = e.cy;
                }
                e.cx = cx_of_rx(&e.r[e.cy], e.want);
                break;
            }
            case PK_CTRL:
                if (k.ctrl == 's' || k.ctrl == 'o') ed_save(&e);
                else if (k.ctrl == 'x') quit = 1;
                else if (k.ctrl == 'c') snprintf(e.msg, sizeof e.msg, " выход — ^X, сохранить — ^S");
                break;
            default:
                break;
            }
            if (quit || k.code == PK_CTRL) break;    /* ^S не повторяем */
        }
        if (hmove) e.want = rx_of(&e.r[e.cy], e.cx);

        if (quit) {
            if (!e.dirty) break;
            snprintf(e.msg, sizeof e.msg,
                     " Сохранить изменения?  Y — да,  N — нет,  Esc — вернуться");
            ed_draw(&e);
            int done = 0;
            for (;;) {
                plat_key a;
                int ar = ed_wait_key(&e, &a);
                if (ar != FV_OK) { rc = ar; done = 2; break; }
                if (is_answer(&a, "yY", "дД") || a.code == PK_ENTER) {
                    if (ed_save(&e)) done = 1;
                    break;
                }
                if (is_answer(&a, "nN", "нН")) { done = 1; break; }
                if (a.code == PK_ESC || (a.code == PK_CTRL && a.ctrl == 'c')) {
                    e.msg[0] = '\0';
                    break;
                }
            }
            if (done) break;
        }
        ed_draw(&e);
    }

    ed_free(&e);
    plat_term_end();
    return rc;
}
