/* util.c */
#include "util.h"
#include "crypto.h"
#include "platform.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char *fv_strerror(int err)
{
    switch (err) {
    case FV_OK:           return "успешно";
    case FV_ERR_IO:       return "ошибка ввода-вывода";
    case FV_ERR_AUTH:     return "неверный пароль или данные повреждены";
    case FV_ERR_FORMAT:   return "неверный формат контейнера";
    case FV_ERR_NOMEM:    return "недостаточно памяти";
    case FV_ERR_ARG:      return "неверный аргумент";
    case FV_ERR_EXISTS:   return "уже существует";
    case FV_ERR_NOTFOUND: return "не найдено";
    case FV_ERR_CRYPTO:   return "ошибка криптобиблиотеки";
    case FV_ERR_CANCEL:   return "отменено";
    case FV_ERR_RANGE:    return "значение вне допустимых границ";
    case FV_ERR_NOTEMPTY: return "каталог не пуст";
    default:              return "неизвестная ошибка";
    }
}

void fv_put_u16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
}

void fv_put_u32(uint8_t *p, uint32_t v)
{
    for (int i = 0; i < 4; i++) p[i] = (uint8_t)(v >> (8 * i));
}

void fv_put_u64(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (8 * i));
}

uint16_t fv_get_u16(const uint8_t *p)
{
    return (uint16_t)(p[0] | (p[1] << 8));
}

uint32_t fv_get_u32(const uint8_t *p)
{
    uint32_t v = 0;
    for (int i = 3; i >= 0; i--) v = (v << 8) | p[i];
    return v;
}

uint64_t fv_get_u64(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--) v = (v << 8) | p[i];
    return v;
}

void *fv_secure_alloc(size_t size)
{
    if (size == 0) size = 1;
    void *p = calloc(1, size);
    if (p) plat_lock_mem(p, size);   /* неудача блокировки не фатальна */
    return p;
}

void fv_secure_free(void *p, size_t size)
{
    if (!p) return;
    if (size == 0) size = 1;
    fv_wipe(p, size);
    plat_unlock_mem(p, size);
    free(p);
}

void fv_hex(const uint8_t *in, size_t len, char *out)
{
    static const char d[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[2 * i]     = d[in[i] >> 4];
        out[2 * i + 1] = d[in[i] & 0x0f];
    }
    out[2 * len] = '\0';
}

/* ---------- растущий буфер ---------- */

void fv_buf_init(fv_buf *b)
{
    b->data = NULL;
    b->len = 0;
    b->cap = 0;
}

int fv_buf_add(fv_buf *b, const void *p, size_t n)
{
    if (!b) return FV_ERR_ARG;
    if (n == 0) return FV_OK;
    if (b->len + n < b->len) return FV_ERR_RANGE;         /* переполнение size_t */
    if (b->len + n > b->cap) {
        size_t nc = b->cap ? b->cap : 64;
        while (nc < b->len + n) nc *= 2;
        uint8_t *nd = (uint8_t *)realloc(b->data, nc);
        if (!nd) return FV_ERR_NOMEM;
        b->data = nd;
        b->cap = nc;
    }
    if (p) memcpy(b->data + b->len, p, n);
    else   memset(b->data + b->len, 0, n);
    b->len += n;
    return FV_OK;
}

int fv_buf_add_u8(fv_buf *b, uint8_t v)
{
    return fv_buf_add(b, &v, 1);
}

int fv_buf_add_u32(fv_buf *b, uint32_t v)
{
    uint8_t t[4];
    fv_put_u32(t, v);
    return fv_buf_add(b, t, 4);
}

int fv_buf_add_u64(fv_buf *b, uint64_t v)
{
    uint8_t t[8];
    fv_put_u64(t, v);
    return fv_buf_add(b, t, 8);
}

void fv_buf_free(fv_buf *b)
{
    if (!b) return;
    free(b->data);
    fv_buf_init(b);
}

/* ---------- список строк ---------- */

int fv_strlist_add(fv_strlist *s, const char *str)
{
    if (!s || !str) return FV_ERR_ARG;
    if (s->count == s->cap) {
        size_t nc = s->cap ? s->cap * 2 : 8;
        char **ni = (char **)realloc(s->items, nc * sizeof(char *));
        if (!ni) return FV_ERR_NOMEM;
        s->items = ni;
        s->cap = nc;
    }
    size_t l = strlen(str) + 1;
    char *copy = (char *)malloc(l);
    if (!copy) return FV_ERR_NOMEM;
    memcpy(copy, str, l);
    s->items[s->count++] = copy;
    return FV_OK;
}

void fv_strlist_free(fv_strlist *s)
{
    if (!s) return;
    for (size_t i = 0; i < s->count; i++) free(s->items[i]);
    free(s->items);
    s->items = NULL;
    s->count = s->cap = 0;
}

/* ---------- разные помощники ---------- */

void fv_human(uint64_t bytes, char *out, size_t len)
{
    static const char *units[] = { "Б", "КиБ", "МиБ", "ГиБ", "ТиБ" };
    double v = (double)bytes;
    int ui = 0;
    while (v >= 1024.0 && ui < 4) {
        v /= 1024.0;
        ui++;
    }
    if (ui == 0) snprintf(out, len, "%" PRIu64 " %s", bytes, units[0]);
    else         snprintf(out, len, "%.1f %s", v, units[ui]);
}

int fv_basename(const char *path, const char **base)
{
    if (!path || !base) return FV_ERR_ARG;
    const char *s1 = strrchr(path, '/');
    const char *s2 = strrchr(path, '\\');
    const char *s = (s1 && s1 > s2) ? s1 : s2;
    *base = s ? s + 1 : path;
    return FV_OK;
}

int fv_dirname(const char *path, char *out, size_t len)
{
    if (!path || !out || len < 2) return FV_ERR_ARG;
    const char *s1 = strrchr(path, '/');
    const char *s2 = strrchr(path, '\\');
    const char *s = (s1 && s1 > s2) ? s1 : s2;
    if (!s) {
        out[0] = '.';
        out[1] = '\0';
        return FV_OK;
    }
    size_t cut = (size_t)(s - path);
    size_t l;
    if (cut == 0)                        l = 1;   /* "/x" -> "/", "\x" -> "\" */
    else if (cut == 2 && path[1] == ':') l = 3;   /* "C:\x" -> "C:\" */
    else                                 l = cut; /* "/a/b" -> "/a" */
    if (l >= len) return FV_ERR_RANGE;
    memcpy(out, path, l);
    out[l] = '\0';
    return FV_OK;
}

void fv_path_join(char *out, size_t n, const char *a, const char *b)
{
    if (!out || n == 0 || !a || !b) return;
    size_t la = strlen(a);
    const char *sep = (la && a[la - 1] != '/' && a[la - 1] != '\\') ? FV_PATH_SEP_STR : "";
    snprintf(out, n, "%s%s%s", a, sep, b);
}
