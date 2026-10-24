/* util.h — коды ошибок и мелкие помощники */
#ifndef FV_UTIL_H
#define FV_UTIL_H

#include <stddef.h>
#include <stdint.h>

enum {
    FV_OK           =  0,
    FV_ERR_IO       = -1,   /* ошибка чтения/записи */
    FV_ERR_AUTH     = -2,   /* неверный пароль или данные повреждены */
    FV_ERR_FORMAT   = -3,   /* неизвестный или испорченный формат */
    FV_ERR_NOMEM    = -4,
    FV_ERR_ARG      = -5,   /* неверный аргумент */
    FV_ERR_EXISTS   = -6,
    FV_ERR_NOTFOUND = -7,
    FV_ERR_CRYPTO   = -8,   /* внутренняя ошибка криптобиблиотеки */
    FV_ERR_CANCEL   = -9,   /* отменено пользователем */
    FV_ERR_RANGE    = -10,  /* значение вне допустимых границ */
    FV_ERR_NOTEMPTY = -11   /* каталог не пуст */
};

const char *fv_strerror(int err);

/* Little-endian кодирование — формат на диске не зависит от платформы */
void     fv_put_u16(uint8_t *p, uint16_t v);
void     fv_put_u32(uint8_t *p, uint32_t v);
void     fv_put_u64(uint8_t *p, uint64_t v);
uint16_t fv_get_u16(const uint8_t *p);
uint32_t fv_get_u32(const uint8_t *p);
uint64_t fv_get_u64(const uint8_t *p);

/* Память для секретов: заблокирована от свопа (по возможности),
 * при освобождении затирается. Размер нужно передавать тот же. */
void *fv_secure_alloc(size_t size);
void  fv_secure_free(void *p, size_t size);

/* Перевод байтов в hex (out должен вмещать 2*len+1) */
void fv_hex(const uint8_t *in, size_t len, char *out);

/* --- растущий байтовый буфер (сериализация индекса) --- */
typedef struct {
    uint8_t *data;
    size_t   len, cap;
} fv_buf;

void fv_buf_init(fv_buf *b);
int  fv_buf_add(fv_buf *b, const void *p, size_t n);      /* FV_OK / FV_ERR_NOMEM */
int  fv_buf_add_u8(fv_buf *b, uint8_t v);
int  fv_buf_add_u32(fv_buf *b, uint32_t v);
int  fv_buf_add_u64(fv_buf *b, uint64_t v);
void fv_buf_free(fv_buf *b);

/* --- список строк (имена блобов при удалении и т.п.) --- */
typedef struct {
    char **items;
    size_t count, cap;
} fv_strlist;

int  fv_strlist_add(fv_strlist *s, const char *str);
void fv_strlist_free(fv_strlist *s);

/* Человекочитаемый размер: "13.5 КиБ" (кириллица, двоичные приставки) */
void fv_human(uint64_t bytes, char *out, size_t len);

/* Последний компонент пути (сепараторы '/' и '\\'); возвращает указатель внутрь path */
int  fv_basename(const char *path, const char **base);

/* Каталог без последнего компонента; если его нет — "." */
int  fv_dirname(const char *path, char *out, size_t len);

/* Склейка a + сепаратор + b (сепаратор ставится, только если a им не кончается) */
void fv_path_join(char *out, size_t n, const char *a, const char *b);

/* --- UTF-8 --- */

/* Декодировать один символ из [*p, end) и сдвинуть *p (минимум на байт).
 * Битый байт b возвращается как 0xDC00 + b (как surrogateescape в Python):
 * такой код уникален и не совпадёт ни с одним настоящим символом. */
uint32_t fv_u8_decode(const char **p, const char *end);

/* Без учёта регистра: латиница и кириллица (А..Я, Ё, Ђ..Џ) -> строчные */
uint32_t fv_fold_cp(uint32_t c);

/* Ширина символа на экране: 0 — комбинирующий, 2 — широкий (CJK, эмодзи),
 * иначе 1 */
int fv_cp_width(uint32_t c);

#endif
