/* rx.h — маленький движок регулярных выражений для grep.
 *
 * Синтаксис — расширенный (как grep -E):
 *   a|b  (…)  *  +  ?  .  ^  $  [abc] [a-z] [^abc]  \d \w \s \D \W \S
 *   \.  \|  \(  и т.п. — буквальные символы
 * Работает по символам UTF-8 (точка, ? и классы — это один символ,
 * а не байт). Поиск — виртуальная машина Пайка: время линейно по длине
 * строки, «взрывных» шаблонов вроде (a*)*b не бывает.
 * Своя реализация, потому что в MinGW нет <regex.h>, а внешние
 * библиотеки сломали бы статический одиночный exe.
 */
#ifndef FV_RX_H
#define FV_RX_H

#include <stddef.h>

typedef struct fv_rx fv_rx;

/* icase — без учёта регистра (латиница и кириллица);
 * fixed — шаблон как обычная строка (grep -F).
 * При ошибке *err — описание на русском. */
int  fv_rx_compile(fv_rx **out, const char *pat, int icase, int fixed,
                   const char **err);

/* Первое (самое левое) совпадение в s[0, len), начиная с байта from.
 * 1 — найдено: [*ms, *me) в байтах; 0 — нет. */
int  fv_rx_search(const fv_rx *rx, const char *s, size_t len, size_t from,
                  size_t *ms, size_t *me);

void fv_rx_free(fv_rx *rx);

#endif
