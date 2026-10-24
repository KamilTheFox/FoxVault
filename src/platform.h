/* platform.h — всё, что отличается между Windows и Linux.
 * Все пути на входе и выходе — в UTF-8. На Windows они внутри
 * переводятся в UTF-16 и идут в *W-функции, поэтому кириллица работает. */
#ifndef FV_PLATFORM_H
#define FV_PLATFORM_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#ifdef _WIN32
#define FV_PATH_SEP     '\\'
#define FV_PATH_SEP_STR "\\"
#else
#define FV_PATH_SEP     '/'
#define FV_PATH_SEP_STR "/"
#endif

#define FV_PATH_MAX 4096

/* Вызвать один раз в начале main: UTF-8 в консоли, запрет дампов памяти */
void plat_init(void);

/* Криптостойкие случайные байты: BCryptGenRandom / getrandom */
int plat_random(void *buf, size_t len);

/* Ввод без эха. Возвращает FV_OK или FV_ERR_CANCEL (EOF / Ctrl+C) */
int plat_read_password(const char *prompt, char *buf, size_t len);

/* Обычный ввод строки (UTF-8) для shell */
int plat_readline(const char *prompt, char *buf, size_t len);

/* Строчный редактор с поддержкой Tab-автодополнения.
 * fn вызывается на Tab: (line, *len) могут быть переписаны (слово дополнено).
 * Возврат fn: 0 — ничего; 1 — строка изменилась (перерисовать);
 *             2 — изменилась, и варианты уже напечатаны (перерисовать).
 * Если stdin — не терминал, работает как plat_readline (пайпы, тесты). */
typedef int (*plat_complete_fn)(char *line, size_t *len, void *ctx);
int plat_readline_ex(const char *prompt, char *buf, size_t len,
                     plat_complete_fn fn, void *fn_ctx);

/* Признак интерактивного терминала */
int plat_isatty_stdin(void);
int plat_isatty_stdout(void);

/* Монотонное время в миллисекундах (для темпа анимации) */
uint64_t plat_now_ms(void);

/* Защита секретов от свопа. Неудача не фатальна. */
int  plat_lock_mem(void *p, size_t len);
void plat_unlock_mem(void *p, size_t len);

/* Файлы */
FILE *plat_fopen(const char *path, const char *mode);
int   plat_fsync(FILE *f);                 /* сбросить данные на носитель */
int   plat_fsync_dir(const char *dir);     /* на Windows — ничего не делает */
int   plat_atomic_replace(const char *tmp, const char *dst);
int   plat_mkdir(const char *path);
int   plat_mkdir_p(const char *path);      /* создать вместе с родителями */
int   plat_remove(const char *path);

/* 0 — нет, 1 — файл, 2 — каталог */
int plat_stat_kind(const char *path);
int plat_file_size(const char *path, uint64_t *size);

/* Текущий каталог хоста (для lcd / lpwd) */
int plat_getcwd(char *buf, size_t len);
int plat_chdir(const char *path);

/* Список каталога хоста (для lls) */
typedef void (*plat_dir_cb)(const char *name, int is_dir, uint64_t size, void *ctx);
int plat_list_dir(const char *path, plat_dir_cb cb, void *ctx);

/* Раскрыть ~, %VAR% (Windows) или $VAR / ${VAR} (Linux) */
int plat_expand_path(const char *in, char *out, size_t len);

/* Каталог настроек пользователя: %APPDATA%\foxvault (Windows)
 * или $XDG_CONFIG_HOME/foxvault, $HOME/.config/foxvault (POSIX) */
int plat_config_dir(char *buf, size_t len);

/* Двоичная запись в stdout в обход текстового режима (для cat):
 * байты уходят без преобразования переводов строк */
void plat_write_stdout(const void *buf, size_t len);

#ifdef _WIN32
/* Аргументы командной строки в UTF-8: GetCommandLineW + CommandLineToArgvW,
 * каждый элемент выделен malloc'ом. Освобождать plat_free_argv().
 * Используется вместо wmain, чтобы не зависеть от точки входа CRT. */
char **plat_get_argv(int *argc);
void   plat_free_argv(char **argv, int argc);

/* UTF-16 -> UTF-8 (буфер malloc, освобождать free()) */
char *plat_wchar_to_utf8(const wchar_t *ws);
#endif

#endif
