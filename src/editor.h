/* editor.h — минимальный полноэкранный редактор для команды edit.
 *
 * Только самое нужное: открыть, листать, править, сохранить (^S), выйти (^X).
 * Текст живёт только в памяти; сохранение идёт через hooks->save прямо
 * в зашифрованный контейнер. Альтернативный экран терминала: после выхода
 * ни на экране, ни в прокрутке текста файла не остаётся.
 */
#ifndef FV_EDITOR_H
#define FV_EDITOR_H

#include <stddef.h>
#include <stdint.h>

enum { FV_EDIT_OK = 0, FV_EDIT_LOCK = 1, FV_EDIT_GONE = 2 };

typedef struct {
    void *ctx;
    /* записать текст в контейнер: FV_OK или код ошибки */
    int  (*save)(void *ctx, const uint8_t *data, size_t len);
    /* раз в ~0,4 с без нажатий: FV_EDIT_OK, FV_EDIT_LOCK (пора блокировать),
     * FV_EDIT_GONE (носитель извлечён) */
    int  (*check)(void *ctx);
    /* терминал уже в обычном режиме: стереть ключи, спросить пароль;
     * FV_OK — продолжить правку */
    int  (*unlock)(void *ctx);
    /* нажатие клавиши — не простой */
    void (*touch)(void *ctx);
    /* сообщение об ошибке save -> текст */
    const char *(*strerror)(int rc);
} fv_edit_hooks;

/* Запустить редактор. data/len — текущий текст (NULL/0 для нового файла),
 * буфер не меняется и не освобождается.
 * FV_OK — обычный выход; FV_ERR_ARG — терминал не поддерживает полноэкранный
 * режим (ничего не сделано, можно перейти на строчный редактор);
 * FV_ERR_AUTH — автоблокировка без верного пароля; FV_ERR_NOTFOUND — носитель
 * извлечён. В двух последних случаях несохранённые правки стёрты. */
int fv_edit_run(const char *title, const uint8_t *data, size_t len, int is_new,
                const fv_edit_hooks *h);

#endif
