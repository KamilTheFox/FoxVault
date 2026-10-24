/* shell.h — интерактивный шелл внутри контейнера */
#ifndef FV_SHELL_H
#define FV_SHELL_H

#include "vault.h"

/* Запустить REPL. Возвращает 0 при нормальном выходе (exit/quit/EOF). */
int fv_shell_run(fv_vault *v);

#endif
