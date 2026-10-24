/* vault.h — контейнер: заголовок + индекс + блобы.
 *
 * Каталог контейнера:
 *     header.0 / header.1  — два слота заголовка с номером поколения
 *     index.0  / index.1   — два слота зашифрованного индекса
 *     blobs/               — содержимое файлов под случайными именами
 *
 * Мастер-ключ шифрует индекс и блобы; сам он обёрнут ключом из пароля
 * (PBKDF2), поэтому смена пароля не перешифровывает данные. Существующие
 * данные никогда не меняются на месте: каждая запись идёт в свободный
 * слот через временный файл и атомарную замену.
 */
#ifndef FV_VAULT_H
#define FV_VAULT_H

#include "crypto.h"
#include "index.h"
#include "util.h"

#define FV_PASS_MAX 512

typedef struct fv_vault fv_vault;

typedef struct {
    uint8_t  type;
    char     name[FV_NAME_MAX + 1];
    uint64_t size;
    uint32_t chunk_size;
    uint64_t mtime;
    char     blob[33];
} fv_vstat;

/* Жизненный цикл */
int  fv_vault_create(const char *dir, const char *pass);
/* То же с колбэком прогресса PBKDF2 (для анимации при создании) */
int  fv_vault_create_ex(const char *dir, const char *pass,
                        fv_kdf_progress cb, void *cb_ctx);
int  fv_vault_open(fv_vault **out, const char *dir, const char *pass);
void fv_vault_free(fv_vault *v);

/* Блокировка: ключи стираются из памяти; разблокировка — по паролю */
void fv_vault_lock(fv_vault *v);
int  fv_vault_unlock(fv_vault *v, const char *pass);
int  fv_vault_is_locked(const fv_vault *v);
void fv_vault_touch(fv_vault *v);            /* отметить активность */

const char *fv_vault_dir(const fv_vault *v);
int  fv_vault_uuid_hex(const fv_vault *v, char out[33]);
uint32_t fv_vault_kdf_iters(const fv_vault *v);
uint32_t fv_vault_hdr_gen(const fv_vault *v);
uint32_t fv_vault_ix_gen(const fv_vault *v);
uint64_t fv_vault_idle_seconds(const fv_vault *v);   /* с последней активности */

int  fv_vault_change_password(fv_vault *v, const char *newpass);

/* Операции (все пути внутри контейнера — UTF-8, '/'-разделитель) */
int  fv_vault_mkdir(fv_vault *v, const char *path);
int  fv_vault_rm(fv_vault *v, const char *path, int recursive);
int  fv_vault_mv(fv_vault *v, const char *src, const char *dst);
int  fv_vault_put(fv_vault *v, const char *host_path, const char *vault_path);
int  fv_vault_get(fv_vault *v, const char *vault_path, const char *host_path);
int  fv_vault_cat(fv_vault *v, const char *vault_path);
int  fv_vault_stat(fv_vault *v, const char *path, fv_vstat *st);
int  fv_vault_list(fv_vault *v, const char *path, fv_list_cb cb, void *ctx);
void fv_vault_totals(const fv_vault *v, size_t *files, size_t *dirs, uint64_t *bytes);

/* Прочитать файл контейнера целиком в память (malloc; освобождает вызывающий).
 * Никаких промежуточных файлов на диске хоста. */
int  fv_vault_read_mem(fv_vault *v, const char *vpath, uint8_t **data, size_t *len);
/* Записать буфер как файл контейнера (перезапись существующего разрешена).
 * Тоже без временных файлов на диске хоста — для встроенного редактора. */
int  fv_vault_write_mem(fv_vault *v, const char *vpath,
                        const uint8_t *data, size_t len);

#endif
