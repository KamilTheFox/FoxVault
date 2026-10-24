/* blob.h — блобы: содержимое файлов под случайными именами, зашифрованное кусками.
 *
 * Файл блоба на диске:
 *     u32 magic 'FVBL' | u32 version | u32 chunk_size | u32 chunk_count
 *     затем chunk_count записей: nonce[12] | ciphertext | tag[16]
 * Каждый чанк шифруется мастер-ключом; AAD связывает чанк с контейнером,
 * конкретным блобом и его позицией — подмена чанка между блобами или
 * перестановка чанков обнаруживаются по тегу.
 */
#ifndef FV_BLOB_H
#define FV_BLOB_H

#include <stdio.h>

#include "crypto.h"

#define FV_CHUNK_DEFAULT (256u * 1024u)   /* байт открытого текста на чанк */
#define FV_BLOB_NAME_LEN 32               /* hex-символов, без ".bin" */
#define FV_BLOB_HEADER_LEN 16u

/* Источник открытого текста: файл хоста или буфер в памяти (для edit) */
typedef struct {
    int             is_mem;        /* 1 — из памяти, 0 — из FILE* */
    FILE           *f;
    const uint8_t  *mem;
    size_t          mem_len;
    size_t          mem_pos;
} fv_blob_src;

/* Записать источник в blobs_dir под новым случайным именем.
 * expected_size известен заранее — по нему считается число чанков.
 * Возвращает имя (32 hex + '\0') и фактический размер/чанк. */
int fv_blob_write_ex(const uint8_t mk[FV_KEY_LEN], const uint8_t uuid[16],
                     const char *blobs_dir, fv_blob_src *src,
                     uint64_t expected_size,
                     char blob_name[FV_BLOB_NAME_LEN + 1],
                     uint32_t *chunk_size_out);

/* То же для файла хоста, открытого на "rb" */
int fv_blob_write(const uint8_t mk[FV_KEY_LEN], const uint8_t uuid[16],
                  const char *blobs_dir, FILE *src,
                  uint64_t expected_size,
                  char blob_name[FV_BLOB_NAME_LEN + 1],
                  uint32_t *chunk_size_out);

typedef struct fv_blob_reader fv_blob_reader;

/* Открыть блоб на чтение. Ожидаемые размер и чанк берутся из индекса
 * (аутентифицированы GCM), расхождение с файлом — порча формата. */
int fv_blob_reader_open(fv_blob_reader **out,
                        const uint8_t mk[FV_KEY_LEN], const uint8_t uuid[16],
                        const char *blobs_dir, const char *blob_name,
                        uint64_t expected_size, uint32_t expected_chunk);

/* Следующий кусок открытого текста. buf должен вмещать expected_chunk байт.
 * *got == 0 — конец файла. */
int fv_blob_reader_read(fv_blob_reader *r, uint8_t *buf, size_t *got);

int fv_blob_reader_close(fv_blob_reader *r);

#endif
