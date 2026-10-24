/* blob.c */
#include "blob.h"
#include "platform.h"
#include "util.h"

#include <stdlib.h>
#include <string.h>

#define BLOB_MAGIC   0x4C425646u    /* "FVBL" little-endian */
#define BLOB_VERSION 1u

static int blob_path(const char *dir, const char *name, char *out, size_t n)
{
    if (!dir || !name || strlen(name) != FV_BLOB_NAME_LEN) return FV_ERR_ARG;
    int w = snprintf(out, n, "%s%c%s.bin", dir, FV_PATH_SEP, name);
    if (w < 0 || (size_t)w >= n) return FV_ERR_RANGE;
    return FV_OK;
}

/* AAD чанка: uuid контейнера | имя блоба (32 hex) | номер чанка */
static void chunk_aad(const uint8_t uuid[16], const char *blob_name,
                      uint64_t idx, uint8_t aad[56])
{
    memcpy(aad, uuid, 16);
    memcpy(aad + 16, blob_name, FV_BLOB_NAME_LEN);
    fv_put_u64(aad + 16 + FV_BLOB_NAME_LEN, idx);
}

static void gen_blob_name(char out[FV_BLOB_NAME_LEN + 1])
{
    uint8_t raw[16];
    fv_random(raw, sizeof raw);
    fv_hex(raw, sizeof raw, out);
}

/* Читать want байт из источника; короткое чтение = ошибка (кроме честного EOF
 * ниже want — это ловится вызывающим по total < expected_size). */
static int src_read(fv_blob_src *s, uint8_t *buf, size_t want, size_t *got)
{
    if (s->is_mem) {
        size_t left = s->mem_len - s->mem_pos;
        size_t take = (left < want) ? left : want;
        if (take) memcpy(buf, s->mem + s->mem_pos, take);
        s->mem_pos += take;
        *got = take;
        return FV_OK;
    }
    size_t r = fread(buf, 1, want, s->f);
    *got = r;
    return (r == want || !ferror(s->f)) ? FV_OK : FV_ERR_IO;
}

int fv_blob_write_ex(const uint8_t mk[FV_KEY_LEN], const uint8_t uuid[16],
                     const char *blobs_dir, fv_blob_src *src,
                     uint64_t expected_size,
                     char blob_name[FV_BLOB_NAME_LEN + 1],
                     uint32_t *chunk_size_out)
{
    if (!mk || !uuid || !blobs_dir || !src || !blob_name || !chunk_size_out)
        return FV_ERR_ARG;
    if (!src->is_mem && !src->f) return FV_ERR_ARG;

    uint32_t chunk = FV_CHUNK_DEFAULT;
    /* число чанков должно влезать в u32 */
    if (expected_size > (uint64_t)chunk * 0xFFFFFFFFull) return FV_ERR_RANGE;
    uint32_t count = (uint32_t)((expected_size + chunk - 1) / chunk);

    /* случайное имя, не занятое ни на диске, ни в индексе (индекс проверит vault) */
    char path[FV_PATH_MAX];
    for (int attempt = 0; ; attempt++) {
        gen_blob_name(blob_name);
        if (blob_path(blobs_dir, blob_name, path, sizeof path) != FV_OK)
            return FV_ERR_ARG;
        if (plat_stat_kind(path) == 0 || attempt >= 8) break;
    }

    FILE *f = plat_fopen(path, "wb");
    if (!f) return FV_ERR_IO;

    int rc = FV_OK;
    uint8_t hdr[16];
    fv_put_u32(hdr,      BLOB_MAGIC);
    fv_put_u32(hdr + 4,  BLOB_VERSION);
    fv_put_u32(hdr + 8,  chunk);
    fv_put_u32(hdr + 12, count);
    if (fwrite(hdr, 1, sizeof hdr, f) != sizeof hdr) rc = FV_ERR_IO;

    uint8_t *plain = (uint8_t *)malloc(chunk);
    uint8_t *seal  = (uint8_t *)malloc((size_t)chunk + FV_SEAL_OVERHEAD);
    if (!plain || !seal) rc = (rc == FV_OK) ? FV_ERR_NOMEM : rc;

    uint8_t aad[56];
    uint64_t total = 0;
    uint64_t idx = 0;
    while (rc == FV_OK && total < expected_size) {
        size_t want = (expected_size - total > chunk)
                          ? (size_t)chunk
                          : (size_t)(expected_size - total);
        size_t got = 0;
        while (got < want) {
            size_t r = 0;
            rc = src_read(src, plain + got, want - got, &r);
            if (rc != FV_OK || r == 0) { rc = (rc == FV_OK) ? FV_ERR_IO : rc; break; }
            got += r;
        }
        if (rc != FV_OK) break;

        chunk_aad(uuid, blob_name, idx, aad);
        rc = fv_seal(mk, aad, sizeof aad, plain, want, seal);
        if (rc != FV_OK) break;
        if (fwrite(seal, 1, want + FV_SEAL_OVERHEAD, f) != want + FV_SEAL_OVERHEAD) {
            rc = FV_ERR_IO;
            break;
        }
        total += want;
        idx++;
    }

    free(plain);
    free(seal);

    if (rc == FV_OK) {
        if (fflush(f) != 0) rc = FV_ERR_IO;
        else if (plat_fsync(f) != FV_OK) rc = FV_ERR_IO;
    }
    fclose(f);

    if (rc != FV_OK) {
        plat_remove(path);               /* не оставляем обрезок */
        return rc;
    }
    *chunk_size_out = chunk;
    return FV_OK;
}

int fv_blob_write(const uint8_t mk[FV_KEY_LEN], const uint8_t uuid[16],
                  const char *blobs_dir, FILE *src,
                  uint64_t expected_size,
                  char blob_name[FV_BLOB_NAME_LEN + 1],
                  uint32_t *chunk_size_out)
{
    fv_blob_src s;
    memset(&s, 0, sizeof s);
    s.is_mem = 0;
    s.f = src;
    return fv_blob_write_ex(mk, uuid, blobs_dir, &s, expected_size,
                            blob_name, chunk_size_out);
}

/* ---------- чтение ---------- */

struct fv_blob_reader {
    FILE    *f;
    uint8_t  mk[FV_KEY_LEN];
    uint8_t  uuid[16];
    char     name[FV_BLOB_NAME_LEN + 1];
    uint32_t chunk_size;
    uint32_t next;
    uint64_t plain_total;
    uint64_t plain_done;
    uint8_t *seal;
};

int fv_blob_reader_open(fv_blob_reader **out,
                        const uint8_t mk[FV_KEY_LEN], const uint8_t uuid[16],
                        const char *blobs_dir, const char *blob_name,
                        uint64_t expected_size, uint32_t expected_chunk)
{
    if (!out || !mk || !uuid || !blobs_dir ||
        !blob_name || strlen(blob_name) != FV_BLOB_NAME_LEN)
        return FV_ERR_ARG;
    *out = NULL;

    char path[FV_PATH_MAX];
    int rc = blob_path(blobs_dir, blob_name, path, sizeof path);
    if (rc != FV_OK) return rc;

    fv_blob_reader *r = (fv_blob_reader *)calloc(1, sizeof *r);
    if (!r) return FV_ERR_NOMEM;

    r->f = plat_fopen(path, "rb");
    if (!r->f) {
        fv_blob_reader_close(r);
        return FV_ERR_NOTFOUND;
    }

    uint8_t hdr[16];
    if (fread(hdr, 1, sizeof hdr, r->f) != sizeof hdr) {
        fv_blob_reader_close(r);
        return FV_ERR_FORMAT;
    }
    uint32_t magic = fv_get_u32(hdr);
    uint32_t ver   = fv_get_u32(hdr + 4);
    uint32_t chunk = fv_get_u32(hdr + 8);
    uint32_t count = fv_get_u32(hdr + 12);
    if (magic != BLOB_MAGIC || ver != BLOB_VERSION || chunk == 0 ||
        chunk != expected_chunk) {
        fv_blob_reader_close(r);
        return FV_ERR_FORMAT;
    }
    uint32_t want_count = (uint32_t)((expected_size + chunk - 1) / chunk);
    if (count != want_count) {
        fv_blob_reader_close(r);
        return FV_ERR_FORMAT;
    }

    /* сверка размера файла с ожидаемым по индексу */
    uint64_t fsz = 0;
    if (plat_file_size(path, &fsz) != FV_OK) {
        fv_blob_reader_close(r);
        return FV_ERR_IO;
    }
    uint64_t expect_fsz = FV_BLOB_HEADER_LEN;
    if (count) {
        uint64_t last = expected_size - (uint64_t)(count - 1) * chunk;
        expect_fsz += (uint64_t)(count - 1) * (chunk + FV_SEAL_OVERHEAD)
                    + last + FV_SEAL_OVERHEAD;
    }
    if (fsz != expect_fsz) {
        fv_blob_reader_close(r);
        return FV_ERR_FORMAT;
    }

    r->seal = (uint8_t *)malloc((size_t)chunk + FV_SEAL_OVERHEAD);
    if (!r->seal) {
        fv_blob_reader_close(r);
        return FV_ERR_NOMEM;
    }

    memcpy(r->mk, mk, FV_KEY_LEN);
    memcpy(r->uuid, uuid, 16);
    strcpy(r->name, blob_name);
    r->chunk_size  = chunk;
    r->next        = 0;
    r->plain_total = expected_size;
    r->plain_done  = 0;

    *out = r;
    return FV_OK;
}

int fv_blob_reader_read(fv_blob_reader *r, uint8_t *buf, size_t *got)
{
    if (!r || !buf || !got) return FV_ERR_ARG;
    *got = 0;
    if (r->plain_done == r->plain_total) return FV_OK;   /* EOF */

    uint64_t left = r->plain_total - r->plain_done;
    size_t len = (left > r->chunk_size) ? (size_t)r->chunk_size : (size_t)left;

    uint8_t aad[56];
    chunk_aad(r->uuid, r->name, r->next, aad);
    size_t sealed_len = len + FV_SEAL_OVERHEAD;
    if (fread(r->seal, 1, sealed_len, r->f) != sealed_len) return FV_ERR_IO;

    int rc = fv_open(r->mk, aad, sizeof aad, r->seal, sealed_len, buf);
    if (rc != FV_OK) return rc;

    r->plain_done += len;
    r->next++;
    *got = len;
    return FV_OK;
}

int fv_blob_reader_close(fv_blob_reader *r)
{
    if (!r) return FV_OK;
    if (r->f) fclose(r->f);
    fv_wipe(r->mk, FV_KEY_LEN);
    free(r->seal);
    free(r);
    return FV_OK;
}
