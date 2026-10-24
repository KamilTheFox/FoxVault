/* vault.c */
#include "vault.h"
#include "blob.h"
#include "crypto.h"
#include "platform.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* gcc не может доказать, что буферы FV_PATH_MAX хватает — подавляем шум */
#if defined(__GNUC__)
#pragma GCC diagnostic ignored "-Wformat-truncation"
#endif

/* ---------- формат на диске ---------- */

#define HDR_MAGIC   "FOXVAULT"        /* 8 байт */
#define FMT_VERSION 1u
#define KDF_ALGO_PBKDF2_SHA256 1u

/* открытая часть заголовка, 72 байта */
#define HDR_PLAIN_LEN 72u
/* целиком: 72 + nonce[12] + mk[32] + tag[16] */
#define HDR_LEN 132u

#define IX_MAGIC        0x58495646u   /* "FVIX" little-endian */
#define IX_PREFIX_LEN   16u

static const char *HDR_SLOT[2] = { "header.0", "header.1" };

struct fv_vault {
    char     dir[FV_PATH_MAX];
    char     blobs[FV_PATH_MAX];
    uint8_t  mk[FV_KEY_LEN];      /* мастер-ключ: под защитой от свопа */
    uint8_t  uuid[16];
    /* копия открытой части заголовка — для повторной разблокировки */
    uint8_t  salt[FV_SALT_LEN];
    uint32_t iters;
    uint32_t hdr_gen;
    uint8_t  sealed_mk[FV_KEY_LEN + FV_SEAL_OVERHEAD];
    fv_index ix;
    int      hdr_slot;               /* какой из header.0/1 актуален */
    int      ix_slot;
    uint32_t ix_gen;
    uint64_t activity;
};

/* ---------- мелочи ---------- */

static void slot_path(const char *dir, const char *name, char *out, size_t n)
{
    snprintf(out, n, "%s%c%s", dir, FV_PATH_SEP, name);
}

/* Записать слот: временный файл -> fsync -> атомарная замена -> fsync каталога */
static int write_file_atomic(const char *dir, const char *name,
                             const uint8_t *data, size_t len)
{
    char dst[FV_PATH_MAX], tmp[FV_PATH_MAX];
    slot_path(dir, name, dst, sizeof dst);
    snprintf(tmp, sizeof tmp, "%s.tmp", dst);

    FILE *f = plat_fopen(tmp, "wb");
    if (!f) return FV_ERR_IO;
    int rc = FV_OK;
    if (fwrite(data, 1, len, f) != len || fflush(f) != 0) rc = FV_ERR_IO;
    if (rc == FV_OK) rc = plat_fsync(f);
    fclose(f);
    if (rc != FV_OK) {
        plat_remove(tmp);
        return rc;
    }
    rc = plat_atomic_replace(tmp, dst);
    plat_fsync_dir(dir);                    /* как получится — лучшее усилие */
    return rc;
}

/* создать каталог вместе с родителями — теперь в platform.c */
#define mkdir_p plat_mkdir_p

/* ---------- заголовок ---------- */

static void hdr_prefix(uint8_t p[HDR_PLAIN_LEN], uint32_t gen,
                       const uint8_t uuid[16], const uint8_t salt[FV_SALT_LEN],
                       uint32_t iters)
{
    memcpy(p, HDR_MAGIC, 8);
    fv_put_u32(p + 8,  FMT_VERSION);
    fv_put_u32(p + 12, gen);
    fv_put_u32(p + 16, KDF_ALGO_PBKDF2_SHA256);
    fv_put_u32(p + 20, iters);
    memcpy(p + 24, salt, FV_SALT_LEN);
    memcpy(p + 56, uuid, 16);
}

static int hdr_parse(const uint8_t *d, size_t len, uint32_t *gen,
                     uint8_t uuid[16], uint8_t salt[FV_SALT_LEN],
                     uint32_t *iters, uint8_t sealed[FV_KEY_LEN + FV_SEAL_OVERHEAD])
{
    if (len != HDR_LEN || memcmp(d, HDR_MAGIC, 8) != 0) return FV_ERR_FORMAT;
    if (fv_get_u32(d + 8) != FMT_VERSION) return FV_ERR_FORMAT;
    if (fv_get_u32(d + 16) != KDF_ALGO_PBKDF2_SHA256) return FV_ERR_FORMAT;
    uint32_t g = fv_get_u32(d + 12);
    uint32_t it = fv_get_u32(d + 20);
    if (it < FV_KDF_MIN_ITERS || it > FV_KDF_MAX_ITERS) return FV_ERR_FORMAT;
    *gen = g;
    *iters = it;
    memcpy(salt, d + 24, FV_SALT_LEN);
    memcpy(uuid, d + 56, 16);
    memcpy(sealed, d + HDR_PLAIN_LEN, FV_KEY_LEN + FV_SEAL_OVERHEAD);
    return FV_OK;
}

/* ---------- индекс: сериализация в байты слота ---------- */

static int ix_slot_bytes(const fv_vault *v, uint32_t gen, fv_buf *file)
{
    fv_buf raw;
    int rc = fv_index_serialize(&v->ix, &raw);
    if (rc != FV_OK) return rc;
    if (raw.len + FV_SEAL_OVERHEAD > 0xFFFFFFFFull) {
        fv_buf_free(&raw);
        return FV_ERR_RANGE;
    }

    uint8_t prefix[IX_PREFIX_LEN];
    fv_put_u32(prefix,      IX_MAGIC);
    fv_put_u32(prefix + 4,  1);
    fv_put_u32(prefix + 8,  gen);
    fv_put_u32(prefix + 12, (uint32_t)(raw.len + FV_SEAL_OVERHEAD));

    uint8_t aad[IX_PREFIX_LEN + 16];
    memcpy(aad, prefix, IX_PREFIX_LEN);
    memcpy(aad + IX_PREFIX_LEN, v->uuid, 16);

    uint8_t *seal = (uint8_t *)malloc(raw.len + FV_SEAL_OVERHEAD);
    if (!seal) {
        fv_buf_free(&raw);
        return FV_ERR_NOMEM;
    }
    rc = fv_seal(v->mk, aad, sizeof aad, raw.data, raw.len, seal);
    if (rc == FV_OK) {
        rc = fv_buf_add(file, prefix, IX_PREFIX_LEN);
        if (rc == FV_OK)
            rc = fv_buf_add(file, seal, raw.len + FV_SEAL_OVERHEAD);
    }
    free(seal);
    fv_buf_free(&raw);
    return rc;
}

static int ix_commit(fv_vault *v)
{
    uint32_t ngen = v->ix_gen + 1;
    fv_buf file;
    fv_buf_init(&file);
    int rc = ix_slot_bytes(v, ngen, &file);
    if (rc != FV_OK) {
        fv_buf_free(&file);
        return rc;
    }
    char name[16];
    int ns = 1 - v->ix_slot;
    snprintf(name, sizeof name, "index.%d", ns);
    rc = write_file_atomic(v->dir, name, file.data, file.len);
    fv_buf_free(&file);
    if (rc != FV_OK) return rc;
    v->ix_slot = ns;
    v->ix_gen = ngen;
    return FV_OK;
}

/* ---------- сборка мусора: блобы без ссылки в индексе ---------- */

static int blob_name_ok(const char *n)
{
    size_t l = strlen(n);
    if (l != FV_BLOB_NAME_LEN + 4) return 0;
    if (strcmp(n + FV_BLOB_NAME_LEN, ".bin") != 0) return 0;
    for (size_t i = 0; i < FV_BLOB_NAME_LEN; i++) {
        char c = n[i];
        int hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        if (!hex) return 0;
    }
    return 1;
}

typedef struct {
    const fv_vault *v;
    const fv_index *ix;
} gc_ctx;

static void gc_cb(const char *name, int is_dir, uint64_t size, void *ctx)
{
    (void)size;
    gc_ctx *g = (gc_ctx *)ctx;
    if (is_dir || !blob_name_ok(name)) return;
    for (size_t i = 0; i < g->ix->count; i++) {
        const fv_node *n = &g->ix->nodes[i];
        if (n->type == FV_NODE_FILE && !memcmp(n->blob, name, FV_BLOB_NAME_LEN))
            return;                          /* на этот блоб есть ссылка */
    }
    char path[FV_PATH_MAX];
    if (snprintf(path, sizeof path, "%s%c%s", g->v->blobs, FV_PATH_SEP, name)
            < (int)sizeof path)
        plat_remove(path);                   /* осиротевший блоб */
}

static void gc_orphans(fv_vault *v)
{
    gc_ctx g = { v, &v->ix };
    plat_list_dir(v->blobs, gc_cb, &g);
}

/* ---------- создание и открытие ---------- */

static int make_abs(char *dir, size_t n)
{
    size_t l = strlen(dir);
    while (l > 1 && (dir[l - 1] == '/' || dir[l - 1] == '\\')) dir[--l] = '\0';
#ifdef _WIN32
    int abs = (dir[0] == '/' || dir[0] == '\\' ||
               ((dir[0] >= 'A' && dir[0] <= 'Z') ||
                (dir[0] >= 'a' && dir[0] <= 'z')) && dir[1] == ':');
#else
    (void)n;
    int abs = (dir[0] == '/');
#endif
    if (abs) return FV_OK;
    char cwd[FV_PATH_MAX];
    int rc = plat_getcwd(cwd, sizeof cwd);
    if (rc != FV_OK) return rc;
    char joined[FV_PATH_MAX];
    fv_path_join(joined, sizeof joined, cwd, dir);
    if (strlen(joined) >= n) return FV_ERR_RANGE;
    strcpy(dir, joined);
    return FV_OK;
}

int fv_vault_create_ex(const char *dir_in, const char *pass,
                       fv_kdf_progress cb, void *cb_ctx)
{
    if (!dir_in || !pass || !*pass) return FV_ERR_ARG;

    char dir[FV_PATH_MAX];
    int rc = plat_expand_path(dir_in, dir, sizeof dir);
    if (rc != FV_OK) return rc;
    rc = make_abs(dir, sizeof dir);
    if (rc != FV_OK) return rc;

    if (plat_stat_kind(dir) == 2) {
        char p[FV_PATH_MAX];
        slot_path(dir, HDR_SLOT[0], p, sizeof p);
        int has0 = plat_stat_kind(p) == 1;
        slot_path(dir, HDR_SLOT[1], p, sizeof p);
        int has1 = plat_stat_kind(p) == 1;
        if (has0 || has1) return FV_ERR_EXISTS;
    }

    rc = mkdir_p(dir);
    if (rc != FV_OK) return rc;
    char blobs[FV_PATH_MAX];
    fv_path_join(blobs, sizeof blobs, dir, "blobs");
    rc = mkdir_p(blobs);
    if (rc != FV_OK) return rc;

    fv_vault v;
    memset(&v, 0, sizeof v);
    snprintf(v.dir, sizeof v.dir, "%s", dir);
    snprintf(v.blobs, sizeof v.blobs, "%s", blobs);
    rc = fv_index_make_root(&v.ix);
    if (rc != FV_OK) return rc;

    uint8_t mk[FV_KEY_LEN];
    rc = fv_random(v.uuid, sizeof v.uuid);
    if (rc == FV_OK) rc = fv_random(v.salt, FV_SALT_LEN);
    if (rc == FV_OK) rc = fv_random(mk, FV_KEY_LEN);
    if (rc == FV_OK) memcpy(v.mk, mk, FV_KEY_LEN);   /* индекс шифруется им же */
    v.iters = FV_KDF_DEFAULT_ITERS;
    if (rc != FV_OK) {
        fv_wipe(mk, FV_KEY_LEN);
        fv_index_free(&v.ix);
        return rc;
    }

    /* индекс поколения 0 — в оба слота */
    fv_buf file;
    fv_buf_init(&file);
    rc = ix_slot_bytes(&v, 0, &file);
    if (rc == FV_OK) rc = write_file_atomic(v.dir, "index.0", file.data, file.len);
    if (rc == FV_OK) rc = write_file_atomic(v.dir, "index.1", file.data, file.len);
    fv_buf_free(&file);
    if (rc != FV_OK) goto done;

    /* заголовок поколения 0 — в оба слота */
    {
        uint8_t *kek = (uint8_t *)fv_secure_alloc(FV_KEY_LEN);
        uint32_t every = v.iters / 100u + 1u;        /* ~100 сигналов прогресса */
        rc = fv_kdf_ex(pass, strlen(pass), v.salt, FV_SALT_LEN, v.iters, kek,
                       cb, cb_ctx, every);
        if (rc == FV_OK) {
            uint8_t pfx[HDR_PLAIN_LEN];
            uint8_t sealed[FV_KEY_LEN + FV_SEAL_OVERHEAD];
            hdr_prefix(pfx, 0, v.uuid, v.salt, v.iters);
            rc = fv_seal(kek, pfx, sizeof pfx, mk, FV_KEY_LEN, sealed);
            if (rc == FV_OK) {
                uint8_t hdr[HDR_LEN];
                memcpy(hdr, pfx, HDR_PLAIN_LEN);
                memcpy(hdr + HDR_PLAIN_LEN, sealed, sizeof sealed);
                rc = write_file_atomic(v.dir, HDR_SLOT[0], hdr, HDR_LEN);
                if (rc == FV_OK)
                    rc = write_file_atomic(v.dir, HDR_SLOT[1], hdr, HDR_LEN);
            }
        }
        fv_secure_free(kek, FV_KEY_LEN);
        if (rc == FV_OK) plat_fsync_dir(v.dir);
    }

done:
    fv_wipe(mk, FV_KEY_LEN);
    fv_wipe(v.mk, FV_KEY_LEN);
    fv_index_free(&v.ix);
    return rc;
}

int fv_vault_create(const char *dir_in, const char *pass)
{
    return fv_vault_create_ex(dir_in, pass, NULL, NULL);
}

/* чтение слота целиком; буфер malloc, размер *len_out */
static int read_whole(const char *path, uint8_t **data, size_t *len_out)
{
    uint64_t sz64 = 0;
    int rc = plat_file_size(path, &sz64);
    if (rc != FV_OK) return rc;
    if (sz64 > (64ull << 20)) return FV_ERR_FORMAT;   /* слоты таких размеров не бывают */
    size_t sz = (size_t)sz64;
    uint8_t *buf = (uint8_t *)malloc(sz ? sz : 1);
    if (!buf) return FV_ERR_NOMEM;
    FILE *f = plat_fopen(path, "rb");
    if (!f) {
        free(buf);
        return FV_ERR_IO;
    }
    size_t got = fread(buf, 1, sz, f);
    fclose(f);
    if (got != sz) {
        free(buf);
        return FV_ERR_IO;
    }
    *data = buf;
    *len_out = sz;
    return FV_OK;
}

static int read_index(fv_vault *v)
{
    int best_slot = -1;
    uint32_t best_gen = 0;
    uint8_t *loaded = NULL;                          /* байты расшифрованного индекса */
    size_t loaded_len = 0;

    for (int s = 0; s < 2; s++) {
        char path[FV_PATH_MAX];
        slot_path(v->dir, s == 0 ? "index.0" : "index.1", path, sizeof path);
        uint8_t *data = NULL;
        size_t len = 0;
        if (read_whole(path, &data, &len) != FV_OK) continue;
        if (len < IX_PREFIX_LEN + FV_SEAL_OVERHEAD) {
            free(data);
            continue;
        }
        uint32_t magic = fv_get_u32(data);
        uint32_t ver   = fv_get_u32(data + 4);
        uint32_t gen   = fv_get_u32(data + 8);
        uint32_t plen  = fv_get_u32(data + 12);
        if (magic != IX_MAGIC || ver != 1 || plen != (uint32_t)(len - IX_PREFIX_LEN)) {
            free(data);
            continue;
        }
        uint8_t aad[IX_PREFIX_LEN + 16];
        memcpy(aad, data, IX_PREFIX_LEN);
        memcpy(aad + IX_PREFIX_LEN, v->uuid, 16);

        size_t raw_len = plen - FV_SEAL_OVERHEAD;
        uint8_t *plain = (uint8_t *)malloc(raw_len ? raw_len : 1);
        if (!plain) {
            free(data);
            return FV_ERR_NOMEM;
        }
        int rc = fv_open(v->mk, aad, sizeof aad,
                         data + IX_PREFIX_LEN, plen, plain);
        free(data);
        if (rc != FV_OK) {
            fv_wipe(plain, raw_len);
            free(plain);
            continue;                                /* этот слот повреждён */
        }

        if (best_slot < 0 || gen > best_gen) {
            free(loaded);
            loaded = plain;
            loaded_len = raw_len;
            best_slot = s;
            best_gen = gen;
        } else {
            fv_wipe(plain, raw_len);
            free(plain);
        }
    }

    if (best_slot < 0) return FV_ERR_FORMAT;

    int rc = fv_index_deserialize(&v->ix, loaded, loaded_len);
    fv_wipe(loaded, loaded_len);
    free(loaded);
    if (rc != FV_OK) return rc;

    v->ix_slot = best_slot;
    v->ix_gen = best_gen;
    return FV_OK;
}

int fv_vault_open(fv_vault **out, const char *dir_in, const char *pass)
{
    *out = NULL;
    if (!out || !dir_in || !pass) return FV_ERR_ARG;

    char dir[FV_PATH_MAX];
    int rc = plat_expand_path(dir_in, dir, sizeof dir);
    if (rc != FV_OK) return rc;
    rc = make_abs(dir, sizeof dir);
    if (rc != FV_OK) return rc;
    if (plat_stat_kind(dir) != 2) return FV_ERR_NOTFOUND;

    /* --- читаем оба слота заголовка --- */
    struct hslot {
        int      ok;
        uint32_t gen;
        uint32_t iters;
        uint8_t  salt[FV_SALT_LEN];
        uint8_t  uuid[16];
        uint8_t  sealed[FV_KEY_LEN + FV_SEAL_OVERHEAD];
    } hs[2];
    memset(hs, 0, sizeof hs);

    int any = 0;
    for (int s = 0; s < 2; s++) {
        char path[FV_PATH_MAX];
        slot_path(dir, HDR_SLOT[s], path, sizeof path);
        uint8_t *data = NULL;
        size_t len = 0;
        if (read_whole(path, &data, &len) != FV_OK) continue;
        uint32_t gen, iters;
        rc = hdr_parse(data, len, &gen, hs[s].uuid, hs[s].salt, &iters, hs[s].sealed);
        free(data);
        if (rc != FV_OK) continue;
        hs[s].ok = 1;
        hs[s].gen = gen;
        hs[s].iters = iters;
        any = 1;
    }
    if (!any) return FV_ERR_FORMAT;

    /* --- перебираем слоты от старшего поколения ---
     * соль может отличаться между слотами (смена пароля упала на середине),
     * поэтому кэшируем выведенные KEK: максимум две разные соли. */
    int order[2] = { 0, 1 };
    if (hs[1].ok && (!hs[0].ok || hs[1].gen > hs[0].gen)) {
        order[0] = 1;
        order[1] = 0;
    }

    uint8_t *kek = (uint8_t *)fv_secure_alloc(2 * FV_KEY_LEN);
    uint8_t kek_salt[2][FV_SALT_LEN];
    int kek_used = 0;

    int found = -1;
    uint8_t mk_tmp[FV_KEY_LEN];
    for (int k = 0; k < 2 && found < 0; k++) {
        int s = order[k];
        if (!hs[s].ok) continue;
        int c = -1;
        for (int j = 0; j < kek_used; j++)
            if (!memcmp(kek_salt[j], hs[s].salt, FV_SALT_LEN)) { c = j; break; }
        if (c < 0) {
            if (kek_used >= 2) continue;             /* третья соль невозможна */
            c = kek_used++;
            rc = fv_kdf(pass, strlen(pass), hs[s].salt, FV_SALT_LEN,
                        hs[s].iters, kek + (size_t)c * FV_KEY_LEN);
            if (rc != FV_OK) {
                fv_secure_free(kek, 2 * FV_KEY_LEN);
                fv_wipe(mk_tmp, FV_KEY_LEN);
                return rc;
            }
            memcpy(kek_salt[c], hs[s].salt, FV_SALT_LEN);
        }
        uint8_t pfx[HDR_PLAIN_LEN];
        hdr_prefix(pfx, hs[s].gen, hs[s].uuid, hs[s].salt, hs[s].iters);
        rc = fv_open(kek + (size_t)c * FV_KEY_LEN, pfx, sizeof pfx,
                     hs[s].sealed, sizeof hs[s].sealed, mk_tmp);
        if (rc == FV_OK) found = s;
    }
    fv_secure_free(kek, 2 * FV_KEY_LEN);
    if (found < 0) {
        fv_wipe(mk_tmp, FV_KEY_LEN);
        return FV_ERR_AUTH;
    }

    /* --- контейнер открыт: собираем структуру --- */
    fv_vault *v = (fv_vault *)calloc(1, sizeof *v);
    if (!v) {
        fv_wipe(mk_tmp, FV_KEY_LEN);
        return FV_ERR_NOMEM;
    }
    snprintf(v->dir, sizeof v->dir, "%s", dir);
    fv_path_join(v->blobs, sizeof v->blobs, dir, "blobs");
    memcpy(v->mk, mk_tmp, FV_KEY_LEN);
    fv_wipe(mk_tmp, FV_KEY_LEN);
    memcpy(v->uuid, hs[found].uuid, 16);
    memcpy(v->salt, hs[found].salt, FV_SALT_LEN);
    v->iters = hs[found].iters;
    v->hdr_gen = hs[found].gen;
    v->hdr_slot = found;
    memcpy(v->sealed_mk, hs[found].sealed, sizeof v->sealed_mk);
    plat_lock_mem(v->mk, FV_KEY_LEN);

    rc = read_index(v);
    if (rc != FV_OK) {
        fv_vault_free(v);
        return rc;
    }

    v->activity = (uint64_t)time(NULL);
    gc_orphans(v);                                   /* лучшее усилие */

    *out = v;
    return FV_OK;
}

void fv_vault_free(fv_vault *v)
{
    if (!v) return;
    fv_wipe(v->mk, FV_KEY_LEN);
    plat_unlock_mem(v->mk, FV_KEY_LEN);
    fv_index_free(&v->ix);
    free(v);
}

/* ---------- блокировка ---------- */

void fv_vault_lock(fv_vault *v)
{
    if (v) fv_wipe(v->mk, FV_KEY_LEN);
}

int fv_vault_is_locked(const fv_vault *v)
{
    if (!v) return 1;
    uint8_t zero[FV_KEY_LEN] = { 0 };
    return fv_ct_memcmp(v->mk, zero, FV_KEY_LEN) == 0;
}

int fv_vault_unlock(fv_vault *v, const char *pass)
{
    if (!v || !pass || !*pass) return FV_ERR_ARG;
    uint8_t pfx[HDR_PLAIN_LEN];
    hdr_prefix(pfx, v->hdr_gen, v->uuid, v->salt, v->iters);
    uint8_t *kek = (uint8_t *)fv_secure_alloc(FV_KEY_LEN);
    int rc = fv_kdf(pass, strlen(pass), v->salt, FV_SALT_LEN, v->iters, kek);
    if (rc == FV_OK)
        rc = fv_open(kek, pfx, sizeof pfx, v->sealed_mk,
                     sizeof v->sealed_mk, v->mk);
    fv_secure_free(kek, FV_KEY_LEN);
    if (rc == FV_OK) v->activity = (uint64_t)time(NULL);
    return rc;
}

void fv_vault_touch(fv_vault *v)
{
    if (v) v->activity = (uint64_t)time(NULL);
}

/* ---------- доступы для info ---------- */

const char *fv_vault_dir(const fv_vault *v)
{
    return v ? v->dir : "";
}

int fv_vault_uuid_hex(const fv_vault *v, char out[33])
{
    if (!v) return FV_ERR_ARG;
    fv_hex(v->uuid, 16, out);
    return FV_OK;
}

uint32_t fv_vault_kdf_iters(const fv_vault *v) { return v ? v->iters : 0; }
uint32_t fv_vault_hdr_gen(const fv_vault *v)   { return v ? v->hdr_gen : 0; }
uint32_t fv_vault_ix_gen(const fv_vault *v)    { return v ? v->ix_gen : 0; }

uint64_t fv_vault_idle_seconds(const fv_vault *v)
{
    if (!v) return 0;
    uint64_t now = (uint64_t)time(NULL);
    return now > v->activity ? now - v->activity : 0;
}

/* ---------- смена пароля ---------- */

int fv_vault_change_password(fv_vault *v, const char *newpass)
{
    if (!v || !newpass || !*newpass) return FV_ERR_ARG;

    uint8_t nsalt[FV_SALT_LEN];
    int rc = fv_random(nsalt, FV_SALT_LEN);
    if (rc != FV_OK) return rc;

    uint8_t *kek = (uint8_t *)fv_secure_alloc(FV_KEY_LEN);
    rc = fv_kdf(newpass, strlen(newpass), nsalt, FV_SALT_LEN, v->iters, kek);
    uint8_t sealed[FV_KEY_LEN + FV_SEAL_OVERHEAD];
    uint8_t hdr[HDR_LEN];
    if (rc == FV_OK) {
        uint32_t ngen = v->hdr_gen + 1;
        uint8_t pfx[HDR_PLAIN_LEN];
        hdr_prefix(pfx, ngen, v->uuid, nsalt, v->iters);
        rc = fv_seal(kek, pfx, sizeof pfx, v->mk, FV_KEY_LEN, sealed);
        if (rc == FV_OK) {
            memcpy(hdr, pfx, HDR_PLAIN_LEN);
            memcpy(hdr + HDR_PLAIN_LEN, sealed, sizeof sealed);
        }
    }
    fv_secure_free(kek, FV_KEY_LEN);
    if (rc != FV_OK) {
        fv_wipe(nsalt, FV_SALT_LEN);
        fv_wipe(hdr, HDR_LEN);
        return rc;
    }

    /* сначала — свободный слот с новым поколением,
     * затем тот же заголовок копируется во второй слот (резерв) */
    int ns = 1 - v->hdr_slot;
    rc = write_file_atomic(v->dir, HDR_SLOT[ns], hdr, HDR_LEN);
    if (rc != FV_OK) {
        fv_wipe(nsalt, FV_SALT_LEN);
        fv_wipe(hdr, HDR_LEN);
        return rc;
    }
    v->hdr_slot = ns;
    v->hdr_gen++;
    memcpy(v->salt, nsalt, FV_SALT_LEN);
    memcpy(v->sealed_mk, sealed, sizeof sealed);

    write_file_atomic(v->dir, HDR_SLOT[1 - ns], hdr, HDR_LEN);  /* резервный слот */
    plat_fsync_dir(v->dir);
    fv_wipe(nsalt, FV_SALT_LEN);
    fv_wipe(hdr, HDR_LEN);
    return FV_OK;
}

/* ---------- операции ---------- */

int fv_vault_mkdir(fv_vault *v, const char *path_in)
{
    if (!v) return FV_ERR_ARG;
    char dest[FV_PATH_MAX];
    int rc = fv_index_norm_path(path_in, dest, sizeof dest);
    if (rc != FV_OK) return rc;

    fv_loc loc;
    rc = fv_index_resolve_ex(&v->ix, dest, &loc);
    if (rc == FV_OK) return FV_ERR_EXISTS;
    if (rc != FV_ERR_NOTFOUND) return rc;
    if (!loc.parent) return FV_ERR_NOTFOUND;         /* нет родителя */

    uint64_t now = (uint64_t)time(NULL);
    uint64_t id = fv_index_add_node(&v->ix, loc.parent, loc.name, FV_NODE_DIR, now);
    if (!id) return FV_ERR_NOMEM;
    rc = ix_commit(v);
    if (rc != FV_OK) {
        fv_index_remove_one(&v->ix, id);             /* откат */
        return rc;
    }
    return FV_OK;
}

int fv_vault_rm(fv_vault *v, const char *path_in, int recursive)
{
    if (!v) return FV_ERR_ARG;
    char dest[FV_PATH_MAX];
    int rc = fv_index_norm_path(path_in, dest, sizeof dest);
    if (rc != FV_OK) return rc;

    uint64_t id;
    rc = fv_index_resolve(&v->ix, dest, &id);
    if (rc != FV_OK) return rc;
    if (id == 1) return FV_ERR_ARG;                  /* корень не удалить */

    const fv_node *n = fv_index_get(&v->ix, id);
    if (!n) return FV_ERR_NOTFOUND;
    if (n->type == FV_NODE_DIR && !recursive && fv_index_has_children(&v->ix, id))
        return FV_ERR_NOTEMPTY;

    /* собираем поддерево и имена блобов */
    fv_node *sub = NULL;
    size_t nsub = 0;
    rc = fv_index_collect_subtree(&v->ix, id, &sub, &nsub);
    if (rc != FV_OK) return rc;

    fv_strlist blobs;
    memset(&blobs, 0, sizeof blobs);
    uint64_t *ids = (uint64_t *)malloc(nsub * sizeof(uint64_t));
    if (!ids) {
        free(sub);
        return FV_ERR_NOMEM;
    }
    for (size_t i = 0; i < nsub; i++) {
        ids[i] = sub[i].id;
        if (sub[i].type == FV_NODE_FILE)
            fv_strlist_add(&blobs, sub[i].blob);
    }

    fv_index_remove_ids(&v->ix, ids, nsub);
    rc = ix_commit(v);
    if (rc != FV_OK) {
        fv_index_restore_nodes(&v->ix, sub, nsub);   /* откат */
        free(ids);
        free(sub);
        fv_strlist_free(&blobs);
        return rc;
    }
    free(ids);
    free(sub);

    /* индекс закоммичен — теперь можно удалять блобы с диска */
    for (size_t i = 0; i < blobs.count; i++) {
        char path[FV_PATH_MAX];
        if (snprintf(path, sizeof path, "%s%c%s.bin", v->blobs, FV_PATH_SEP, blobs.items[i])
                < (int)sizeof path)
            plat_remove(path);
    }
    fv_strlist_free(&blobs);
    return FV_OK;
}

int fv_vault_mv(fv_vault *v, const char *src_in, const char *dst_in)
{
    if (!v) return FV_ERR_ARG;
    char src[FV_PATH_MAX], dst[FV_PATH_MAX];
    int rc = fv_index_norm_path(src_in, src, sizeof src);
    if (rc != FV_OK) return rc;
    rc = fv_index_norm_path(dst_in, dst, sizeof dst);
    if (rc != FV_OK) return rc;

    uint64_t sid;
    rc = fv_index_resolve(&v->ix, src, &sid);
    if (rc != FV_OK) return rc;
    if (sid == 1) return FV_ERR_ARG;                 /* корень не перемещают */

    /* вычисляем конечный путь */
    char final_dst[FV_PATH_MAX];
    uint64_t did = 0;
    rc = fv_index_resolve(&v->ix, dst, &did);
    if (rc == FV_OK && fv_index_get(&v->ix, did)->type == FV_NODE_DIR) {
        const char *base = strrchr(src, '/') + 1;
        if (snprintf(final_dst, sizeof final_dst, "%s%s%s",
                     strcmp(dst, "/") == 0 ? "" : dst, "/", base) >= (int)sizeof final_dst)
            return FV_ERR_RANGE;
        rc = FV_ERR_NOTFOUND;                        /* final_dst может не существовать */
    } else if (rc == FV_OK) {
        strcpy(final_dst, dst);                      /* цель — существующий файл */
    } else if (rc == FV_ERR_NOTFOUND) {
        strcpy(final_dst, dst);
    } else {
        return rc;
    }

    if (!strcmp(src, final_dst)) return FV_OK;       /* перемещение в себя */

    /* каталог нельзя переносить внутрь себя */
    {
        const fv_node *sn = fv_index_get(&v->ix, sid);
        if (sn->type == FV_NODE_DIR) {
            size_t sl = strlen(src);
            if (!strncmp(final_dst, src, sl) && final_dst[sl] == '/')
                return FV_ERR_ARG;
        }
    }

    /* возможная перезапись файла */
    char del_blob[33] = { 0 };
    uint64_t del_id = 0;
    fv_node del_saved;
    uint64_t tmp_id;
    if (fv_index_resolve(&v->ix, final_dst, &tmp_id) == FV_OK) {
        const fv_node *dn = fv_index_get(&v->ix, tmp_id);
        if (dn->type == FV_NODE_DIR) return FV_ERR_EXISTS;
        if (tmp_id == sid) return FV_OK;
        del_id = tmp_id;
        strcpy(del_blob, dn->blob);
        del_saved = *dn;
    }

    fv_loc fl;
    rc = fv_index_resolve_ex(&v->ix, final_dst, &fl);
    if (rc == FV_OK) return FV_ERR_EXISTS;           /* ещё жив после проверки? */
    if (!fl.parent) return FV_ERR_NOTFOUND;

    /* мутируем индекс */
    if (del_id) fv_index_remove_one(&v->ix, del_id);
    fv_node *sn2 = fv_index_node(&v->ix, sid);
    uint64_t old_parent = sn2->parent;
    char old_name[FV_NAME_MAX + 1];
    strcpy(old_name, sn2->name);
    sn2->parent = fl.parent;
    strcpy(sn2->name, strrchr(final_dst, '/') + 1);

    rc = ix_commit(v);
    if (rc != FV_OK) {                               /* откат */
        if (del_id) fv_index_restore_nodes(&v->ix, &del_saved, 1);
        sn2 = fv_index_node(&v->ix, sid);
        sn2->parent = old_parent;
        strcpy(sn2->name, old_name);
        return rc;
    }
    if (del_id) {
        char path[FV_PATH_MAX];
        if (snprintf(path, sizeof path, "%s%c%s.bin", v->blobs, FV_PATH_SEP, del_blob)
                < (int)sizeof path)
            plat_remove(path);
    }
    return FV_OK;
}

/* Общий путь записи: блоб из src + мутация индекса с откатом.
 * final — полный путь файла в контейнере. Существующий файл перезаписывается
 * (старый блоб удаляется), существующий каталог — ошибка. */
static int vault_store(fv_vault *v, fv_blob_src *src, uint64_t size,
                       const char *final_in)
{
    char final[FV_PATH_MAX];
    int rc = fv_index_norm_path(final_in, final, sizeof final);
    if (rc != FV_OK) return rc;

    /* конечный целевой узел: либо файл на перезапись, либо новое имя */
    fv_loc floc;
    int exists = (fv_index_resolve_ex(&v->ix, final, &floc) == FV_OK);
    if (exists) {
        if (fv_index_get(&v->ix, floc.id)->type == FV_NODE_DIR)
            return FV_ERR_EXISTS;
    } else if (!floc.parent) {
        return FV_ERR_NOTFOUND;
    }

    /* случайное имя блоба, свободное и в индексе, и на диске */
    char blob[33];
    char bpath[FV_PATH_MAX];
    uint64_t tmp_id = 0;
    for (int attempt = 0; ; attempt++) {
        uint8_t raw[16];
        rc = fv_random(raw, sizeof raw);
        if (rc != FV_OK) return rc;
        fv_hex(raw, sizeof raw, blob);
        if (fv_index_resolve(&v->ix, blob, &tmp_id) == FV_OK) {
            /* занято в индексе (маловероятно) */
        } else {
            snprintf(bpath, sizeof bpath, "%s%c%s.bin", v->blobs, FV_PATH_SEP, blob);
            if (plat_stat_kind(bpath) == 0 || attempt >= 8) break;
        }
    }

    uint32_t chunk = 0;
    rc = fv_blob_write_ex(v->mk, v->uuid, v->blobs, src, size, blob, &chunk);
    if (rc != FV_OK) return rc;
    uint64_t wsize = size;

    /* мутация индекса с откатом */
    uint64_t now = (uint64_t)time(NULL);
    fv_node saved;
    int overwrote = 0;
    uint64_t newid = 0;
    if (exists) {
        fv_node *n = fv_index_node(&v->ix, floc.id);
        saved = *n;
        overwrote = 1;
        memcpy(n->blob, blob, 33);
        n->size = wsize;
        n->chunk_size = chunk;
        n->mtime = now;
    } else {
        newid = fv_index_add_node(&v->ix, floc.parent, floc.name, FV_NODE_FILE, now);
        if (!newid) {
            snprintf(bpath, sizeof bpath, "%s%c%s.bin", v->blobs, FV_PATH_SEP, blob);
            plat_remove(bpath);
            return FV_ERR_NOMEM;
        }
        fv_node *n = fv_index_node(&v->ix, newid);
        memcpy(n->blob, blob, 33);
        n->size = wsize;
        n->chunk_size = chunk;
    }

    rc = ix_commit(v);
    if (rc != FV_OK) {                               /* откат */
        if (overwrote) {
            *fv_index_node(&v->ix, saved.id) = saved;
        } else {
            fv_index_remove_one(&v->ix, newid);
        }
        snprintf(bpath, sizeof bpath, "%s%c%s.bin", v->blobs, FV_PATH_SEP, blob);
        plat_remove(bpath);
        return rc;
    }

    if (overwrote) {                                 /* старый блоб больше не нужен */
        char oldp[FV_PATH_MAX];
        if (snprintf(oldp, sizeof oldp, "%s%c%s.bin", v->blobs, FV_PATH_SEP, saved.blob)
                < (int)sizeof oldp)
            plat_remove(oldp);
    }
    return FV_OK;
}

int fv_vault_put(fv_vault *v, const char *host_in, const char *vdest)
{
    if (!v || !host_in || !vdest) return FV_ERR_ARG;
    char host[FV_PATH_MAX];
    int rc = plat_expand_path(host_in, host, sizeof host);
    if (rc != FV_OK) return rc;

    int k = plat_stat_kind(host);
    if (k == 0) return FV_ERR_NOTFOUND;
    if (k == 2) return FV_ERR_ARG;                   /* каталоги не копируем */
    uint64_t size = 0;
    rc = plat_file_size(host, &size);
    if (rc != FV_OK) return rc;

    /* цель: существующий каталог -> положить внутрь; иначе путь цели */
    char dest[FV_PATH_MAX], final[FV_PATH_MAX];
    rc = fv_index_norm_path(vdest, dest, sizeof dest);
    if (rc != FV_OK) return rc;
    uint64_t did;
    if (fv_index_resolve(&v->ix, dest, &did) == FV_OK &&
        fv_index_get(&v->ix, did)->type == FV_NODE_DIR) {
        const char *base = NULL;
        rc = fv_basename(host, &base);
        if (rc != FV_OK || !base || !*base) return FV_ERR_ARG;
        if (snprintf(final, sizeof final, "%s%s%s",
                     strcmp(dest, "/") == 0 ? "" : dest, "/", base) >= (int)sizeof final)
            return FV_ERR_RANGE;
    } else {
        strcpy(final, dest);
    }

    FILE *hf = plat_fopen(host, "rb");
    if (!hf) return FV_ERR_IO;
    fv_blob_src src;
    memset(&src, 0, sizeof src);
    src.is_mem = 0;
    src.f = hf;
    rc = vault_store(v, &src, size, final);
    fclose(hf);
    return rc;
}

int fv_vault_get(fv_vault *v, const char *vsrc, const char *host_in)
{
    if (!v || !vsrc || !host_in) return FV_ERR_ARG;
    char src[FV_PATH_MAX];
    int rc = fv_index_norm_path(vsrc, src, sizeof src);
    if (rc != FV_OK) return rc;

    uint64_t id;
    rc = fv_index_resolve(&v->ix, src, &id);
    if (rc != FV_OK) return rc;
    const fv_node *n = fv_index_get(&v->ix, id);
    if (n->type == FV_NODE_DIR) return FV_ERR_ARG;   /* это каталог */

    char host[FV_PATH_MAX], final[FV_PATH_MAX];
    rc = plat_expand_path(host_in, host, sizeof host);
    if (rc != FV_OK) return rc;

    int k = plat_stat_kind(host);
    if (k == 2) {
        fv_path_join(final, sizeof final, host, n->name);
        if (plat_stat_kind(final) == 1) return FV_ERR_EXISTS;
    } else if (k == 1) {
        return FV_ERR_EXISTS;                        /* молча не перезаписываем */
    } else {
        strcpy(final, host);
        char d[FV_PATH_MAX];
        if (fv_dirname(final, d, sizeof d) == FV_OK && plat_stat_kind(d) != 2)
            return FV_ERR_NOTFOUND;                  /* каталога назначения нет */
    }

    char tmp[FV_PATH_MAX];
    if (snprintf(tmp, sizeof tmp, "%s.fvpart", final) >= (int)sizeof tmp)
        return FV_ERR_RANGE;

    FILE *hf = plat_fopen(tmp, "wb");
    if (!hf) return FV_ERR_IO;

    fv_blob_reader *r = NULL;
    rc = fv_blob_reader_open(&r, v->mk, v->uuid, v->blobs, n->blob,
                             n->size, n->chunk_size);
    uint8_t *buf = NULL;
    uint64_t total = 0;
    if (rc == FV_OK) {
        buf = (uint8_t *)malloc(n->chunk_size);
        if (!buf) rc = FV_ERR_NOMEM;
    }
    while (rc == FV_OK) {
        size_t got = 0;
        rc = fv_blob_reader_read(r, buf, &got);
        if (rc != FV_OK || got == 0) break;
        if (fwrite(buf, 1, got, hf) != got) { rc = FV_ERR_IO; break; }
        total += got;
    }
    if (rc == FV_OK && total != n->size) rc = FV_ERR_FORMAT;
    if (rc == FV_OK) {
        if (fflush(hf) != 0) rc = FV_ERR_IO;
        else rc = plat_fsync(hf);
    }
    free(buf);
    fv_blob_reader_close(r);
    fclose(hf);

    if (rc != FV_OK) {
        plat_remove(tmp);
        return rc;
    }
    rc = plat_atomic_replace(tmp, final);
    if (rc != FV_OK) {
        plat_remove(tmp);
        return rc;
    }
    char d[FV_PATH_MAX];
    if (fv_dirname(final, d, sizeof d) == FV_OK)
        plat_fsync_dir(d);
    return FV_OK;
}

int fv_vault_cat(fv_vault *v, const char *vsrc)
{
    if (!v || !vsrc) return FV_ERR_ARG;
    char src[FV_PATH_MAX];
    int rc = fv_index_norm_path(vsrc, src, sizeof src);
    if (rc != FV_OK) return rc;

    uint64_t id;
    rc = fv_index_resolve(&v->ix, src, &id);
    if (rc != FV_OK) return rc;
    const fv_node *n = fv_index_get(&v->ix, id);
    if (n->type == FV_NODE_DIR) return FV_ERR_ARG;

    fv_blob_reader *r = NULL;
    rc = fv_blob_reader_open(&r, v->mk, v->uuid, v->blobs, n->blob,
                             n->size, n->chunk_size);
    if (rc != FV_OK) return rc;

    uint8_t *buf = (uint8_t *)malloc(n->chunk_size);
    if (!buf) {
        fv_blob_reader_close(r);
        return FV_ERR_NOMEM;
    }
    for (;;) {
        size_t got = 0;
        rc = fv_blob_reader_read(r, buf, &got);
        if (rc != FV_OK) break;
        if (got == 0) { rc = FV_OK; break; }
        plat_write_stdout(buf, got);
    }
    free(buf);
    fv_blob_reader_close(r);
    return rc;
}

int fv_vault_stat(fv_vault *v, const char *path_in, fv_vstat *st)
{
    if (!v || !path_in || !st) return FV_ERR_ARG;
    char src[FV_PATH_MAX];
    int rc = fv_index_norm_path(path_in, src, sizeof src);
    if (rc != FV_OK) return rc;
    uint64_t id;
    rc = fv_index_resolve(&v->ix, src, &id);
    if (rc != FV_OK) return rc;
    const fv_node *n = fv_index_get(&v->ix, id);
    memset(st, 0, sizeof *st);
    st->type = n->type;
    strcpy(st->name, n->name);
    st->size = n->size;
    st->chunk_size = n->chunk_size;
    st->mtime = n->mtime;
    strcpy(st->blob, n->blob);
    return FV_OK;
}

int fv_vault_list(fv_vault *v, const char *path_in, fv_list_cb cb, void *ctx)
{
    if (!v || !path_in || !cb) return FV_ERR_ARG;
    char src[FV_PATH_MAX];
    int rc = fv_index_norm_path(path_in, src, sizeof src);
    if (rc != FV_OK) return rc;
    uint64_t id;
    rc = fv_index_resolve(&v->ix, src, &id);
    if (rc != FV_OK) return rc;
    return fv_index_list(&v->ix, id, cb, ctx);
}

void fv_vault_totals(const fv_vault *v, size_t *files, size_t *dirs, uint64_t *bytes)
{
    if (v) fv_index_totals(&v->ix, files, dirs, bytes);
    else {
        if (files) *files = 0;
        if (dirs)  *dirs = 0;
        if (bytes) *bytes = 0;
    }
}

/* ---------- память <-> контейнер (для встроенного редактора) ---------- */

#define FV_MEM_LIMIT (256ull << 20)      /* разумная страховка от гигантских файлов */

int fv_vault_read_mem(fv_vault *v, const char *vpath, uint8_t **data, size_t *len)
{
    *data = NULL;
    *len = 0;
    if (!v || !vpath || !data || !len) return FV_ERR_ARG;
    char src[FV_PATH_MAX];
    int rc = fv_index_norm_path(vpath, src, sizeof src);
    if (rc != FV_OK) return rc;

    uint64_t id;
    rc = fv_index_resolve(&v->ix, src, &id);
    if (rc != FV_OK) return rc;
    const fv_node *n = fv_index_get(&v->ix, id);
    if (n->type == FV_NODE_DIR) return FV_ERR_ARG;
    if (n->size > FV_MEM_LIMIT) return FV_ERR_RANGE;

    uint8_t *buf = (uint8_t *)malloc(n->size ? (size_t)n->size : 1);
    if (!buf) return FV_ERR_NOMEM;

    fv_blob_reader *r = NULL;
    rc = fv_blob_reader_open(&r, v->mk, v->uuid, v->blobs, n->blob,
                             n->size, n->chunk_size);
    size_t total = 0;
    while (rc == FV_OK) {
        size_t got = 0;
        rc = fv_blob_reader_read(r, buf + total, &got);
        if (rc != FV_OK || got == 0) break;
        total += got;
    }
    fv_blob_reader_close(r);

    if (rc != FV_OK || total != (size_t)n->size) {
        fv_wipe(buf, total);
        free(buf);
        return (rc == FV_OK) ? FV_ERR_FORMAT : rc;
    }
    *data = buf;
    *len = total;
    return FV_OK;
}

int fv_vault_write_mem(fv_vault *v, const char *vpath,
                       const uint8_t *data, size_t len)
{
    if (!v || !vpath || (!data && len)) return FV_ERR_ARG;
    if ((uint64_t)len > FV_MEM_LIMIT) return FV_ERR_RANGE;

    fv_blob_src src;
    memset(&src, 0, sizeof src);
    src.is_mem = 1;
    src.mem = data;
    src.mem_len = len;
    return vault_store(v, &src, (uint64_t)len, vpath);
}
