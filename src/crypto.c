/* crypto.c */
#include "crypto.h"
#include "platform.h"
#include "util.h"

#include <mbedtls/gcm.h>
#include <mbedtls/md.h>
#include <mbedtls/pkcs5.h>
#include <mbedtls/platform_util.h>

#include <string.h>

int fv_random(void *buf, size_t len)
{
    return plat_random(buf, len);
}

/* PBKDF2-HMAC-SHA256, dkLen = 32 = hLen — ровно один блок F(P,S,c,1).
 * Пишем цикл сами, чтобы между итерациями вызывать колбэк прогресса:
 * mbedtls_pkcs5_pbkdf2_hmac — один непрерываемый вызов. */
int fv_kdf_ex(const char *pass, size_t pass_len,
              const uint8_t *salt, size_t salt_len,
              uint32_t iters, uint8_t out[FV_KEY_LEN],
              fv_kdf_progress cb, void *cb_ctx, uint32_t cb_every)
{
    if (!pass || !salt || !out) return FV_ERR_ARG;
    if (iters < FV_KDF_MIN_ITERS || iters > FV_KDF_MAX_ITERS) return FV_ERR_RANGE;

    const mbedtls_md_info_t *mi = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!mi) return FV_ERR_CRYPTO;

    mbedtls_md_context_t c;
    mbedtls_md_init(&c);
    if (mbedtls_md_setup(&c, mi, 1) != 0) {
        mbedtls_md_free(&c);
        return FV_ERR_CRYPTO;
    }

    int rc = FV_OK;
    uint8_t u[32], t[32];
    uint8_t tail[4] = { 0, 0, 0, 1 };               /* INT_32_BE(1) */

    if (mbedtls_md_hmac_starts(&c, (const unsigned char *)pass, pass_len) != 0 ||
        mbedtls_md_hmac_update(&c, salt, salt_len) != 0 ||
        mbedtls_md_hmac_update(&c, tail, sizeof tail) != 0 ||
        mbedtls_md_hmac_finish(&c, u) != 0) {
        rc = FV_ERR_CRYPTO;
    } else {
        memcpy(t, u, 32);
    }

    for (uint32_t i = 2; rc == FV_OK && i <= iters; i++) {
        if (mbedtls_md_hmac_starts(&c, (const unsigned char *)pass, pass_len) != 0 ||
            mbedtls_md_hmac_update(&c, u, 32) != 0 ||
            mbedtls_md_hmac_finish(&c, u) != 0) {
            rc = FV_ERR_CRYPTO;
            break;
        }
        for (int j = 0; j < 32; j++) t[j] = (uint8_t)(t[j] ^ u[j]);
        if (cb && cb_every && (i % cb_every) == 0) cb(cb_ctx, i, iters);
    }

    mbedtls_md_free(&c);
    if (rc != FV_OK) {
        fv_wipe(u, sizeof u);
        fv_wipe(t, sizeof t);
        fv_wipe(out, FV_KEY_LEN);
        return rc;
    }
    memcpy(out, t, FV_KEY_LEN);
    fv_wipe(u, sizeof u);
    fv_wipe(t, sizeof t);
    return FV_OK;
}

int fv_kdf(const char *pass, size_t pass_len,
           const uint8_t *salt, size_t salt_len,
           uint32_t iters, uint8_t out[FV_KEY_LEN])
{
    return fv_kdf_ex(pass, pass_len, salt, salt_len, iters, out,
                     NULL, NULL, 0);
}

int fv_gcm_encrypt_raw(const uint8_t key[FV_KEY_LEN], const uint8_t nonce[FV_NONCE_LEN],
                       const uint8_t *aad, size_t aad_len,
                       const uint8_t *in, size_t len,
                       uint8_t *out, uint8_t tag[FV_TAG_LEN])
{
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);

    int rc = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, FV_KEY_LEN * 8);
    if (rc == 0)
        rc = mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_ENCRYPT, len,
                                       nonce, FV_NONCE_LEN, aad, aad_len,
                                       in, out, FV_TAG_LEN, tag);
    mbedtls_gcm_free(&ctx);   /* затирает раунд-ключи */
    return rc == 0 ? FV_OK : FV_ERR_CRYPTO;
}

int fv_seal(const uint8_t key[FV_KEY_LEN],
            const uint8_t *aad, size_t aad_len,
            const uint8_t *in, size_t len,
            uint8_t *out)
{
    if (!key || !out || (!in && len)) return FV_ERR_ARG;

    uint8_t *nonce = out;
    uint8_t *ct    = out + FV_NONCE_LEN;
    uint8_t *tag   = out + FV_NONCE_LEN + len;

    int rc = fv_random(nonce, FV_NONCE_LEN);
    if (rc != FV_OK) return rc;

    return fv_gcm_encrypt_raw(key, nonce, aad, aad_len, in, len, ct, tag);
}

int fv_open(const uint8_t key[FV_KEY_LEN],
            const uint8_t *aad, size_t aad_len,
            const uint8_t *in, size_t in_len,
            uint8_t *out)
{
    if (!key || !in || in_len < FV_SEAL_OVERHEAD) return FV_ERR_ARG;

    size_t len = in_len - FV_SEAL_OVERHEAD;
    if (len && !out) return FV_ERR_ARG;

    const uint8_t *nonce = in;
    const uint8_t *ct    = in + FV_NONCE_LEN;
    const uint8_t *tag   = in + FV_NONCE_LEN + len;

    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);

    int rc = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, FV_KEY_LEN * 8);
    if (rc == 0)
        rc = mbedtls_gcm_auth_decrypt(&ctx, len, nonce, FV_NONCE_LEN,
                                      aad, aad_len, tag, FV_TAG_LEN, ct, out);
    mbedtls_gcm_free(&ctx);

    if (rc == MBEDTLS_ERR_GCM_AUTH_FAILED) {
        /* mbedTLS уже затирает out, но перестрахуемся */
        if (len) fv_wipe(out, len);
        return FV_ERR_AUTH;
    }
    return rc == 0 ? FV_OK : FV_ERR_CRYPTO;
}

void fv_wipe(void *p, size_t len)
{
    if (p && len) mbedtls_platform_zeroize(p, len);
}

int fv_ct_memcmp(const void *a, const void *b, size_t len)
{
    const volatile uint8_t *x = (const volatile uint8_t *)a;
    const volatile uint8_t *y = (const volatile uint8_t *)b;
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) diff |= (uint8_t)(x[i] ^ y[i]);
    return diff != 0;
}
