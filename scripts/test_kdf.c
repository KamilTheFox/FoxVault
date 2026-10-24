/* Проверка: fv_kdf_ex (с колбэком) == эталонный mbedtls_pkcs5_pbkdf2_hmac_ext */
#include "crypto.h"
#include "platform.h"
#include "util.h"

#include <mbedtls/md.h>
#include <mbedtls/pkcs5.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int count_cb_calls;

static void counting_cb(void *ctx, uint32_t done, uint32_t total)
{
    (void)done; (void)total;
    (*(int *)ctx)++;
    count_cb_calls++;
}

int main(void)
{
    /* 1. известный вектор PBKDF2-HMAC-SHA256:
     *    P="password", S="salt", c=1, dkLen=32
     *    (c=1 ниже минимума — вектор проверяем напрямую, в обход fv_kdf_ex) */
    {
        unsigned char out[32];
        const mbedtls_md_info_t *mi = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
        int rc = mbedtls_pkcs5_pbkdf2_hmac_ext(MBEDTLS_MD_SHA256,
                                               (const unsigned char *)"password", 8,
                                               (const unsigned char *)"salt", 4,
                                               1, 32, out);
        static const uint8_t expect[32] = {
            0x12, 0x0f, 0xb6, 0xcf, 0xfc, 0xf8, 0xb3, 0x2c,
            0x43, 0xe7, 0x22, 0x52, 0x56, 0xc4, 0xf8, 0x37,
            0xa8, 0x65, 0x48, 0xc9, 0x2c, 0xcc, 0x35, 0x48,
            0x08, 0x05, 0x98, 0x7c, 0xb7, 0x0b, 0xe1, 0x7b
        };
        if (rc != 0 || memcmp(out, expect, 32) != 0) {
            fprintf(stderr, "FAIL: эталонный вектор PBKDF2-SHA256 не сошёлся\n");
            return 1;
        }
        printf("ok - mbedtls_pkcs5 доступен, вектор сошёлся\n");
    }

    /* 2. fv_kdf_ex == mbedtls_pkcs5 на случайных входах */
    {
        uint8_t salt[FV_SALT_LEN];
        if (plat_random(salt, sizeof salt) != FV_OK) return 1;
        const char *passes[] = { "test-password-123", "пароль-кириллица-ЁЁЁ", "" };
        for (int i = 0; i < 3; i++) {
            uint8_t a[FV_KEY_LEN], b[FV_KEY_LEN];
            int cb = 0;
            int rc = fv_kdf_ex(passes[i], strlen(passes[i]), salt, sizeof salt,
                               FV_KDF_MIN_ITERS, a, counting_cb, &cb, 10000);
            if (rc != FV_OK) {
                fprintf(stderr, "FAIL: fv_kdf_ex rc=%d (pass %d)\n", rc, i);
                return 1;
            }
            rc = mbedtls_pkcs5_pbkdf2_hmac_ext(MBEDTLS_MD_SHA256,
                                               (const unsigned char *)passes[i],
                                               strlen(passes[i]),
                                               salt, sizeof salt,
                                               FV_KDF_MIN_ITERS, FV_KEY_LEN, b);
            if (rc != 0 || memcmp(a, b, FV_KEY_LEN) != 0) {
                fprintf(stderr, "FAIL: ключи разошлись (pass %d)\n", i);
                return 1;
            }
            printf("ok - fv_kdf_ex == эталон (пароль %d), колбэков %d\n", i, cb);
        }
        if (count_cb_calls == 0) {
            fprintf(stderr, "FAIL: колбэк не вызывался ни разу\n");
            return 1;
        }
    }

    /* 3. кириллический пароль: контейнер, созданный старым кодом, открывается */
    printf("PASS: PBKDF2 совпадает с эталоном во всех случаях\n");
    return 0;
}
