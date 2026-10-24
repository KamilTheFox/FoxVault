/* crypto.h — обёртка над mbedTLS: AES-256-GCM и PBKDF2-HMAC-SHA256.
 *
 * Формат запечатанного сообщения (fv_seal):
 *     nonce[12] | ciphertext[len] | tag[16]
 * Итого длина = len + FV_SEAL_OVERHEAD.
 *
 * AAD (дополнительные аутентифицируемые данные) не шифруются, но защищены
 * тегом: туда кладём контекст (тип объекта, ID блоба, номер чанка), чтобы
 * зашифрованный кусок нельзя было подменить другим, тоже валидным.
 */
#ifndef FV_CRYPTO_H
#define FV_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#define FV_KEY_LEN        32
#define FV_NONCE_LEN      12
#define FV_TAG_LEN        16
#define FV_SALT_LEN       32
#define FV_SEAL_OVERHEAD  (FV_NONCE_LEN + FV_TAG_LEN)

/* Рекомендация OWASP для PBKDF2-HMAC-SHA256 */
#define FV_KDF_DEFAULT_ITERS  600000u
#define FV_KDF_MIN_ITERS      100000u
#define FV_KDF_MAX_ITERS      100000000u

/* Криптостойкие случайные байты от ОС */
int fv_random(void *buf, size_t len);

/* Прогресс PBKDF2: вызывается раз в cb_every итераций (для анимации) */
typedef void (*fv_kdf_progress)(void *ctx, uint32_t done, uint32_t total);

/* PBKDF2-HMAC-SHA256 → 32-байтный ключ, с опциональным прогрессом */
int fv_kdf_ex(const char *pass, size_t pass_len,
              const uint8_t *salt, size_t salt_len,
              uint32_t iters, uint8_t out[FV_KEY_LEN],
              fv_kdf_progress cb, void *cb_ctx, uint32_t cb_every);

/* PBKDF2-HMAC-SHA256 → 32-байтный ключ (без прогресса) */
int fv_kdf(const char *pass, size_t pass_len,
           const uint8_t *salt, size_t salt_len,
           uint32_t iters, uint8_t out[FV_KEY_LEN]);

/* Шифрование со случайным nonce. out — минимум len + FV_SEAL_OVERHEAD байт.
 * in и out не должны перекрываться. */
int fv_seal(const uint8_t key[FV_KEY_LEN],
            const uint8_t *aad, size_t aad_len,
            const uint8_t *in, size_t len,
            uint8_t *out);

/* Расшифровка с проверкой тега. in_len >= FV_SEAL_OVERHEAD.
 * out — минимум in_len - FV_SEAL_OVERHEAD байт.
 * При неверном теге возвращает FV_ERR_AUTH, а out затирается. */
int fv_open(const uint8_t key[FV_KEY_LEN],
            const uint8_t *aad, size_t aad_len,
            const uint8_t *in, size_t in_len,
            uint8_t *out);

/* Низкоуровневый вариант с заданным nonce — только для тестов на эталонных векторах */
int fv_gcm_encrypt_raw(const uint8_t key[FV_KEY_LEN], const uint8_t nonce[FV_NONCE_LEN],
                       const uint8_t *aad, size_t aad_len,
                       const uint8_t *in, size_t len,
                       uint8_t *out, uint8_t tag[FV_TAG_LEN]);

/* Затирание, которое компилятор не выкинет */
void fv_wipe(void *p, size_t len);

/* Сравнение за постоянное время: 0 — равны */
int fv_ct_memcmp(const void *a, const void *b, size_t len);

#endif
