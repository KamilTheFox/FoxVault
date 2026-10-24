/*
 * Минимальная конфигурация mbedTLS для foxvault.
 * Включено только то, что нужно: AES-256-GCM (с AES-NI) и PBKDF2-HMAC-SHA256.
 * Случайные числа берём напрямую у ОС (platform.c), поэтому entropy/ctr_drbg не нужны.
 */
#ifndef FOXVAULT_MBEDTLS_CONFIG_H
#define FOXVAULT_MBEDTLS_CONFIG_H

/* Аппаратное ускорение AES */
#define MBEDTLS_HAVE_ASM
#define MBEDTLS_AESNI_C

/* Блочный шифр и режим */
#define MBEDTLS_AES_C
#define MBEDTLS_GCM_C
#define MBEDTLS_CIPHER_C

/* Хеш и KDF */
#define MBEDTLS_MD_C
#define MBEDTLS_SHA256_C
#define MBEDTLS_PKCS5_C

/* Платформенный слой mbedTLS: на MinGW обязателен (snprintf отличается
 * от MSVCRT — там auto-enable PLATFORM_SNPRINTF_ALT/ VSNPRINTF_ALT),
 * на POSIX даёт стандартные обёртки и не меняет поведения. */
#define MBEDTLS_PLATFORM_C

/* Только 256-битные ключи — 128/192 не используются, но AES_C их не отключает,
 * это нормально. */

#endif /* FOXVAULT_MBEDTLS_CONFIG_H */
