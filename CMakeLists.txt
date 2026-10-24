cmake_minimum_required(VERSION 3.16)
project(foxvault C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# ---------- mbedTLS: собираем только нужные файлы со своим конфигом ----------
set(MBEDTLS_DIR ${CMAKE_SOURCE_DIR}/third_party/mbedtls)
set(MBEDTLS_SOURCES
    ${MBEDTLS_DIR}/library/aes.c
    ${MBEDTLS_DIR}/library/aesni.c
    ${MBEDTLS_DIR}/library/aesce.c
    ${MBEDTLS_DIR}/library/gcm.c
    ${MBEDTLS_DIR}/library/cipher.c
    ${MBEDTLS_DIR}/library/cipher_wrap.c
    ${MBEDTLS_DIR}/library/block_cipher.c
    ${MBEDTLS_DIR}/library/md.c
    ${MBEDTLS_DIR}/library/sha256.c
    ${MBEDTLS_DIR}/library/pkcs5.c
    ${MBEDTLS_DIR}/library/platform.c
    ${MBEDTLS_DIR}/library/platform_util.c
    ${MBEDTLS_DIR}/library/constant_time.c
)
add_library(fv_mbedtls STATIC ${MBEDTLS_SOURCES})
target_include_directories(fv_mbedtls PUBLIC
    ${MBEDTLS_DIR}/include
    ${CMAKE_SOURCE_DIR}/config)
target_compile_definitions(fv_mbedtls PUBLIC
    MBEDTLS_CONFIG_FILE="foxvault_mbedtls_config.h")
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    # AES-NI через интринсики
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64|amd64")
        target_compile_options(fv_mbedtls PRIVATE -maes -mpclmul -msse2)
    endif()
    target_compile_options(fv_mbedtls PRIVATE -w)
endif()

# ---------- сам foxvault ----------
add_executable(foxvault
    src/main.c
    src/shell.c
    src/vault.c
    src/index.c
    src/blob.c
    src/crypto.c
    src/platform.c
    src/util.c
)
target_link_libraries(foxvault PRIVATE fv_mbedtls)

if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(foxvault PRIVATE -Wall -Wextra -Wshadow -Wformat=2
                                            -Wconversion -Wno-sign-conversion)
endif()

if(WIN32)
    target_link_libraries(foxvault PRIVATE bcrypt shell32)
    target_compile_definitions(foxvault PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN)
    if(MINGW)
        # один самостоятельный exe без зависимостей от DLL MinGW
        # (аргументы берутся из GetCommandLineW, поэтому -municode не нужен)
        target_link_options(foxvault PRIVATE -static)
    endif()
endif()

option(FV_ASAN "Сборка с AddressSanitizer" OFF)
if(FV_ASAN)
    target_compile_options(foxvault PRIVATE -fsanitize=address,undefined -g -O1)
    target_link_options(foxvault PRIVATE -fsanitize=address,undefined)
endif()
