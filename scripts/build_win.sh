#!/bin/bash
# Кросс-компиляция foxvault под Windows x86_64 через zig cc (mingw-w64 runtime)
set -e
# каталог проекта определяем относительно самого скрипта:
# скрипт лежит в <проект>/scripts/, значит проект — на уровень выше
cd "$(cd "$(dirname "$0")" && pwd)/.."
ZIG="python3 -m ziglang"
TARGET="-target x86_64-windows-gnu"
OUT=build-win
mkdir -p $OUT/obj

MBEDCFG='-Iconfig -Ithird_party/mbedtls/include -DMBEDTLS_CONFIG_FILE="foxvault_mbedtls_config.h"'
MBSRC="aes aesni aesce gcm cipher cipher_wrap block_cipher md sha256 pkcs5 platform platform_util constant_time"

echo "== mbedTLS =="
for f in $MBSRC; do
    $ZIG cc $TARGET -O2 -w $MBEDCFG \
        -c third_party/mbedtls/library/$f.c -o $OUT/obj/mb_$f.o &
done
wait

echo "== foxvault =="
$ZIG cc $TARGET -O2 -std=gnu11 -Wall -Wextra -Wno-format-truncation \
    -Isrc $MBEDCFG -DUNICODE -D_UNICODE -DWIN32_LEAN_AND_MEAN \
    -c src/main.c     -o $OUT/obj/main.o &
$ZIG cc $TARGET -O2 -std=gnu11 -Wall -Wextra -Wno-format-truncation \
    -Isrc $MBEDCFG -DUNICODE -D_UNICODE -DWIN32_LEAN_AND_MEAN \
    -c src/shell.c    -o $OUT/obj/shell.o &
$ZIG cc $TARGET -O2 -std=gnu11 -Wall -Wextra -Wno-format-truncation \
    -Isrc $MBEDCFG -DUNICODE -D_UNICODE -DWIN32_LEAN_AND_MEAN \
    -c src/vault.c    -o $OUT/obj/vault.o &
$ZIG cc $TARGET -O2 -std=gnu11 -Wall -Wextra -Wno-format-truncation \
    -Isrc $MBEDCFG -DUNICODE -D_UNICODE -DWIN32_LEAN_AND_MEAN \
    -c src/index.c    -o $OUT/obj/index.o &
$ZIG cc $TARGET -O2 -std=gnu11 -Wall -Wextra -Wno-format-truncation \
    -Isrc $MBEDCFG -DUNICODE -D_UNICODE -DWIN32_LEAN_AND_MEAN \
    -c src/blob.c     -o $OUT/obj/blob.o &
$ZIG cc $TARGET -O2 -std=gnu11 -Wall -Wextra -Wno-format-truncation \
    -Isrc $MBEDCFG -DUNICODE -D_UNICODE -DWIN32_LEAN_AND_MEAN \
    -c src/crypto.c   -o $OUT/obj/crypto.o &
$ZIG cc $TARGET -O2 -std=gnu11 -Wall -Wextra -Wno-format-truncation \
    -Isrc $MBEDCFG -DUNICODE -D_UNICODE -DWIN32_LEAN_AND_MEAN \
    -c src/platform.c -o $OUT/obj/platform.o &
$ZIG cc $TARGET -O2 -std=gnu11 -Wall -Wextra -Wno-format-truncation \
    -Isrc $MBEDCFG -DUNICODE -D_UNICODE -DWIN32_LEAN_AND_MEAN \
    -c src/util.c     -o $OUT/obj/util.o &
$ZIG cc $TARGET -O2 -std=gnu11 -Wall -Wextra -Wno-format-truncation \
    -Isrc $MBEDCFG -DUNICODE -D_UNICODE -DWIN32_LEAN_AND_MEAN \
    -c src/editor.c   -o $OUT/obj/editor.o &
$ZIG cc $TARGET -O2 -std=gnu11 -Wall -Wextra -Wno-format-truncation \
    -Isrc $MBEDCFG -DUNICODE -D_UNICODE -DWIN32_LEAN_AND_MEAN \
    -c src/rx.c       -o $OUT/obj/rx.o &
wait

echo "== link =="
$ZIG cc $TARGET -std=gnu11 -static \
    $OUT/obj/*.o -o $OUT/foxvault.exe -lbcrypt -lshell32
ls -la $OUT/foxvault.exe
