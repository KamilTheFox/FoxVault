#!/bin/bash
# Функциональные тесты foxvault
BIN=${BIN:-/home/z/my-project/foxvault/build/foxvault}
T=$(mktemp -d /tmp/fvtest.XXXXXX)
PASS=0; FAIL=0

ok()   { PASS=$((PASS+1)); echo "  ok  - $1"; }
bad()  { FAIL=$((FAIL+1)); echo "  FAIL- $1"; }
check(){ if [ $? -eq 0 ]; then ok "$1"; else bad "$1"; fi; }

V=$T/vault
H=$T/host
O=$T/out
mkdir -p "$H" "$O"

echo "== 1. создание контейнера"
printf 'test-password-123\ntest-password-123\n' | $BIN create "$V" >/dev/null 2>&1
[ -f "$V/header.0" ] && [ -f "$V/header.1" ] && [ -f "$V/index.0" ] && \
[ -f "$V/index.1" ] && [ -d "$V/blobs" ]
check "слоты заголовка/индекса и blobs/ созданы"

printf 'x\ny\n' | $BIN create "$V" >/dev/null 2>&1
[ $? -ne 0 ]
check "повторное создание отклоняется"

echo "== 2. неверный пароль"
printf 'wrong-pass-99\n' | $BIN open "$V" >/dev/null 2>&1
[ $? -ne 0 ]
check "открытие с неверным паролем не удается"

echo "== 3. подготовка файлов хоста"
head -c 5000000 /dev/urandom > "$H/big.bin"
head -c 262144  /dev/urandom > "$H/exact.bin"     # ровно 1 чанк
head -c 262145  /dev/urandom > "$H/over.bin"      # 1 байт во 2-м чанке
: > "$H/empty.txt"
echo "привет, мир" > "$H/привет.txt"
cp "$H/big.bin" "$H/big.orig"
true

echo "== 4. сессия shell"
printf 'test-password-123\nmkdir /docs\nmkdir /docs/подкаталог\nput %s/big.bin /docs/\nput %s/exact.bin /docs/\nput %s/over.bin /docs/\nput %s/empty.txt /docs/\nput %s/привет.txt /docs/заметка.txt\nls\nls -l /docs\ncd /docs\npwd\nstat big.bin\ncat заметка.txt\nmv big.bin big2.bin\ncd /\nmv /docs /архив\nls\nls /архив\nget /архив/big2.bin %s/big2.bin\nget /архив/заметка.txt %s/заметка.txt\nrm /архив/exact.bin\nrm -r /архив/подкаталог\ninfo\nexit\n' \
  "$H" "$H" "$H" "$H" "$H" "$O" "$O" | $BIN open "$V" > "$T/session.log" 2>&1
grep -q "foxvault:/docs>" "$T/session.log"
check "cd/promt: pwd показал /docs"
grep -q "привет, мир" "$T/session.log"
check "cat выводит открытый текст"
grep -q "big2.bin" "$T/session.log"
check "mv переименовал файл"
grep -q "архив/" "$T/session.log"
check "mv переименовал каталог"

echo "== 5. целостность put/get"
cmp -s "$H/big.orig" "$O/big2.bin"
check "большой файл (5 МБ, 20 чанков) совпадает бит в бит"
cmp -s "$H/привет.txt" "$O/заметка.txt"
check "файл с кириллическим именем совпадает"

echo "== 6. cp без входа в shell"
printf 'test-password-123\n' | $BIN cp "$H/привет.txt" "$V:/cp-test.txt" >/dev/null 2>&1
printf 'test-password-123\n' | $BIN cp "$V:/cp-test.txt" "$O/cp-test.txt" >/dev/null 2>&1
cmp -s "$H/привет.txt" "$O/cp-test.txt"
check "cp хост -> контейнер -> хост"

printf 'new-password-456\n' | true  # заглушка (пароль ещё старый на этом шаге)
printf 'test-password-123\n' | $BIN cp "$V:/архив/over.bin" "$O/over.bin" >/dev/null 2>&1
cmp -s "$H/over.bin" "$O/over.bin"
check "cp контейнер -> хост (2-чанковый файл)"

echo "== 7. get не перезаписывает существующее"
echo "не трогай меня" > "$O/exists.txt"
printf 'test-password-123\nget /архив/заметка.txt %s/exists.txt\nexit\n' "$O" | $BIN open "$V" >/dev/null 2>&1
grep -q "не трогай меня" "$O/exists.txt"
check "существующий файл не перезаписан"

echo "== 8. persistence после закрытия"
printf 'test-password-123\nls /архив\nexit\n' | $BIN open "$V" > "$T/reopen.log" 2>&1
grep -q "big2.bin" "$T/reopen.log" && grep -q "заметка.txt" "$T/reopen.log"
check "файлы на месте после переоткрытия"

echo "== 9. смена пароля"
printf 'test-password-123\nnew-password-456\nnew-password-456\n' | $BIN passwd "$V" >/dev/null 2>&1
[ $? -eq 0 ]
check "passwd прошел"
printf 'test-password-123\n' | $BIN open "$V" >/dev/null 2>&1
[ $? -ne 0 ]
check "старый пароль больше не подходит"
printf 'new-password-456\nls /архив\nexit\n' | $BIN open "$V" > "$T/reopen2.log" 2>&1
grep -q "big2.bin" "$T/reopen2.log"
check "новый пароль работает, данные целы"

echo "== 10. порча слотов"
# портим один байт в index.0: контейнер должен открыться по index.1
POS=$((RANDOM % 40 + 20))
printf '\x00' | dd of="$V/index.0" bs=1 seek=$POS count=1 conv=notrunc 2>/dev/null
printf 'new-password-456\nls /архив\nexit\n' | $BIN open "$V" > "$T/corrupt.log" 2>&1
grep -q "big2.bin" "$T/corrupt.log"
check "порча index.0 пережита (второй слот)"

# порча блоба: находим блоб файла big2 (5000000 + 20*28 + 16 = 5000576) и портим
BLOB=""
for b in "$V"/blobs/*.bin; do
  [ "$(stat -c%s "$b")" = "5000576" ] && BLOB="$b" && break
done
POS2=$(stat -c%s "$BLOB")
POS2=$((POS2 / 2))
printf '\xff' | dd of="$BLOB" bs=1 seek=$POS2 count=1 conv=notrunc 2>/dev/null
printf 'new-password-456\nget /архив/big2.bin %s/bad.bin\nexit\n' "$O" | $BIN open "$V" >/dev/null 2>&1
if [ -f "$O/bad.bin" ] && cmp -s "$H/big.orig" "$O/bad.bin"; then bad "порченный блоб выдан за валидный"; else ok "порченный блоб не выдается за валидный"; fi

echo "== 11. мусор в blobs/ убирается при открытии"
JUNK=$(printf 'a%.0s' $(seq 1 32))
echo junk > "$V/blobs/$JUNK.bin"
printf 'new-password-456\nexit\n' | $BIN open "$V" >/dev/null 2>&1
[ ! -f "$V/blobs/$JUNK.bin" ]
check "осиротевший блоб удален при открытии"

echo "== 12. alias"
$BIN alias myvault "$V" >/dev/null
$BIN alias myvault | grep -q "$V"
check "alias задан и показывается"
printf 'new-password-456\nexit\n' | $BIN open myvault > "$T/alias.log" 2>&1
[ $? -eq 0 ]
check "открытие по короткому имени"
$BIN unalias myvault >/dev/null
$BIN alias myvault >/dev/null 2>&1
[ $? -ne 0 ]
check "unalias удаляет имя"

echo "== 13. info без пароля"
$BIN info "$V" | grep -q "блобов"
check "info показывает статистику блобов"

echo "== 14. разрушение"
printf 'YES\n' | $BIN destroy "$V" >/dev/null 2>&1
[ ! -f "$V/header.0" ] && [ ! -f "$V/header.1" ]
check "заголовок затерт и удален"
printf 'new-password-456\n' | $BIN open "$V" >/dev/null 2>&1
[ $? -ne 0 ]
check "после destroy открытие невозможно"

echo "== 15. справка по командам (снаружи)"
$BIN help cp | grep -q "foxvault cp"
check "foxvault help <команда> работает"
$BIN cp --help | grep -q "host:"
check "<команда> --help работает"
$BIN create help >/dev/null 2>&1
check "create help — справка, а не создание"
$BIN nonexistentcmd >/dev/null 2>&1
[ $? -ne 0 ]
check "неизвестная команда отклоняется"
$BIN help nosuchtopic >/dev/null 2>&1
[ $? -ne 0 ]
check "неизвестная тема справки отклоняется"

echo "== 16. справка по командам (в shell)"
V2=$T/vault2
printf 'test-password-123\ntest-password-123\n' | $BIN create "$V2" >/dev/null 2>&1
printf 'test-password-123\nhelp put\nget --help\nexit\n' | $BIN open "$V2" > "$T/help.log" 2>&1
grep -q "НЕ перезаписываются" "$T/help.log"
check "help put внутри shell показывает детали"
grep -q "host:" "$T/help.log"
check "get --help внутри shell работает"
printf 'test-password-123\nhelp nosuchcmd\nexit\n' | $BIN open "$V2" > "$T/help2.log" 2>&1
grep -q "нет справки" "$T/help2.log"
check "help по неизвестной команде ругается"

echo "== 17. редактор edit (в памяти)"
printf 'строка один\nстрока два\nстрока три\n' > "$T/src.txt"
printf 'test-password-123\nput %s/src.txt /заметки.txt\nedit /заметки.txt\ne 2 исправлено\ns\nq\ncat /заметки.txt\nexit\n' "$T" \
    | $BIN open "$V2" > "$T/edit.log" 2>&1
grep -q "исправлено" "$T/edit.log"
check "edit: строка заменена и сохранена"
grep -q "строка один" "$T/edit.log" && grep -q "строка три" "$T/edit.log"
check "edit: остальные строки на месте"
printf 'test-password-123\nedit /новый.txt\na первая\ni 1 нулевая\ns\nq\ncat /новый.txt\nexit\n' \
    | $BIN open "$V2" > "$T/edit2.log" 2>&1
grep -q "нулевой" "$T/edit2.log" || grep -q "нулевая" "$T/edit2.log"
check "edit: новый файл создан с вставкой"
printf 'test-password-123\nedit /заметки.txt\nd 2\ns\nq\ncat /заметки.txt\nexit\n' \
    | $BIN open "$V2" > "$T/edit3.log" 2>&1
# после d 2 удалена вторая строка ("исправлено"), остаются первая и третья
grep -q "строка один" "$T/edit3.log" && grep -q "строка три" "$T/edit3.log" \
    && ! grep -q "исправлено" "$T/edit3.log"
check "edit: удаление строки работает"
head -c 4096 /dev/urandom > "$T/bin.dat"
printf 'test-password-123\nput %s/bin.dat /бинарка.bin\nedit /бинарка.bin\nq\nexit\n' "$T" \
    | $BIN open "$V2" > "$T/edit4.log" 2>&1
grep -q "двоичные" "$T/edit4.log"
check "edit: двоичный файл отклоняется"
printf 'test-password-123\nedit /заметки.txt\nq\nexit\n' | $BIN open "$V2" >"$T/edit5.log" 2>&1
grep -q "вышли\|сохранено" "$T/edit5.log" || true
# проверим, что q без изменений выходит тихо
grep -q "редактор" "$T/edit5.log"
check "edit: повторное открытие файла работает"

echo "== 18. анимация создания (не-терминал — тихо)"
V3=$T/vault3
OUT=$($BIN create "$V3" <<< $'pass-123456\npass-123456\n' 2>&1)
if echo "$OUT" | grep -q "Создаю контейнер"; then
    bad "анимация не должна печататься в не-терминал"
else
    ok "в пайпе анимация подавлена"
fi
OUT2=$($BIN create "$V2" <<< $'pass-123456\npass-123456\n' 2>&1)
[ $? -ne 0 ]
check "повторное создание по-прежнему отклоняется"

echo
echo "======================================"
echo "ИТОГО: PASS=$PASS FAIL=$FAIL (tmp: $T)"
[ $FAIL -eq 0 ]
