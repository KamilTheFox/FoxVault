#!/usr/bin/env python3
# Демо анимации создания в настоящем pty (stdout = терминал)
import os, pty, select, time, sys

BIN = "/home/z/my-project/foxvault/build/foxvault"
TARGET = "/tmp/fv-demo-pty"

os.system("rm -rf " + TARGET)
pid, fd = pty.fork()
if pid == 0:
    os.environ["TERM"] = "xterm"
    os.execv(BIN, ["foxvault", "create", TARGET])

out = b""
sent = 0
prompts = ["оль: ".encode()]          # "Введите пароль: " / "Повторите пароль: "
t0 = time.time()
while time.time() - t0 < 10:
    r, _, _ = select.select([fd], [], [], 0.2)
    if r:
        try:
            data = os.read(fd, 4096)
        except OSError:
            break
        if not data:
            break
        out += data
    if sent < 2 and out.count(prompts[0]) > sent:
        os.write(fd, b"pass-123456\r\n")
        sent += 1
    DONE = "контейнер создан".encode()
    MISMATCH = "пароли не совпадают".encode()
    if DONE in out or MISMATCH in out:
        time.sleep(0.2)
        try:
            while True:
                r, _, _ = select.select([fd], [], [], 0.2)
                if not r: break
                d = os.read(fd, 4096)
                if not d: break
                out += d
        except OSError:
            pass
        break

try:
    os.close(fd)
except OSError:
    pass
os.waitpid(pid, 0)

text = out.decode("utf-8", "replace").replace("\r\n", "\n")
dots = [ln for ln in text.split("\r") if "Создаю контейнер" in ln]
print("---- визуальная дорожка анимации (по \\r) ----")
for ln in dots:
    print(repr(ln.strip()))
print("---- финал ----")
print(text.strip().splitlines()[-1])
print("контейнер создан:", os.path.isdir(TARGET))
ok = len(dots) >= 1 and "контейнер создан" in text and os.path.isdir(TARGET)
print("ANIMATION-OK" if ok else "ANIMATION-FAIL")
sys.exit(0 if ok else 1)
