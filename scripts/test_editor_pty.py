#!/usr/bin/env python3
"""Тест полноэкранного редактора edit в настоящем pty (Linux).

Правка, ^S, выход ^X с вопросом (N и Y), прокрутка PgDn, длинная строка,
сохранение CRLF, автоблокировка посреди правки (верный и неверный пароль).
Содержимое проверяется через cat из контейнера, экран — эмулятором pyte.

Запуск:  BIN=$PWD/build-linux/foxvault python3 scripts/test_editor_pty.py
"""
import fcntl, os, pty, select, shutil, struct, subprocess, sys, tempfile, termios, time

HERE = os.path.dirname(os.path.abspath(__file__))
BIN = os.environ.get("BIN") or os.path.join(HERE, "..", "build-linux", "foxvault")
PASS = "edit-pass-123456"
COLS, ROWS = 80, 24

try:
    import pyte
except ImportError:
    pyte = None

UP, DOWN, LEFT, RIGHT = b"\x1b[A", b"\x1b[B", b"\x1b[D", b"\x1b[C"
HOME, END, PGDN, PGUP, DEL = b"\x1b[H", b"\x1b[F", b"\x1b[6~", b"\x1b[5~", b"\x1b[3~"
CTRL_S, CTRL_X, ENTER, BS, ESC = b"\x13", b"\x18", b"\r", b"\x7f", b"\x1b"

fails = 0
ALL_OUT = []                                     # вывод всех сессий: ищем отчёты ASan


def check(cond, what):
    global fails
    print(("  ok  - " if cond else "  FAIL- ") + what)
    if not cond:
        fails += 1


class Sess:
    def __init__(self, vault, idle=None):
        env = dict(os.environ, TERM="xterm")
        env["FV_IDLE_TIMEOUT"] = str(idle) if idle is not None else "0"
        self.pid, self.fd = pty.fork()
        if self.pid == 0:
            os.execve(BIN, [BIN, "open", vault], env)
        fcntl.ioctl(self.fd, termios.TIOCSWINSZ, struct.pack("HHHH", ROWS, COLS, 0, 0))
        self.out = bytearray()
        ALL_OUT.append(self.out)
        self.screen = pyte.Screen(COLS, ROWS) if pyte else None
        self.stream = pyte.ByteStream(self.screen) if pyte else None

    def pump(self, t=0.15):
        end = time.time() + t
        while time.time() < end:
            r, _, _ = select.select([self.fd], [], [], 0.03)
            if r:
                try:
                    d = os.read(self.fd, 65536)
                except OSError:
                    return
                if not d:
                    return
                self.out.extend(d)
                if self.stream:
                    self.stream.feed(d)

    def wait(self, token, t=10):
        end = time.time() + t
        while token.encode() not in self.out and time.time() < end:
            self.pump(0.1)
        return token.encode() in self.out

    def wait_since(self, mark, token, t=30):
        """ждать token в выводе после позиции mark (а не где угодно раньше)"""
        end = time.time() + t
        tok = token.encode()
        while tok not in self.out[mark:] and time.time() < end:
            self.pump(0.1)
        return tok in self.out[mark:]

    def keys(self, *parts, pause=0.08):
        for p in parts:
            os.write(self.fd, p if isinstance(p, bytes) else p.encode())
            self.pump(pause)

    def rows(self):
        return [l.rstrip() for l in self.screen.display] if self.screen else []

    def mark(self):
        return len(self.out)

    def since(self, m):
        return bytes(self.out[m:]).decode("utf-8", "replace")

    def close(self, t=20):
        """дождаться выхода процесса; не дождались — убить и сообщить"""
        end = time.time() + t
        while time.time() < end:
            self.pump(0.1)
            try:
                pid, _ = os.waitpid(self.pid, os.WNOHANG)
            except ChildProcessError:
                pid = self.pid
            if pid:
                break
        else:
            os.kill(self.pid, 9)
            os.waitpid(self.pid, 0)
            tail = bytes(self.out[-400:]).decode("utf-8", "replace")
            check(False, "процесс не завершился; хвост вывода: " + repr(tail))
        try:
            os.close(self.fd)
        except OSError:
            pass


def vault_cat(vault, path):
    """содержимое файла контейнера (байты) — между приглашениями shell"""
    r = subprocess.run([BIN, "open", vault],
                       input=f"{PASS}\ncat {path}\nexit\n".encode(), capture_output=True)
    ALL_OUT.append(r.stderr)
    p = "foxvault:/> ".encode()
    out = r.stdout
    a = out.find(p) + len(p)
    b = out.rfind(p)
    return out[a:b]


def put(vault, host, dst):
    subprocess.run([BIN, "open", vault], input=f"{PASS}\nput {host} {dst}\nexit\n".encode(),
                   capture_output=True)


def main():
    if not os.access(BIN, os.X_OK):
        print("нет бинарника:", BIN)
        return 2
    tmp = tempfile.mkdtemp(prefix="fv-ed-")
    vault = os.path.join(tmp, "v")
    subprocess.run([BIN, "create", vault], input=f"{PASS}\n{PASS}\n".encode(),
                   capture_output=True, check=True)
    with open(os.path.join(tmp, "a.txt"), "w", encoding="utf-8") as f:
        f.write("первая строка\nвторая\nтретья\n")
    with open(os.path.join(tmp, "long.txt"), "w") as f:
        f.write("".join(f"line {i}\n" for i in range(1, 101)))
    with open(os.path.join(tmp, "crlf.txt"), "wb") as f:
        f.write(b"one\r\ntwo\r\n")
    for n in ("a.txt", "long.txt", "crlf.txt"):
        put(vault, os.path.join(tmp, n), "/")

    print("== правка и сохранение")
    s = Sess(vault)
    s.wait("Пароль:")
    s.keys(PASS + "\r")
    s.wait("foxvault:/>")
    m = s.mark()
    s.keys("edit /a.txt\r", pause=0.4)
    rows = s.rows()
    check("\x1b[?1049h" in s.since(m), "альтернативный экран включён")
    if pyte:
        check(rows[0] == "первая строка" and rows[1] == "вторая", "текст файла на экране")
        check("/a.txt" in rows[ROWS - 2] and "строка 1/3" in rows[ROWS - 2], "строка состояния")
        check("^S Сохранить" in rows[ROWS - 1] and "^X Выход" in rows[ROWS - 1], "подсказка клавиш")
    s.keys(DOWN, END, " +", "ё")                 # вторая +ё
    s.keys(HOME, "[", RIGHT, RIGHT, DEL)         # [вт|о|рая -> [втрая... (удалён «о»)
    s.keys(DOWN, END, ENTER, "новая")            # после «третья» — новая строка
    s.keys(UP, UP, UP, END, BS, BS)              # «первая строка» -> «первая стро»
    if pyte:
        check("[изменён]" in s.rows()[ROWS - 2], "пометка [изменён]")
    s.keys(CTRL_S, pause=0.4)
    if pyte:
        check("сохранено" in s.rows()[ROWS - 1], "сообщение «сохранено»")
        check("[изменён]" not in s.rows()[ROWS - 2], "пометка снята после ^S")
    m = s.mark()
    s.keys(CTRL_X, pause=0.4)
    check("\x1b[?1049l" in s.since(m), "^X без правок выходит сразу, экран восстановлен")
    s.wait("foxvault:/>")
    got = vault_cat_in(s, "/a.txt")
    check(got == "первая стро\n[втрая +ё\nтретья\nновая\n", "содержимое после ^S: " + repr(got))

    print("== выход с вопросом")
    s.keys("edit /a.txt\r", pause=0.4)
    s.keys("ЛИШНЕЕ", CTRL_X, pause=0.3)
    if pyte:
        check("Сохранить изменения?" in s.rows()[ROWS - 1], "вопрос при несохранённых правках")
    s.keys(ESC, pause=0.3)                       # вернуться в редактор
    if pyte:
        check(s.rows()[0].startswith("ЛИШНЕЕ"), "Esc возвращает к правке")
    s.keys(CTRL_X, "n", pause=0.4)
    s.wait("foxvault:/>")
    got = vault_cat_in(s, "/a.txt")
    check("ЛИШНЕЕ" not in got, "N — выход без сохранения")
    s.keys("edit /a.txt\r", pause=0.4)
    s.keys(END, "!", CTRL_X, "y", pause=0.4)
    s.wait("foxvault:/>")
    got = vault_cat_in(s, "/a.txt")
    check(got.startswith("первая стро!\n"), "Y — сохранить и выйти")

    print("== прокрутка, длинная строка, новый файл")
    s.keys("edit /long.txt\r", pause=0.4)
    s.keys(PGDN, PGDN, pause=0.2)
    if pyte:
        r = s.rows()
        check("строка 43/100" in r[ROWS - 2], "PgDn ×2 -> строка 43: " + r[ROWS - 2].strip()[-14:])
        check("line 43" in r, "видна строка 43")
    s.keys(PGUP, pause=0.2)
    s.keys(END, "x" * 120, pause=0.02)           # строка шире экрана
    s.pump(0.6)                                  # дождаться последней перерисовки
    if pyte:
        r = s.rows()
        check(any(l.endswith("x" * 40) for l in r), "горизонтальная прокрутка длинной строки")
    s.keys(CTRL_S, CTRL_X, pause=0.4)
    s.wait("foxvault:/>")
    got = vault_cat_in(s, "/long.txt")
    check(("line 22" + "x" * 120 + "\n") in got and got.count("\n") == 100,
          "длинная строка сохранена целиком")
    s.keys("edit /новый.md\r", pause=0.4)
    if pyte:
        check("[новый]" in s.rows()[ROWS - 2], "новый файл помечен [новый]")
    s.keys("# Заголовок", ENTER, "текст", CTRL_S, CTRL_X, pause=0.4)
    s.wait("foxvault:/>")
    check(vault_cat_in(s, "/новый.md") == "# Заголовок\nтекст\n", "новый файл создан")

    print("== CRLF")
    s.keys("edit /crlf.txt\r", pause=0.4)
    s.keys(END, "!", CTRL_S, CTRL_X, pause=0.4)
    s.wait("foxvault:/>")
    s.keys("exit\r", pause=0.3)
    s.close()
    check(vault_cat(vault, "/crlf.txt").endswith(b"one!\r\ntwo\r\n"), "окончания CRLF сохранены")

    print("== автоблокировка в редакторе")
    s = Sess(vault, idle=2)
    s.wait("Пароль:")
    s.keys(PASS + "\r")
    s.wait("foxvault:/>")
    s.keys("edit /a.txt\r", pause=0.4)
    s.keys(HOME, "ДО-БЛОКИРОВКИ ")
    m = s.mark()
    s.wait_since(m, "пароль:", t=15)            # простой > 2 с
    after = s.since(m)
    check("автоблокировка" in after and "пароль:" in after, "по простою спрашивает пароль")
    check("\x1b[?1049l" in after, "текст файла убран с экрана перед вопросом")
    m = s.mark()
    s.keys(PASS + "\r")
    back = s.wait_since(m, "\x1b[?1049h")       # снова в редакторе
    s.pump(0.3)
    check(back, "после пароля редактор открывается снова")
    if pyte:
        check(s.rows()[0].startswith("ДО-БЛОКИРОВКИ "), "после пароля правки на месте")
    m = s.mark()
    s.keys(CTRL_S)
    s.wait_since(m, "сохранено")
    m = s.mark()
    s.keys(CTRL_X)
    s.wait_since(m, "foxvault:/>")
    s.keys("exit\r", pause=0.3)
    s.close()
    check(vault_cat(vault, "/a.txt").decode().startswith("ДО-БЛОКИРОВКИ "),
          "правка до блокировки сохранена")

    s = Sess(vault, idle=2)
    s.wait("Пароль:")
    s.keys(PASS + "\r")
    s.wait("foxvault:/>")
    s.keys("edit /a.txt\r", pause=0.4)
    s.keys(HOME, "НЕ-ДОЛЖНО ")
    m = s.mark()
    for _ in range(3):
        s.wait_since(m, "пароль:", t=15)         # вводим только когда спросили
        m = s.mark()
        s.keys("wrong-password\r")
    s.close()
    txt = bytes(s.out).decode("utf-8", "replace")
    check("несохранённые правки стёрты" in txt, "3 неверных пароля — выход из shell")
    check("НЕ-ДОЛЖНО" not in vault_cat(vault, "/a.txt").decode(), "несохранённое не записано")

    san = [b for b in ALL_OUT if b"Sanitizer" in b or b"runtime error" in b]
    check(not san, "нет отчётов AddressSanitizer/UBSan" + (": " + repr(bytes(san[0][-300:])) if san else ""))

    shutil.rmtree(tmp, ignore_errors=True)
    print("ИТОГО:", "PASS" if not fails else f"FAIL={fails}")
    return 1 if fails else 0


def vault_cat_in(s, path):
    """cat внутри уже открытой сессии: вывод между командой и приглашением"""
    m = s.mark()
    s.keys(f"cat {path}\r", pause=0.3)
    s.wait("foxvault:/>")
    txt = s.since(m).replace("\r\n", "\n")
    start = txt.find("\n") + 1                   # после эха команды
    end = txt.rfind("foxvault:/>")
    return txt[start:end]


if __name__ == "__main__":
    sys.exit(main())
