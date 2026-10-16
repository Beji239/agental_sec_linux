"""
tests/test_log_injection.py, outside text cannot forge a log line or drive
the terminal.

A device on the network names itself, a DNS answer names a domain, a process
names itself, and all of them reach log messages. A newline there would add a
line that reads as the app's own, and an escape code would reach the terminal
the launcher opens. Every handler formats through core.log_format.SafeFormatter.
"""
import io
import logging
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.log_format import SafeFormatter  # noqa: E402

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}"
          + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


FMT = "%(asctime)s [%(name)s] %(levelname)s: %(message)s"
out = io.StringIO()
handler = logging.StreamHandler(out)
handler.setFormatter(SafeFormatter(FMT, datefmt="%H:%M:%S"))
log = logging.getLogger("test.log_injection")
log.propagate = False
log.addHandler(handler)
log.setLevel(logging.INFO)

print("[1] a hostile name stays on its own line")
host = ("printer\n2026-10-15 21:00:00 [core.duty] INFO: Duty run: nothing "
        "needed doing\r")
log.info("New device on the LAN: %s", host)
log.info(f"f-string form too: {host}")
lines = out.getvalue().splitlines()
check("two messages are two lines", len(lines), 2)
check("the forged line is visible as data", "\\x0a2026-10-15" in lines[0], True)
check("a carriage return is escaped", "\\x0d" in lines[0], True)

print("\n[2] terminal and display tricks")
out.seek(0)
out.truncate()
log.info("proc \x1b[2J\x1b[31mred\x1b[0m bell\x07 nel\x85 ls  rlo‮moc.evil")
line = out.getvalue()
check("still one line", line.count("\n"), 1)
check("no escape character reaches the output", "\x1b" in line, False)
check("no bell", "\x07" in line, False)
check("the Unicode separators are escaped",
      ("\\x85" in line, "\\u2028" in line), (True, True))
check("a right-to-left override is escaped", "\\u202e" in line, True)
check("tabs and ordinary text are left alone",
      SafeFormatter("%(message)s").format(logging.makeLogRecord(
          {"msg": "a\tb é ✓", "levelname": "INFO"})), "a\tb é ✓")

print("\n[3] a traceback keeps its lines")
out.seek(0)
out.truncate()
try:
    raise ValueError("boom\nsecond line of the message")
except ValueError:
    log.exception("failed on %s", "x\ny")
text = out.getvalue()
check("the message line is escaped", "failed on x\\x0ay" in text, True)
check("the traceback follows on its own lines",
      "Traceback (most recent call last):" in text.splitlines()[1], True)

print("\n[4] main.py formats every handler this way")
src = (ROOT / "main.py").read_text(encoding="utf-8")
check("the console handler", "_h.setFormatter(SafeFormatter(" in src, True)
check("the log file", "_file_handler.setFormatter(\n            SafeFormatter("
      in src, True)
check("and no plain Formatter is left", "logging.Formatter(" in src, False)

print(f"\n{'ALL PASSED' if not fails else str(len(fails)) + ' FAILED'}")
sys.exit(1 if fails else 0)
