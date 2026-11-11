"""
tests/test_closing_wait.py, a start waits for the last copy to finish closing.

A copy that says it is closing, or that no longer answers while its pid file
names it, is waited for until its process ends. A copy that answers as
running is refused at once, and a start with nothing before it goes ahead.
Runs against a stand-in dashboard and a short sleep standing in for the copy.
"""
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}"
          + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


import main                                    # noqa: E402
import logging                                 # noqa: E402

# Kept out of the app's own log.
for _h in list(logging.getLogger().handlers):
    if isinstance(_h, logging.FileHandler):
        logging.getLogger().removeHandler(_h)
        _h.close()

tmp = pathlib.Path(tempfile.mkdtemp(prefix="closingwait_"))
main._PID_FILE = tmp / "agentalsec.pid"


def copy(seconds):
    """A process named like the app that ends after `seconds`."""
    script = tmp / "main.py"
    script.write_text(f"import time\ntime.sleep({seconds})\n")
    p = subprocess.Popen([sys.executable, str(script)])
    threading.Thread(target=p.wait, daemon=True).start()
    time.sleep(0.3)
    return p


state = {"answer": None, "closing": True, "pid": 0}


class Dashboard(BaseHTTPRequestHandler):
    def do_GET(self):
        if state["answer"] is False:
            time.sleep(4)                       # busy, past the 3 s timeout
        body = json.dumps({"pid": state["pid"],
                           "shutting_down": state["closing"]}).encode()
        try:
            self.send_response(200 if self.headers.get("X-API-Key") == "k"
                               else 401)
            self.end_headers()
            self.wfile.write(body)
        except OSError:
            pass                                # the caller gave up first

    def log_message(self, *a):
        pass


srv = HTTPServer(("127.0.0.1", 0), Dashboard)
PORT = srv.server_port
threading.Thread(target=srv.serve_forever, daemon=True).start()

print("\n[1] a copy that says it is closing")
p = copy(2)
state.update(answer=True, closing=True, pid=p.pid)
t = time.time()
check("waited for it", main._wait_for_closing_copy("127.0.0.1", PORT, "k",
                                                   True), True)
check("until its process ended", time.time() - t >= 1.0, True)

print("\n[2] a copy that answers as running")
p = copy(5)
state.update(answer=True, closing=False, pid=p.pid)
main._PID_FILE.write_text(f"{p.pid}\n")
t = time.time()
check("refused, not waited for",
      main._wait_for_closing_copy("127.0.0.1", PORT, "k", True), False)
check("at once", time.time() - t < 3.5, True)

print("\n[3] a copy closing from a signal, silent, named by the pid file")
state.update(answer=False)
p = copy(6)
main._PID_FILE.write_text(f"{p.pid}\n")
check("waited for it",
      main._wait_for_closing_copy("127.0.0.1", PORT, "k", True), True)

print("\n[4] a copy that already let the port go")
p = copy(2)
main._PID_FILE.write_text(f"{p.pid}\n")
check("waited for it",
      main._wait_for_closing_copy("127.0.0.1", 1, "k", False), True)

print("\n[5] nothing before this start")
check("an ended pid goes ahead",
      main._wait_for_closing_copy("127.0.0.1", 1, "k", False), False)
main._PID_FILE.write_text(f"{os.getpid()}\n")
check("its own pid goes ahead",
      main._wait_for_closing_copy("127.0.0.1", 1, "k", False), False)
main._PID_FILE.unlink()
check("no pid file goes ahead",
      main._wait_for_closing_copy("127.0.0.1", 1, "k", False), False)

print("\n[6] the pid file")
main._write_pid_file()
check("names this process", main._PID_FILE.read_text().strip(),
      str(os.getpid()))
check("readable by everyone", oct(main._PID_FILE.stat().st_mode & 0o777),
      "0o644")

srv.shutdown()
print(f"\n{'ALL PASSED' if not fails else f'{len(fails)} FAILED: {fails}'}")
sys.exit(1 if fails else 0)
