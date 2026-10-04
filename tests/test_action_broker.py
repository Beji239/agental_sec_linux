"""
tests/test_action_broker.py: the app's side of the root session.

pkexec is replaced by running the helper's serve loop directly, so this runs
unelevated and asks for no password. What is asserted:

  1. not installed is a refusal with the fix named, and nothing starts
  2. one session serves every call of a run (the password is asked once)
  3. a session past its cap is replaced by a new one, and the call still runs
  4. a request the helper received and never answered is NOT resent
  5. close() ends the session
"""
import os
import pathlib
import stat
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}" + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


from tools import action_broker as ab  # noqa: E402

tmp = pathlib.Path(tempfile.mkdtemp())
starts = tmp / "starts"


def fake_helper(body: str) -> str:
    path = tmp / f"helper_{len(list(tmp.iterdir()))}.py"
    path.write_text(f"""#!{sys.executable}
import sys
sys.path.insert(0, {str(ROOT)!r})
open({str(starts)!r}, "a").write("x")
from tools import action_helper as ah
ah.LOG_DIR = {str(tmp / 'log')!r}
ah.LOG_PATH = {str(tmp / 'log' / 'l')!r}
{body}
""")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return str(path)


ab.LAUNCHER = []
ab._max_age_hours = lambda: 1.0

print("\n[0] only the running app may open a root session")
reply = ab.call("list_blocks")
check("a process that is not the app is refused before anything starts",
      (reply["ok"], "only used by the running app" in reply["refused"],
       starts.exists()), (False, True, False))
ab.LIVE = True
os.environ["AGENTALSEC_TEST_DB"] = "/tmp/x.db"
reply = ab.call("list_blocks")
check("and so is any run with a test database",
      "test run" in reply["refused"], True)
del os.environ["AGENTALSEC_TEST_DB"]

print("\n[1] not installed")
ab.HELPER_PATH = str(tmp / "absent.py")
reply = ab.call("list_blocks")
check("refused, with the install command named",
      (reply["ok"], "install_action_helper.sh" in reply["refused"]), (False, True))
check("and nothing was started", starts.exists(), False)

ab.installed = lambda: {"installed": True, "problems": [], "fix": ""}

print("\n[2] one session per run")
ab.HELPER_PATH = fake_helper("ah.serve(float(sys.argv[3]))")
first = ab.call("block_ip", "127.0.0.1")
pid = ab._state["proc"].pid
second = ab.call("list_quarantine")
check("both calls answered", (first["verb"], second["verb"]),
      ("block_ip", "list_quarantine"))
check("by the same session", ab._state["proc"].pid, pid)
check("which was started once", starts.read_text(), "x")
check("status reports it open", ab.status()["session_open"], True)

print("\n[3] the cap")
ab.close()
ab._max_age_hours = lambda: 0.0000001
ab.call("list_quarantine")
before = ab._state["proc"].pid
import time  # noqa: E402
time.sleep(0.1)
ab._max_age_hours = lambda: 1.0
reply = ab.call("list_quarantine")
check("past the cap the call still runs", reply.get("verb"), "list_quarantine")
check("in a new session", ab._state["proc"].pid != before, True)
ab.close()
ab._max_age_hours = lambda: 1.0

print("\n[4] delivered and not answered")
starts.unlink()
ab.CALL_TIMEOUT_SECONDS = 2
ab.HELPER_PATH = fake_helper("""
import json
print(json.dumps({"ready": True}), flush=True)
sys.stdin.readline()
import time
time.sleep(30)
""")
reply = ab.call("kill", "4242", "sleep", "1")
check("the outcome is reported as unknown", reply.get("unknown"), True)
check("and the request was not sent to a second session", starts.read_text(), "x")

print("\n[5] close")
ab._state["proc"] = None
ab.HELPER_PATH = fake_helper("ah.serve(float(sys.argv[3]))")
ab.call("list_quarantine")
proc = ab._state["proc"]
ab.close()
check("closing the pipe ends the helper", proc.poll(), 0)

print()
if fails:
    print(f"{len(fails)} FAILED: {fails}")
    sys.exit(1)
print("all passed")
