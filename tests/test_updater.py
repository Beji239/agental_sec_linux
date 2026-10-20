"""
tests/test_updater.py, the update check and the Update button.

No network and no password: GitHub's answer is handed in, and the commands
the button runs are recorded instead of run, except the command runner
itself, which is tried on small scripts. What is asserted:

  1. the kind of update is read from the two numbers, security from the title
  2. a failed check keeps the last answer and says it could not check
  3. only the running app asks GitHub or starts a job
  4. the button runs update.sh, then the launchers and the root step only
     when needed, then restarts; a failed step stops what comes after it
  5. the root step's exit codes become plain reasons with the command to run
  6. the daily switch is read from config.json and written there
"""
import json
import os
import pathlib
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import _isolate_db                                      # noqa: E402
_isolate_db.isolate()

from core import updater, version                       # noqa: E402

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}"
          + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


CURRENT = version.current()["version"]
major, minor, patch = (int(x) for x in CURRENT.split("."))
NEXT_PATCH = f"{major}.{minor}.{patch + 1}"
NEXT_MINOR = f"{major}.{minor + 1}.0"

print("the kind of update")
check("patch", updater.kind_of("2.6.1", "2.6.2"), "patch")
check("minor", updater.kind_of("2.6.1", "v2.7.0"), "minor")
check("major", updater.kind_of("2.6.1", "3.0.0"), "major")
check("same", updater.kind_of("2.6.1", "2.6.1"), "none")
check("older", updater.kind_of("2.6.1", "2.5.9"), "none")
check("unreadable", updater.kind_of("2.6.1", "latest"), None)
check("a label with commits is not a number", updater.parse_version("2.6.1 +3"), None)


def release(tag, title=None, url=None, body="Notes"):
    return {"tag_name": tag, "name": title or f"AgentalSec {tag}",
            "body": body, "published_at": "2026-10-20T10:00:00Z",
            "html_url": url or f"https://github.com/{updater.REPO}/releases/tag/{tag}"}


s = updater.summarise(release("v2.7.0", "Security fix for the router agent"))
check("security from the title", s["security"], True)
check("version without the v", s["version"], "2.7.0")
s = updater.summarise(release("v2.7.0", "Faster", body="security everywhere"))
check("security in the notes alone does not count", s["security"], False)
s = updater.summarise(release("v2.7.0", url="https://evil.example/x"))
check("a link off the repository becomes the releases page", s["url"],
      updater.RELEASES_PAGE)
try:
    updater.summarise(release("nightly"))
    check("a tag that is no version is refused", False, True)
except updater.CheckFailed:
    check("a tag that is no version is refused", True, True)

print("checks and what they keep")
updater._save({})
check("nothing asked before the first check", updater.status()["checked_at"], None)
res = updater.check_now(lambda: release(f"v{NEXT_MINOR}"))
check("a good answer", res["ok"], True)
st = updater.status()
check("newer release is available", st["available"], True)
check("its kind", st["kind"], "minor")


def failing():
    raise updater.CheckFailed("GitHub could not be reached (ConnectionError)")


res = updater.check_now(failing)
st = updater.status()
check("a failed check says so", (res["ok"], st["check_ok"]), (False, False))
check("and names why", "could not be reached" in st["check_error"], True)
check("the last answer stays", st["release"]["version"], NEXT_MINOR)
check("still shown as available", st["available"], True)
updater.check_now(lambda: release(f"v{CURRENT}"))
st = updater.status()
check("the running version is not an update", (st["available"], st["kind"]),
      (False, "none"))
check("a good check clears the error", st["check_error"], "")

now = time.time()
check("due a day after a good check",
      updater._due({"ok": True, "checked_at": now - 86500}, now), True)
check("not due an hour after a good check",
      updater._due({"ok": True, "checked_at": now - 3600}, now), False)
check("a failed check is retried after three hours",
      updater._due({"ok": False, "checked_at": now - 3 * 3600 - 5}, now), True)
check("a clock set back makes it due",
      updater._due({"ok": True, "checked_at": now + 9999}, now), True)

print("only the running app")
updater.LIVE = False
res = updater.check_now()
check("check refused outside the app, no network", res["ok"], False)
check("job refused outside the app", updater.start_job("update")["started"], False)
updater.LIVE = True
os.environ["AGENTALSEC_TEST_DB"] = os.environ.get("AGENTALSEC_TEST_DB") or "x"
check("job refused in a test run", updater.start_job("helpers")["started"], False)
check("unknown job refused", updater.start_job("rm")["started"], False)
updater.LIVE = False

tmp = pathlib.Path(tempfile.mkdtemp(prefix="updater."))
check("no git clone, no update",
      "not a git clone" in updater.can_update(tmp)["reason"], True)

print("the button, with the commands recorded")
UPDATE_OUT = """Looking for updates on main...

Waiting to be installed:
  A change

Code updated to v2.7.0.
Installing the Python packages...

These root helpers need installing again: ./scripts/install_action_helper.sh

Updated to AgentalSec 2.7.0.
Done. What is left:
  - Restart AgentalSec: close it, then start it again from its icon.
    The database updates itself at that start.
  - The launchers changed. Run: ./scripts/install_launchers.sh
  - Run: sudo ./scripts/install_action_helper.sh --apply
  - The router agent changed. Run: ./scripts/install_gateway_agent.sh --enroll 192.0.2.1
  Your config.json is not changed: a new setting keeps its default until you change it in Settings.
"""
check("leftover keeps only what the button does not do",
      updater.leftover(UPDATE_OUT),
      ["The router agent changed. Run: ./scripts/install_gateway_agent.sh --enroll 192.0.2.1"])

calls, restarts = [], []
real_run, real_behind = updater._run, updater.helpers_behind
real_which = updater.shutil.which
updater.shutil.which = lambda name: "/usr/bin/" + name


def fake(results):
    def run(cmd, timeout, first_line_wait=None, env=None):
        calls.append([os.path.basename(c) for c in cmd])
        for key, value in results.items():
            if any(key in c for c in cmd):
                return value
        return 0, ""
    return run


def job(results, behind=(), what="update"):
    calls.clear()
    restarts.clear()
    updater._run = fake(results)
    updater.helpers_behind = lambda root=None: list(behind)
    updater.RESTART = lambda reason: restarts.append(reason)
    updater._job.update(running=True, log=[], todo=[])
    real_sleep = updater.time.sleep
    updater.time.sleep = lambda s: None
    try:
        updater._worker(what)
    finally:
        updater.time.sleep = real_sleep
    return dict(updater._job)


j = job({"update.sh": (0, UPDATE_OUT), "pkexec": (0, "")},
        behind=["install_action_helper.sh"])
check("update.sh, launchers, root step, in that order",
      [c[0] if c[0] != "bash" else c[1] for c in calls],
      ["update.sh", "install_launchers.sh", "pkexec"])
check("root step is refresh_helpers --apply",
      calls[2][1:3], ["refresh_helpers.sh", "--apply"])
check("the update finished well", (j["ok"], j["running"]), (True, False))
check("and restarts", (j["restarting"], len(restarts)), (True, 1))
check("the router line is left for the owner",
      [t for t in j["todo"] if "router" in t] != [], True)

j = job({"update.sh": (0, "Already up to date: AgentalSec 2.6.1.\n")})
check("up to date: nothing else runs, no restart",
      (len(calls), j["restarting"], len(restarts), j["ok"]), (1, False, 0, True))

j = job({"update.sh": (1, "update: could not reach the repository.\n")},
        behind=["install_action_helper.sh"])
check("update.sh failing stops everything after it",
      (len(calls), j["ok"], len(restarts)), (1, False, 0))
check("and says so", "did not finish" in j["result"], True)

j = job({"update.sh": (0, UPDATE_OUT), "pkexec": (126, "")},
        behind=["install_action_helper.sh"])
check("dialog closed: the code still restarts", len(restarts), 1)
check("dialog closed: not a clean finish", j["ok"], False)
check("dialog closed: the command by hand is first in the list",
      "refresh_helpers.sh --apply" in j["todo"][0], True)

j = job({"pkexec": (0, "")}, behind=["install_capture_service.sh"], what="helpers")
check("Reinstall helpers runs only the root step",
      [c[0] for c in calls], ["pkexec"])
check("and does not restart", (j["ok"], len(restarts)), (True, 0))

updater._job.update(running=False, finished_at=None, result="", log=[])
kept = updater.status()["job"]
check("the outcome is kept for after the restart",
      (kept["result"], kept["running"]), (j["result"], False))

for code, words in (("no_output", "No password was given"),
                    (127, "dialog was closed"), (2, "exit 2"),
                    (None, "could not be started")):
    updater._run = fake({"pkexec": (code, "")})
    ok, why = updater._root_refresh(False)
    check(f"root step {code!r} explained", (ok, words in why), (False, True))
updater._run = fake({"pkexec": (0, "")})
calls.clear()
updater._root_refresh(True)
check("--audit passed along", calls[-1][-1], "--audit")

updater._run, updater.helpers_behind, updater.RESTART = real_run, real_behind, None
updater.shutil.which = real_which

print("the command runner")
script = tmp / "talk.sh"
script.write_text("echo one\necho two >&2\nexit 3\n")
code, out = updater._run(["bash", str(script)], 20)
check("output and exit code", (code, out.splitlines()), (3, ["one", "two"]))
script.write_text("sleep 30\n")
t0 = time.time()
code, _ = updater._run(["bash", str(script)], 60, first_line_wait=1)
check("silent command ended at the wait", code, "no_output")
check("and quickly", time.time() - t0 < 15, True)
script.write_text("echo started\nsleep 30\n")
code, out = updater._run(["bash", str(script)], 2, first_line_wait=1)
check("a command that talks then hangs ends at the timeout", (code, out), ("timeout", "started"))

print("the daily switch")
from core import settings                               # noqa: E402
real_cfg = settings.CONFIG_PATH
cfg = tmp / "config.json"
settings.CONFIG_PATH = cfg
try:
    check("no config file: on", updater.enabled(), True)
    cfg.write_text(json.dumps({"flask": {"port": 5000}}))
    check("not set: on", updater.enabled(), True)
    check("switched off", updater.set_enabled(False), None)
    check("reads off", updater.enabled(), False)
    check("other settings kept", json.loads(cfg.read_text())["flask"], {"port": 5000})
    updater.set_enabled(True)
    check("reads on again", updater.enabled(), True)
finally:
    settings.CONFIG_PATH = real_cfg

print("\n" + ("ALL PASS" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
