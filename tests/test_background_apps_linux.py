"""
tests/test_background_apps_linux.py: background apps on Linux.

Which owner a process has, the tier it gets, what the page may offer, and
that block, disable and undo are refused by tier, journalled first, rolled
back on failure and undone exactly. Sources and the executor are fakes, so
nothing on this machine changes; the autostart override runs for real in a
scratch folder.
"""
import base64
import json
import pathlib
import sqlite3
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


tmp = pathlib.Path(tempfile.mkdtemp())
db = tmp / "t.db"
from core import memory_engine as me  # noqa: E402
me.DB_PATH = db
c = sqlite3.connect(db)
c.executescript((ROOT / "Schema.SQL").read_text(encoding="utf-8"))
c.commit()
c.close()
from core import migrations  # noqa: E402
migrations.run_migrations(db)
from tools import background_apps_linux as ba      # noqa: E402
from tools import background_actions_linux as bx   # noqa: E402

LIST = ba.validate_list({"entries": [
    {"kind": "service", "match": "kerneloops.service", "tier": "safe_to_block", "why": "crash uploads"},
    {"kind": "service", "match": "fwupd.service", "tier": "block_not_disable", "why": "firmware"},
    {"kind": "service", "match": "static-thing.service", "tier": "safe_to_block", "why": "static"},
    {"kind": "timer", "match": "motd-news.timer", "tier": "safe_to_block", "why": "news"},
    {"kind": "autostart", "match": "mintwelcome", "tier": "safe_to_block", "why": "welcome"},
    {"kind": "autostart", "match": "mintreport", "tier": "safe_to_block", "why": "reports"},
    {"kind": "process", "match": "kerneloops", "tier": "leave", "why": "pulled down"},
    {"kind": "service", "match": "bad"},
]})


print("\n[1] the list")
check("the malformed entry is rejected, by name", len(LIST["rejected"]), 1)
check("fnmatch, case insensitive", ba.list_match(LIST, "timer", "MOTD-news.timer")["tier"], "safe_to_block")
check("not listed is None", ba.list_match(LIST, "service", "ssh.service"), None)


print("\n[2] owners from cgroups and Exec lines")
check("system service", ba.owner_from_cgroup("/system.slice/kerneloops.service"),
      ("service", "kerneloops.service"))
check("user service", ba.owner_from_cgroup(
    "/user.slice/user-1000.slice/user@1000.service/app.slice/gvfs-daemon.service"),
      ("user_service", "gvfs-daemon.service"))
check("flatpak", ba.owner_from_cgroup(
    "/user.slice/user-1000.slice/user@1000.service/app.slice/app-flatpak-com.example.App-1234.scope"),
      ("flatpak", "com.example.App"))
check("session process has no owner here", ba.owner_from_cgroup(
    "/user.slice/user-1000.slice/session-2.scope"), None)
check("Exec with env", ba.exec_program("env GTK=1 /usr/bin/mintreport-tray %U"), "mintreport-tray")
check("Exec through sh -c", ba.exec_program("sh -c 'sleep 5; mintwelcome-launcher'"), "sleep")


print("\n[3] the verdict")
check("unknown process is leave", ba.verdict("process", "x", [{"name": "x", "pid": 99}], LIST)["tier"], "leave")
check("a core process is leave whatever the list says",
      ba.verdict("service", "kerneloops.service", [{"name": "systemd-journald", "pid": 9}], LIST)["tier"], "leave")
check("listed service keeps its tier",
      ba.verdict("service", "kerneloops.service", [], LIST)["tier"], "safe_to_block")
check("a process entry only pulls the tier down",
      ba.verdict("service", "kerneloops.service", [{"name": "kerneloops", "pid": 5}], LIST)["tier"], "leave")
check("an unread list calls nothing safe",
      ba.verdict("service", "kerneloops.service", [], {"read": False, "why_not": "x"})["tier"], "leave")


def usage(*procs):
    return {"read": True, "interval": 0, "unreadable": 0,
            "by_pid": {p["pid"]: {"exe": None, "cmd0": None, "cpu_percent": 1.0,
                                  "ram_mb": 10.0, **p} for p in procs}}


SERVICES = {"read": True, "why_not": None, "items": [
    {"name": "kerneloops.service", "description": "Kernel oops", "active": "active",
     "sub": "running", "unit_file_state": "enabled"},
    {"name": "fwupd.service", "description": "Firmware", "active": "active",
     "sub": "running", "unit_file_state": "static"},
    {"name": "static-thing.service", "description": "Static", "active": "active",
     "sub": "running", "unit_file_state": "static"},
    {"name": "ssh.service", "description": "SSH", "active": "active",
     "sub": "running", "unit_file_state": "enabled"}]}
TIMERS = {"read": True, "why_not": None, "items": [
    {"name": "motd-news.timer", "description": "news", "active": "active",
     "unit_file_state": "enabled", "triggers": ["motd-news.service"]}]}
home = tmp / "home"
(home / "autostart").mkdir(parents=True)
sysdir = tmp / "xdg"
sysdir.mkdir()
(sysdir / "mintreport.desktop").write_text(
    "[Desktop Entry]\nName=System Reports\nExec=mintreport-tray\n")
(sysdir / "mintwelcome.desktop").write_text(
    "[Desktop Entry]\nName=Welcome\nExec=mintwelcome-launcher\n")
AUTO = ba.read_autostart(system_dirs=(str(sysdir),), user_dir=home / "autostart")
EMPTY = {"read": True, "items": [], "why_not": None}


def snap():
    return ba.snapshot(
        usage=usage({"pid": 10, "name": "kerneloops", "cgroup": "/system.slice/kerneloops.service"},
                    {"pid": 11, "name": "fwupd", "cgroup": "/system.slice/fwupd.service"},
                    {"pid": 12, "name": "static-thing", "cgroup": "/system.slice/static-thing.service"},
                    {"pid": 13, "name": "sshd", "cgroup": "/system.slice/ssh.service"},
                    {"pid": 14, "name": "mintreport-tray", "cmd0": "mintreport-tray",
                     "cgroup": "/user.slice/user-1000.slice/session-2.scope"}),
        services=SERVICES, timers=TIMERS, autostart=AUTO, flatpaks=EMPTY,
        snaps=EMPTY, the_list=ba.validate_list({"entries": [
            e for e in LIST["entries"] if e["kind"] != "process"]}))


print("\n[4] the snapshot")
s = snap()
act = {(a["owner_kind"], a["owner_name"]): a for a in s["actionable"]}
check("the running safe service is actionable", ("service", "kerneloops.service") in act, True)
check("the login app is found by its program", ("autostart", "mintreport") in act, True)
check("an enabled login app that is not running is listed too",
      act.get(("autostart", "mintwelcome"), {}).get("running"), False)
check("the enabled timer is listed", ("timer", "motd-news.timer") in act, True)
check("an unlisted service is not actionable", ("service", "ssh.service") in act, False)
check("safe to block sorts first", s["actionable"][0]["tier"], "safe_to_block")
check("nothing unread", s["incomplete"], [])


print("\n[5] what the page may offer")
bx._is_root = lambda: True
ba.user_autostart_dir = lambda account=None: home / "autostart"
check("safe service: block and disable", bx.allowed(act[("service", "kerneloops.service")]),
      ["block", "disable"])
check("block_not_disable: block only", bx.allowed(act[("service", "fwupd.service")]), ["block"])
check("a static unit cannot be disabled", bx.allowed(act[("service", "static-thing.service")]),
      ["block"])
check("a login app: disable only", bx.allowed(act[("autostart", "mintreport")]), ["disable"])
check("a timer: disable only", bx.allowed(act[("timer", "motd-news.timer")]), ["disable"])
bx._is_root = lambda: False
check("not root: no system change is offered",
      bx.allowed(act[("service", "kerneloops.service")]), [])
check("but a login app still is", bx.allowed(act[("autostart", "mintreport")]), ["disable"])
bx._is_root = lambda: True


print("\n[6] the plan refuses what the tier refuses")
check("leave is refused", bx.plan("disable", "service", "ssh.service", snap=s)["ok"], False)
check("disable on block_not_disable is refused",
      "Block, do not disable" in (bx.plan("disable", "service", "fwupd.service", snap=s)["error"] or ""), True)
check("uninstall does not exist", bx.plan("uninstall", "service", "kerneloops.service", snap=s)["ok"], False)
p = bx.plan("disable", "service", "kerneloops.service", snap=s)
check("a safe service plans disable then stop",
      [st["do"]["op"] for st in p["steps"]], ["unit_file", "unit_run"])
check("and the start goes last on undo", p["steps"][1].get("undo_last"), True)


class Fake:
    def __init__(self, fail_on=None):
        self.calls, self.fail_on = [], fail_on

    def __getattr__(self, name):
        def call(**kw):
            self.calls.append((name, kw))
            if name == self.fail_on:
                raise RuntimeError("boom")
        return call


print("\n[7] apply journals first, then runs; undo puts it back")
ex = Fake()
out = bx.apply("disable", "service", "kerneloops.service", reason="test",
               requested_by="user", snap=s, executor=ex)
check("applied", out["ok"], True)
check("disable then stop", [(n, kw.get("state") or kw.get("action")) for n, kw in ex.calls],
      [("unit_file", "disable"), ("unit_run", "stop")])
ch = bx.list_changes()["changes"][0]
check("journalled as active, by the user", (ch["state"], ch["requested_by"]), ("active", "user"))
check("a second disable is refused", bx.plan("disable", "service", "kerneloops.service", snap=s)["ok"], False)
ex2 = Fake()
u = bx.undo(ch["id"], executor=ex2)
check("undo ok", u["ok"], True)
check("enable first, start last", [(n, kw.get("state") or kw.get("action")) for n, kw in ex2.calls],
      [("unit_file", "enable"), ("unit_run", "start")])
check("the row says undone", bx.list_changes()["changes"][0]["state"], "undone")

ex3 = Fake(fail_on="unit_run")
out = bx.apply("disable", "service", "kerneloops.service", snap=s, executor=ex3)
check("a failed step fails the change", out["ok"], False)
check("and rolls back the step before it", ex3.calls[-1], ("unit_file", {"unit": "kerneloops.service", "state": "enable"}))
check("recorded as failed", bx.list_changes()["changes"][0]["state"], "failed")


print("\n[7b] block cuts a service's network through systemd, and undo resets it")
no_rules = lambda unit: ("", "")
p = bx.plan("block", "service", "kerneloops.service", snap=s, ip_rules=no_rules)
check("one step: the unit's own network switch",
      [(st["do"]["op"], st["do"]["cut"], st["undo"]["cut"]) for st in p["steps"]],
      [("unit_net", True, False)])
check("a stopped service can be planned too (no cgroup needed)",
      bx.plan("block", "service", "fwupd.service", snap=s, ip_rules=no_rules)["ok"], True)
p = bx.plan("block", "service", "kerneloops.service", snap=s,
            ip_rules=lambda unit: ("", "10.0.0.0/8"))
check("rules set outside AgentalSec are left alone", p["ok"], False)
ex = Fake()
out = bx.apply("block", "service", "kerneloops.service", snap=s, executor=ex,
               ip_rules=no_rules)
check("blocked", (out["ok"], ex.calls), (True, [("unit_net", {"unit": "kerneloops.service", "cut": True})]))
ex = Fake()
check("undo ok", bx.undo(bx.list_changes()["changes"][0]["id"], executor=ex)["ok"], True)
check("undo resets the switch", ex.calls, [("unit_net", {"unit": "kerneloops.service", "cut": False})])


print("\n[8] a login app, with the real file operations in a scratch home")
real = bx.Executor()
real._own = lambda path: None
out = bx.apply("disable", "autostart", "mintreport", snap=s, executor=real)
check("applied", out["ok"], True)
override = home / "autostart" / "mintreport.desktop"
check("the user's copy hides it", "Hidden=true" in override.read_text(), True)
check("and keeps the rest of the entry", "Exec=mintreport-tray" in override.read_text(), True)
cid = bx.list_changes()["changes"][0]["id"]
check("undo ok", bx.undo(cid, executor=real)["ok"], True)
check("the copy we made is gone again", override.exists(), False)

override.write_text("[Desktop Entry]\nName=Mine\nExec=mintreport-tray --quiet\n")
before = override.read_bytes()
bx.apply("disable", "autostart", "mintreport", snap=snap(), executor=real)
cid = bx.list_changes()["changes"][0]["id"]
bx.undo(cid, executor=real)
check("a copy the user already had comes back byte for byte", override.read_bytes(), before)


print("\n[9] the model's tools are gated and the card shows the plan")
from core import tool_registry as tr  # noqa: E402
names = {t["name"] for t in tr.TOOL_MANIFEST}
check("all four tools exist", {"query_background_apps", "block_background_app",
                               "disable_background_app", "undo_background_change"} <= names, True)
check("the three changing tools are gated",
      all(tr.requires_permission(n, {}) for n in ("block_background_app",
          "disable_background_app", "undo_background_change")), True)
check("the read is not", tr.requires_permission("query_background_apps", {}), False)
routes = (ROOT / "api" / "routes.py").read_text(encoding="utf-8")
check("the page's five routes exist", all(r in routes for r in (
    '"/api/background_apps"', '"/api/background_apps/plan"', '"/api/background_apps/apply"',
    '"/api/background_apps/undo"', '"/api/background_apps/changes"')), True)
html = (ROOT / "ui" / "index.html").read_text(encoding="utf-8")
check("the card is on the Processes page", 'id="bg-apps-card"' in html, True)

print()
if fails:
    print(f"{len(fails)} FAILED: {fails}")
    sys.exit(1)
print("all passed")
