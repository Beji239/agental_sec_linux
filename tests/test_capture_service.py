"""
tests/test_capture_service.py, packet capture as its own service.

On a scratch database: the core captures itself only when no capture service
is installed or reporting; it reads the service's reports, and says it is
blind, with the reason, when they never came, stopped or went stale; the
sensor watch, the LAN checks and payload arming work through the reports;
the names helper's file names programs this account cannot read; the copy
check catches a root helper that differs from the project; and the real
capture loop runs in a network namespace and leaves its report.
"""
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import _isolate_db  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
db = _isolate_db.isolate()

from core import capture_service as cs  # noqa: E402
from core import memory_engine as me  # noqa: E402
from core import migrations  # noqa: E402
from core import root_copies  # noqa: E402
from core import sensor_watch  # noqa: E402
from core import tool_registry as tr  # noqa: E402

migrations.run_migrations(db)

failures = []


def check(label, ok, detail=""):
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}")
    if not ok:
        failures.append(label)
        print(f"        {detail}")


cs.UNIT_PATH = pathlib.Path(tempfile.mkdtemp()) / "agentalsec-capture.service"
STATUS = {"sniffer": {"running": True, "packets_this_run": 42,
                      "capture_state": {"alive": True}},
          "liveness": {"started": True, "running": True, "thread_alive": True,
                       "interval": 60, "last_ok_at": time.time(),
                       "started_at": time.time(), "consecutive_failures": 0},
          "tls_run_counts": {"hellos": 3},
          "lan_watch": {"has_looked": True, "notes": ["looked at 9 ARP"]}}


def age(seconds):
    with me._get_conn() as c:
        c.execute("UPDATE sensor_service SET reported_at = ? WHERE role = ?",
                  (cs._iso(time.time() - seconds), cs.ROLE))


print("\n[1] Who captures")
check("nothing installed or reporting: the core captures itself",
      cs.mode({}) == "in_process")
check("the config can say so outright",
      cs.mode({"capture": {"mode": "service"}}) == "service")
remote = cs.RemoteCapture()
st = remote.status()
check("with no report the stand-in is blind and says how to install",
      st.get("blind") and "install_capture_service" in st["blind_reason"], st)
cs.report(STATUS, time.time())
check("a fresh report: the service captures", cs.mode({}) == "service")
cs.UNIT_PATH.write_text("[Unit]\n")
cs.report(dict(STATUS), time.time(), stopped=True)
check("once installed, even a stopped service keeps the core from capturing "
      "twice", cs.mode({}) == "service")
cs.UNIT_PATH.unlink()
check("a stopped service that is not installed: the core captures",
      cs.mode({}) == "in_process")

print("\n[2] The core reads the reports")
cs.report(STATUS, time.time())
st = remote.status()
check("its status is the service's", st.get("packets_this_run") == 42
      and not st.get("blind") and "capture service" in st.get("where", ""), st)
check("the TLS counts too", remote.tls_run_counts() == {"hellos": 3})
check("the sensor watch reads it as collecting",
      sensor_watch.assess("packet_sniffer", remote)["state"] == "ok")
from core import capabilities, sensor_health  # noqa: E402
cap = capabilities.get().availability()["capture"]
check("capture counts as available, through the service",
      os.geteuid() == 0 or (cap["available"] and cap.get("via") ==
                            "the capture service"), cap)
check("so the packet tools carry no blind warning",
      not [w for w in sensor_health.warnings_for(
          "query_packets", {"packet_sniffer": remote})
          if "capture" in w.lower()],
      sensor_health.warnings_for("query_packets", {"packet_sniffer": remote}))
age(cs.STALE_SECONDS + 30)
st = remote.status()
check("a stale report is blind, with the age and what to check",
      st.get("blind") and "has not reported" in st["blind_reason"]
      and "systemctl status" in st["blind_reason"], st)
check("and the sensor watch says so",
      sensor_watch.assess("packet_sniffer", remote)["state"] == "quiet")
check("and the packet tools warn that capture is blind",
      sensor_health.warnings_for("query_packets", {"packet_sniffer": remote}))
cs.report(STATUS, time.time(), stopped=True)
check("a stopped service is blind and says when",
      "stopped at" in (remote.status().get("blind_reason") or ""))

print("\n[3] The model's tools work through the service")
cs.report(STATUS, time.time())
tr.init_registry("t", {"packet_sniffer": remote})
lan = tr._query_lan_watch()
check("the LAN checks come from the service",
      lan.get("running") and lan.get("where") == "the capture service"
      and lan.get("notes") == ["looked at 9 ARP"], lan)
armed = tr._dispatch("arm_payload_capture", {"destination": "198.51.100.9",
                                             "reason": "test"})
check("arming is accepted", armed.get("armed"), armed)
check("and saved where the service reloads it",
      "198.51.100.9" in (me.get_preference("payload_armed_destinations")
                         or ""))
from tools import payload_ring  # noqa: E402
ring = payload_ring.PayloadRing("svc")
me.set_preference("payload_armed_destinations", "198.51.100.10")
ring._load_armed()
check("the service side picks up a change", "198.51.100.10" in ring._armed)
tr.init_registry("t", {})

print("\n[4] The names helper names what this account cannot read")
from tools import names_helper, packet_sniffer_linux as sn  # noqa: E402
tmp = pathlib.Path(tempfile.mkdtemp())
names = tmp / "names.json"
snap = names_helper.snapshot()
snap["endpoints"]["tcp 203.0.113.77 4444"] = 1
snap["programs"]["1"] = {"comm": "rootthing", "cmdline": "/usr/sbin/rootthing",
                         "exe": "/usr/sbin/rootthing", "uid": 0}
names_helper.write(str(names), snap)
check("the file is written whole, readable", oct(names.stat().st_mode)[-3:]
      == "644" and json.loads(names.read_text())["endpoints"])
sn.NAMES_FILE = str(names)
index = {}
added, why = sn._names_from_helper(index)
check("its endpoints fill the index", why is None and index.get(
    ("203.0.113.77", 4444)) == 1 and added >= 1, (added, why))
sn._pid_info.clear()
real = sn.psutil.Process
sn.psutil.Process = lambda pid: (_ for _ in ()).throw(
    sn.psutil.AccessDenied(pid))
check("a program this account cannot read is named from the file",
      sn._describe_pid(1) == ("rootthing", "/usr/sbin/rootthing"))
sn.psutil.Process = real
old = json.loads(names.read_text())
old["written_at"] = time.time() - 60
names.write_text(json.dumps(old))
check("an old file is not trusted, and the note says why",
      "has not written" in (sn._names_from_helper({})[1] or ""))
sn.NAMES_FILE = str(tmp / "missing.json")
check("a missing helper says how to install it",
      "install_capture_service" in (sn._names_from_helper({})[1] or ""))

from tools import port_owner  # noqa: E402
listed = port_owner.list_sockets()["sockets"]
mine = port_owner.socket_owners()["owners"]
theirs = [x for x in listed if x["inode"] not in mine]
if theirs and os.geteuid() != 0:
    snap = names_helper.snapshot()
    snap["inodes"][theirs[0]["inode"]] = [1]
    snap["programs"]["1"] = {"comm": "init", "cmdline": "/sbin/init",
                             "exe": "/usr/lib/systemd/systemd", "uid": 0}
    snap["processes_unreadable"] = 0
    names_helper.write(str(names), snap)
    names_helper.NAMES_FILE = str(names)
    row = [r for r in port_owner.correlate()["sockets"]
           if r["inode"] == theirs[0]["inode"]]
    cov = port_owner.correlate()["coverage"]
    check("a socket of another account gets its owner from the helper",
          row and row[0]["pid"] == 1 and row[0]["exe"] ==
          "/usr/lib/systemd/systemd", row)
    check("and the coverage says the helper read every process",
          cov["processes_denied"] == 0 and cov["named_by_helper"] >= 1, cov)
else:
    print("  [SKIP] no socket of another account to test with")

print("\n[5] The root copies are compared with the project")
inst = pathlib.Path(tempfile.mkdtemp())
(inst / "ebpf").mkdir()
for _name, src, dst, _fix in root_copies.COPIES:
    shutil.copy(ROOT / src, inst / dst)
rows = root_copies.check(ROOT, inst)
check("all four match", all(r["matches"] for r in rows), rows)
(inst / "names_helper.py").write_text("# changed\n")
watch = root_copies.RootCopies(ROOT, inst)
a = sensor_watch.assess("root_helpers", watch)
check("a changed copy is reported, with the command that fixes it",
      a["state"] == "quiet" and "names helper" in a["reason"]
      and "install_capture_service.sh --apply" in a["reason"], a)
empty = root_copies.RootCopies(ROOT, pathlib.Path(tempfile.mkdtemp()))
check("nothing installed is off, not an alarm",
      sensor_watch.assess("root_helpers", empty)["state"] == "off")

print("\n[5b] The settings card describes the split")
from core import settings  # noqa: E402
cs.UNIT_PATH.write_text("[Unit]\n")
cs.report(STATUS, time.time())
parts = {"capture service": True, "names helper": True, "read helper": True,
         "action helper": True}
real_split = root_copies.split


def fake_split():
    return {"installed": True, "ok": all(parts.values()),
            "parts": [{"part": k, "holds": "its right", "ok": v,
                       "why": None if v else f"{k} is not there"}
                      for k, v in parts.items()]}


root_copies.split = fake_split
real_held = capabilities._held_by_helper
capabilities._held_by_helper = lambda name: "a helper"
if os.geteuid() != 0:
    rows = settings._privilege_rows()
    admin = [r for r in rows if r["title"] == "Administrator rights"][0]
    check("running as you is the design, not a problem",
          admin["state"] == "ok" and "Runs as you, by design" in
          admin["detail"], admin)
    check("and every capability is available through its helper",
          [r for r in rows if r["title"] == "Capabilities"
           and r["state"] == "ok" and "through a helper" in r["detail"]],
          rows)
    parts["read helper"] = False
    admin = [r for r in settings._privilege_rows()
             if r["title"] == "Administrator rights"][0]
    check("a missing helper is a problem, with what to do",
          admin["state"] == "problem" and "read helper is not there"
          in admin["fix"], admin)
root_copies.split = real_split
capabilities._held_by_helper = real_held
cs.UNIT_PATH.unlink()

print("\n[5c] The firewall is read through the read helper")
from tools import iptables_manager as fw, local_integrity as li  # noqa: E402
real_status, real_call, real_out = li.helper_status, li.helper_call, \
    fw._ufw_out
li.helper_status = lambda force=False: {"available": True,
                                        "verbs": ["firewall_rules"]}
li.helper_call = lambda verb, timeout=0: {"ok": True, "data": {
    "ufw_status": {"rc": 0, "stdout": "[ 1] 203.0.113.5 DENY IN Anywhere "
                   "# AgentalSec_block_203.0.113.5\n"},
    "ufw_added": {"rc": 0, "stdout": ""}}}
fw._ufw_out = lambda argv, timeout=0: (1, "", "You need to be root", None)
if os.geteuid() != 0:
    readable, text, why = fw._ufw_listing_text()
    check("ufw refuses, the helper's listing is used",
          readable and "AgentalSec_block_203.0.113.5" in text, (why, text))
li.helper_status, li.helper_call, fw._ufw_out = real_status, real_call, \
    real_out
check("the app may ask the helper for that verb",
      "firewall_rules" in open(li.__file__).read())

print("\n[5d] Failed logins are read through the read helper")
import base64  # noqa: E402
from tools import event_monitor_linux as em  # noqa: E402
recs = (bytes(range(256)) * 5)[:em.UTMP_SIZE * 3]
fake_st = type("St", (), {"st_ino": 77, "st_size": 9000})()
li.helper_status = lambda force=False: {"available": True,
                                        "verbs": ["btmp"]}
li.helper_call = lambda verb, timeout=0: {"ok": True, "data": {
    "ino": 77, "size": 9000, "start": 9000 - len(recs),
    "data_b64": base64.b64encode(recs).decode()}}
got = em._login_records_from_helper("btmp", fake_st,
                                    9000 - em.UTMP_SIZE * 2, 10)
check("the records from where the monitor stopped",
      got and got[1] == 9000 - em.UTMP_SIZE * 2
      and got[0] == recs[em.UTMP_SIZE:], got and (got[1], len(got[0])))
behind = em._login_records_from_helper("btmp", fake_st, 0, 10)
check("fallen behind, it starts where the helper's records start",
      behind and behind[1] == 9000 - len(recs))
check("another file (rotated) is not taken",
      em._login_records_from_helper(
          "btmp", type("St", (), {"st_ino": 78})(), 0, 10) is None)
check("wtmp never goes through the helper",
      em._login_records_from_helper("wtmp", fake_st, 0, 10) is None)
li.helper_status, li.helper_call = real_status, real_call

print("\n[6] A code change makes the service start again on the new code")
proj = pathlib.Path(tempfile.mkdtemp())
(proj / "VERSION").write_text("1\n")
before = cs.code_stamp(proj)
time.sleep(0.01)
(proj / "VERSION").write_text("2\n")
check("the stamp moves", cs.code_stamp(proj) != before)

print("\n[7] The capture loop itself, in a network namespace")
if shutil.which("unshare") is None:
    print("  [SKIP] unshare is not available")
else:
    with me._get_conn() as c:
        c.execute("DELETE FROM sensor_service")
    env = dict(os.environ, AGENTALSEC_TEST_DB=str(db),
               PYTHONPATH=str(ROOT))
    code = ("import json; from core import capture_service as cs; "
            "cs.run(json.load(open('config.linux.example.json')), "
            "report_seconds=1, stop_after=4)")
    p = subprocess.run(["unshare", "-rn", "sh", "-c",
                        f"ip link set lo up; {sys.executable} -c \"{code}\""],
                       cwd=ROOT, env=env, capture_output=True, text=True,
                       timeout=120)
    last = cs.latest()
    check("it ran and reported", p.returncode == 0 and last is not None,
          (p.returncode, p.stderr[-800:]))
    if last:
        check("its final report says it stopped", bool(last["stopped_at"]))
        check("and carries the packet sensor's own status",
              "capture_reason" in (last["status"].get("sniffer") or {}),
              list((last["status"].get("sniffer") or {}))[:8])

print("\nALL PASSED" if not failures else f"\nFAILED: {failures}")
sys.exit(1 if failures else 0)
