"""
tests/test_report_details.py, the daily report names what it counts.

A failed login says who, from where and when, and one try logged by sshd and
btmp counts once. A new port names its program and what started it. A program
from an odd place says what started it. The app's own files its installer
wrote are kept apart from changed system files, and only when they match.
Runs on a scratch database with made-up data.
"""
import json
import os
import pathlib
import sqlite3
import sys
import tempfile
from datetime import date, datetime, timezone

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import _isolate_db                                    # noqa: E402
_isolate_db.isolate()

from core import daily_report as dr                   # noqa: E402
from core import memory_engine as me                  # noqa: E402
from core import migrations                           # noqa: E402
from core import own_install                          # noqa: E402
from tools import ebpf_events, local_integrity as li, port_owner  # noqa: E402

migrations.run_migrations(me.DB_PATH)
fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}"
          + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


DAY = date(2026, 3, 4)
start, end = dr.day_bounds(DAY)


def at(h, m=0):
    return datetime(2026, 3, 4, h, m).astimezone()


def sql_at(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


print("failed logins")
t1, t2 = at(10, 5), at(14, 30)
with me._get_conn() as conn:
    rows = [
        (t1, None, "192.0.2.50", "Invalid user guest from 192.0.2.50 port 4",
         {"service": "sshd", "pid": "4242"}),
        (t1, None, "192.0.2.50",
         "Connection closed by invalid user guest 192.0.2.50 port 4 [preauth]",
         {"service": "sshd", "pid": "4242"}),
        (t1, "guest", "192.0.2.50",
         "failed login for guest from 192.0.2.50 on ssh:notty",
         {"service": "btmp", "pid": "4242"}),
        (t2, "ada", None,
         "pam_unix(sudo:auth): authentication failure; logname=ada uid=1000 "
         "euid=0 tty=/dev/pts/2 ruser=ada rhost=  user=ada",
         {"service": "sudo", "pid": None}),
    ]
    for when, user, src, desc, raw in rows:
        conn.execute(
            "INSERT INTO events (session_id, occurred_at, source, event_type, "
            "username, src_ip, description, raw_data) VALUES "
            "('t', ?, 'auth.log', 'failed_login', ?, ?, ?, ?)",
            (sql_at(when), user, src, desc, json.dumps(raw)))
    conn.commit()
    conn.row_factory = sqlite3.Row
    lg = dr._logins(conn, start, end, {"192.0.2.50": "Test Laptop"})
check("one SSH try logged three times counts once, plus the sudo one",
      lg["failed"], {"SSH": 1, "sudo": 1})
words = dr._attempt_words(lg["attempts"], DAY)
check("the SSH try names the user and the device it came from",
      f'SSH as guest from "Test Laptop" (192.0.2.50), {t1:%H:%M}' in words,
      True)
check("the sudo try says it was at this computer, on which terminal",
      f"sudo as ada at this computer on pts/2, {t2:%H:%M}" in words, True)


print("new ports")
p = {"proto": "tcp", "local_port": 8080, "comm": "python3",
     "exe": "/usr/bin/python3.12", "pid": 42, "detected_at": sql_at(at(9)),
     "origin": {"user": "ada", "unit": "session-2.scope",
                "started": sql_at(at(8, 59)),
                "parents": [{"comm": "bash"}, {"comm": "code"}]}}
check("a port names its program, user and what started it",
      dr._port_words(p, DAY),
      f"tcp 8080, python3 (/usr/bin/python3.12, pid 42), run by ada, in "
      f"session-2.scope, started {at(8, 59):%H:%M}, started by bash, from code")
p["origin"] = None
check("and says so when that was not recorded",
      dr._port_words(p, DAY).endswith("what started it was not recorded"),
      True)
o = port_owner.process_origin(os.getpid())
check("the origin of a running process is read from /proc",
      bool(o and o["parents"] and o["parents"][0]["pid"] == os.getppid()),
      True)
with me._get_conn() as conn:
    cols = {c[1] for c in conn.execute("PRAGMA table_info(port_owner_change)")}
check("and the change table keeps it", "origin_json" in cols, True)


print("programs from odd places")
rows = [
    {"id": 1, "entity_value": "/tmp/x/bin/tool", "found_at": sql_at(at(11)),
     "dismissed": 0, "raw_data": json.dumps(
         {"pid": 7, "exe": "/tmp/x/bin/tool"})},
    {"id": 2, "entity_value": "/tmp/x/bin/tool", "found_at": sql_at(at(11)),
     "dismissed": 0, "raw_data": json.dumps(
         {"pid": 7, "realpath": "/tmp/x/bin/tool", "parent_comm": "make",
          "uid": 0})},
]
count, text = dr._odd_result(rows, DAY)
check("one run seen by both process rules counts once", count, "1")
check("and says what started it and as whom",
      text, f"/tmp/x/bin/tool, started by make, as root, {at(11):%H:%M}")
check("a /proc/self path is not resolved in this process",
      ebpf_events.in_staging_directory("/proc/self/fd/6"), None)


print("the app's own files")
proj = pathlib.Path(tempfile.mkdtemp(prefix="ownfiles."))
(proj / "scripts" / "systemd-hardening").mkdir(parents=True)
conf = b"[Service]\nNoNewPrivileges=yes\n"
(proj / "scripts" / "systemd-hardening" / "agentalsec-demo.conf").write_bytes(conf)
target = "/etc/systemd/system/agentalsec-demo.service.d/hardening.conf"
h = li._hash16(conf)
check("a drop-in identical to the project's copy is the app's own",
      bool(li.own_file_check(target, f"644:0:0:{len(conf)}:{h}", proj)), True)
check("not when its content differs",
      li.own_file_check(target, f"644:0:0:{len(conf)}:{'0' * 16}", proj), None)
check("not when others can write it",
      li.own_file_check(target, f"666:0:0:{len(conf)}:{h}", proj), None)
check("not when root does not own it",
      li.own_file_check(target, f"644:1000:0:{len(conf)}:{h}", proj), None)

script = (ROOT / "scripts" / "install_read_helper.sh").read_text()
(proj / "scripts" / "install_read_helper.sh").write_text(script)
drop = own_install.expected(proj)[
    "/etc/sudoers.d/agentalsec-read-helper"][1].exact
check("the sudoers drop-in is rendered from the installer, nothing left open",
      bool(drop) and "read_helper.py sudoers, \\" in drop
      and "$" not in drop, True)
body = drop.encode()
sudoers = "/etc/sudoers.d/agentalsec-read-helper"
check("a drop-in with exactly that text is the app's own, by its hash alone",
      bool(li.own_file_check(sudoers,
                             f"440:0:0:{len(body)}:{li._hash16(body)}",
                             proj)), True)
wider = body.replace(b"--verbs", b"--verbs, /bin/sh")
check("one with a wider grant is not",
      li.own_file_check(sudoers, f"440:0:0:{len(wider)}:{li._hash16(wider)}",
                        proj), None)

old = {"dirs": {"/etc/systemd/system": {"entries": {}}}}
new = {"dirs": {"/etc/systemd/system": {"entries": {
    "agentalsec-demo.service.d/hardening.conf": f"644:0:0:{len(conf)}:{h}"}}}}
real_root = li.PROJECT_ROOT
li.PROJECT_ROOT = proj
try:
    found = li.diff_dir_sets(old, new, hashed=True)
finally:
    li.PROJECT_ROOT = real_root
check("the sensor files it as info, not as a new file alarm",
      [(f["severity"], f["title"].split(":")[0]) for f in found],
      [("info", "AgentalSec updated its own file")])
count, text = dr._system_files_result([
    {"entity_value": "/etc/passwd", "raw_data": "{}"},
    {"entity_value": target, "raw_data": json.dumps({"own_file": "x"})}])
check("the report counts only the real change", count, "1")
check("and names the app's own apart",
      text, "/etc/passwd; 1 file of AgentalSec's own updated, each matching "
            "what its installer writes")

print("\n" + ("ALL PASS" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
