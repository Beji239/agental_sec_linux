"""
tests/test_event_monitor_features.py, what the event monitor reads now.

    EM3-5  SSH (pre-auth disconnects, max auth attempts, every failed and
           accepted method, scanner banners), accounts (failed su, group
           changes, password changes, lockouts), polkit, AppArmor/SELinux,
           kernel taint, core dumps, and any netfilter log line. Joining a
           privileged group raises LNX-1017; a tainting module LNX-1018.
    EM3-6  journald's structured fields: MESSAGE_ID names the event and its
           unit, and auth patterns only count from auth/authpriv.
    EM3-7  /var/log/wtmp and btmp, read with a cursor like the text logs.
    EM3-8  a journald follower wakes the poll loop when a record arrives.

No database writes (the adapter's writer is mocked), no network, no root.
Addresses are RFC 5737 documentation ranges.
"""
import os
import struct
import sys
import tempfile
import threading
import time
from pathlib import Path
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tests"))

import _isolate_db                                       # noqa: E402
_isolate_db.isolate()

import adapters                                          # noqa: E402
from tools import event_monitor_linux as em              # noqa: E402

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}"
          + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


def line(text, src="auth.log", sec=0):
    return em._parse_syslog_line(
        f"2026-09-28T10:00:{sec:02d}.000000-07:00 h {text}", src)


def cats(entry):
    return [c[0] for c in em._categorize_entry(entry)]


def shape(entry):
    c = em._categorize_entry(entry)
    return [(f["type"], f["entity_value"]) for f in
            em._shape_findings(entry, c, em._extract_fields(entry), 0)]


print("\n[1] EM3-5: the new patterns")
cases = [
    ("sshd[1]: Connection closed by authenticating user ada 203.0.113.9 port 5000 [preauth]", "auth.log", "ssh_preauth_disconnect"),
    ("sshd[1]: error: maximum authentication attempts exceeded for root from 203.0.113.9 port 5 ssh2 [preauth]", "auth.log", "ssh_max_auth_attempts"),
    ("sshd[1]: Failed publickey for ada from 203.0.113.9 port 5 ssh2", "auth.log", "failed_login"),
    ("sshd[1]: Failed keyboard-interactive/pam for invalid user bob from 203.0.113.9 port 5 ssh2", "auth.log", "failed_login"),
    ("sshd[1]: Accepted keyboard-interactive/pam for ada from 198.51.100.4 port 5 ssh2", "auth.log", "successful_login"),
    ("sshd[1]: error: kex_exchange_identification: Connection closed by remote host", "auth.log", "ssh_scanner_probe"),
    ("sshd[1]: banner exchange: Connection from 203.0.113.9 port 5: invalid format", "auth.log", "ssh_scanner_probe"),
    ("su[5]: FAILED SU (to root) ada on pts/1", "auth.log", "failed_login"),
    ("usermod[9]: add 'ada' to group 'plugdev'", "auth.log", "group_membership_changed"),
    ("passwd[9]: pam_unix(passwd:chauthtok): password changed for ada", "auth.log", "password_changed"),
    ("sshd[1]: pam_faillock(sshd:auth): Consecutive login failures for user root account temporarily locked", "auth.log", "account_locked"),
    ("polkitd[7]: Operator of unix-session:2 FAILED to authenticate to gain authorization for action org.x", "auth.log", "polkit_auth_failed"),
    ('kernel: audit: type=1400 audit(1.2:3): apparmor="DENIED" operation="open" profile="p" name="/etc/shadow"', "kern.log", "mac_denial"),
    ("kernel: audit: avc:  denied  { read } for pid=1 comm=\"x\"", "kern.log", "mac_denial"),
    ("systemd-coredump[3]: Process 1234 (sshd) of user 0 dumped core.", "syslog", "process_crashed"),
    ("kernel: [DROP-IN] IN=eth0 OUT= MAC=aa SRC=203.0.113.9 DST=192.0.2.10 LEN=60 PROTO=TCP SPT=5 DPT=22", "kern.log", "firewall_block"),
]
for text, src, want in cases:
    check(f"{want} <- {text[:48]}", want in cats(line(text, src)), True)
check("a netfilter line logged on its way to ALLOW is not a block",
      cats(line("kernel: [UFW ALLOW] IN=eth0 OUT= MAC=aa SRC=203.0.113.9 DST=192.0.2.10 PROTO=TCP DPT=22", "kern.log")),
      [])

print("\n[2] EM3-5: LNX-1017 and LNX-1018")
check("joining sudo raises privileged_group_added",
      shape(line("usermod[9]: add 'mallory' to group 'sudo'", sec=1)),
      [("privileged_group_added", "mallory")])
check("the shadow-group line of the same change is not a second finding",
      shape(line("usermod[9]: add 'mallory' to shadow group 'sudo'", sec=1)), [])
check("gpasswd's wording is read too",
      shape(line("gpasswd[9]: user eve added by root to group docker", sec=2)),
      [("privileged_group_added", "eve")])
check("an ordinary group is an event, not a finding",
      shape(line("usermod[9]: add 'ada' to group 'plugdev'", sec=3)), [])
check("a tainting module is named",
      shape(line("kernel: evilmod: module verification failed: signature and/or required key missing - tainting kernel", "kern.log", 4)),
      [("kernel_tainted", "module:evilmod")])

saved = []
fake_me = mock.Mock()
fake_me.is_dismissed.return_value = False
fake_me.save_finding.side_effect = lambda **kw: saved.append(kw) or {"id": 1}
mon = adapters.LinuxEventMonitor("t", {})
result = {"events": [], "findings": [
    {"type": "privileged_group_added", "entity_type": "user", "entity_value": "mallory",
     "severity": "high", "description": "d", "message": "m"},
    {"type": "kernel_tainted", "entity_type": "file", "entity_value": "module:evilmod",
     "severity": "medium", "description": "d", "message": "m"}],
    "markers": {}, "gaps": [], "read_failures": {}}
with mock.patch("core.memory_engine", fake_me, create=True), \
        mock.patch.dict(sys.modules, {"core.memory_engine": fake_me}), \
        mock.patch.object(em, "monitor_once", return_value=result), \
        mock.patch.object(mon, "_load_markers", return_value={}), \
        mock.patch.object(mon, "_save_markers"):
    try:
        mon.poll()
    except Exception as e:                                # noqa: BLE001
        print(f"  (poll raised {type(e).__name__}: {e})")
check("the adapter files both under their registered ids",
      sorted((k["detection_id"], k["entity_type"], k["entity_value"]) for k in saved),
      [("LNX-1017", "user", "mallory"), ("LNX-1018", "file", "module:evilmod")])

print("\n[3] EM3-6: structured journald fields")
rec = {"__REALTIME_TIMESTAMP": "1790614166648909", "__SEQNUM": "1", "__SEQNUM_ID": "x"}
failed = em._journald_entry(dict(rec, MESSAGE="x.service: Failed with result 'exit-code'.",
                                 SYSLOG_IDENTIFIER="systemd", _PID="1",
                                 MESSAGE_ID=em.MSGID_UNIT_FAILED, UNIT="x.service"))
check("MESSAGE_ID names a unit failure", cats(failed), ["service_failed"])
worded = em._journald_entry(dict(rec, MESSAGE="unit x failed (reworded by a newer systemd)",
                                 SYSLOG_IDENTIFIER="systemd", _PID="1",
                                 MESSAGE_ID=em.MSGID_UNIT_FAILED, UNIT="odd.service"))
em._service_failures.clear()
em._service_failure_seen.clear()
got = []
for i in range(3):
    e = dict(worded, timestamp=f"2026-09-28 10:00:0{i}")
    got += em._shape_findings(e, em._categorize_entry(e), {}, 0)
check("the unit comes from the UNIT field when the text does not name it",
      [(f["type"], f["entity_value"]) for f in got], [("service_restart_loop", "odd.service")])
fake_login = em._journald_entry(dict(rec, MESSAGE="Failed password for root from 203.0.113.9 port 5 ssh2",
                                     SYSLOG_IDENTIFIER="someapp", SYSLOG_FACILITY="1"))
check("an auth pattern from a non-auth facility is not a login", cats(fake_login), [])
real_login = em._journald_entry(dict(rec, MESSAGE="Failed password for root from 203.0.113.9 port 5 ssh2",
                                     SYSLOG_IDENTIFIER="sshd", SYSLOG_FACILITY="4"))
check("from auth it is", cats(real_login), ["failed_login"])

print("\n[4] EM3-7: wtmp and btmp")


def utmp(ut_type, user, host, line_, sec, addr=b""):
    return struct.pack(em.UTMP_FORMAT, ut_type, 100, line_.encode(), b"ts/0",
                       user.encode(), host.encode(), 0, 0, 0, sec, 0,
                       addr.ljust(16, b"\0"))


tmp = Path(tempfile.mkdtemp())
wtmp = tmp / "wtmp"
wtmp.write_bytes(utmp(2, "reboot", "6.1.0", "~", 1790600000)
                 + utmp(7, "ada", "203.0.113.9", "pts/0", 1790600100,
                        bytes([203, 0, 113, 9]))
                 + utmp(8, "", "", "pts/0", 1790600200))
r = em._read_login_records(wtmp, "wtmp", None)
check("boot, login and logout are read",
      [(e["preset_categories"][0][0], e.get("username"), e.get("ip_address")) for e in r["entries"]],
      [("system_boot", None, None), ("login_session", "ada", "203.0.113.9"),
       ("logout_session", None, None)])
check("and the cursor sits after the last whole record",
      r["marker"]["offset"], 3 * em.UTMP_SIZE)
with wtmp.open("ab") as fh:
    fh.write(utmp(7, "bob", "198.51.100.4", "pts/1", 1790600300) + b"partial")
r2 = em._read_login_records(wtmp, "wtmp", r["marker"])
check("the next read takes only the new record, never a partial one",
      [e.get("username") for e in r2["entries"]], ["bob"])
wtmp.unlink()
wtmp.write_bytes(utmp(7, "carol", "", "tty1", 1790600400))
r3 = em._read_login_records(wtmp, "wtmp", r2["marker"])
check("a rotated file is read from its start, and the gap is reported",
      ([e.get("username") for e in r3["entries"]], bool(r3["gap"])), (["carol"], True))

btmp = tmp / "btmp"
btmp.write_bytes(b"".join(utmp(6, "root", "203.0.113.7", "ssh:notty", 1790600000 + i,
                               bytes([203, 0, 113, 7])) for i in range(6)))
entries = em._read_login_records(btmp, "btmp", None)["entries"]
check("btmp records are failed logins with their source",
      {(e["preset_categories"][0][0], e["ip_address"]) for e in entries},
      {("failed_login", "203.0.113.7")})
check("they do not count toward brute force when the text logs were read",
      em._counts_as_login_attempt(entries[0]), False)
check("they do when no text auth log could be read",
      em._counts_as_login_attempt(dict(entries[0], count_attempt=True)), True)
os.chmod(btmp, 0)
if os.geteuid() != 0:
    check("an unreadable btmp is reported, not taken as empty",
          "cannot read" in (em._read_login_records(btmp, "btmp", None)["error"] or ""), True)

print("\n[5] EM3-8: journald wakes the poll loop")
mon = adapters.LinuxEventMonitor("t", {"sensors": {"event_monitor": {"poll_interval": 60}}})
mon._running = True
mon.STREAM_MIN_GAP = 0.0
threading.Timer(0.3, mon._wake.set).start()
t = time.time()
mon._wait_for_next_poll()
check("a record wakes the loop long before the 60 s interval", time.time() - t < 5, True)
check("and the wake-up is counted", mon._stream["wakeups"], 1)
check("streaming is on by default", em.configure({})["stream"], True)
check("and can be switched off",
      em.configure({"sensors": {"event_monitor": {"stream": False}}})["stream"], False)
em.configure({})

print("\n" + "=" * 62)
if fails:
    print(f"{len(fails)} FAILED: " + ", ".join(fails))
    sys.exit(1)
print("ALL PASS")
