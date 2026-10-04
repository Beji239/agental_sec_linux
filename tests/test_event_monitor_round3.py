"""
tests/test_event_monitor_round3.py, event monitor fixes EM3-1 to EM3-4.

    EM3-1  a non-UTF-8 journald MESSAGE (a JSON list of byte values) crashed
           the poll before the cursor was saved, so the journal stalled on it
    EM3-2  the stale-cursor fallback used --since with --lines=N, which
           returns the NEWEST N and skips the older records
    EM3-3  one failed SSH attempt was counted up to three times, on the read
           clock, with no guard against a re-read
    EM3-4  addresses were read as IPv4 only

No database, no network, no root. Addresses are RFC 5737 / RFC 3849.
"""
import os
import sys
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from tools import event_monitor_linux as em

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}" + ("" if ok else f"  (got {got!r}, want {want!r})"))
    if not ok:
        fails.append(label)


def reset():
    em._failed_logins.clear()
    em._failed_login_seen.clear()
    em._seen_events.clear()


print("\n[1] EM3-1: a binary journald message costs nothing")
rec = {"__REALTIME_TIMESTAMP": "1790614166648909", "__SEQNUM": "5",
       "__SEQNUM_ID": "x", "MESSAGE": [104, 105, 255],
       "SYSLOG_IDENTIFIER": ["a", "b"], "_PID": None}
entry = em._journald_entry(rec)
check("a byte-list MESSAGE becomes text", entry["message"], "hi�")
check("a repeated field becomes one string", entry["service"], "a b")
check("a null field becomes empty", entry["pid"], "")
check("and the entry categorises without raising",
      em._categorize_entry(entry), [])

reset()
bad = {"source": "journald", "message": object(), "timestamp": None}
good = em._parse_syslog_line(
    "2026-09-28T10:00:00-07:00 h sshd[1]: Accepted publickey for ada from "
    "192.0.2.4 port 22 ssh2", "auth.log")
with mock.patch.dict(em._config, {"login_records": False}), \
        mock.patch.object(em, "_get_log_file_paths", return_value={"journald": None}), \
        mock.patch.object(em, "_read_journald_lines",
                          return_value={"entries": [bad, good],
                                        "marker": {"cursor": "c2"},
                                        "remaining": 0, "error": None,
                                        "gap": None}):
    with mock.patch.object(em, "_dedupe_across_paths",
                           side_effect=lambda e: (e, {})):
        out = em.monitor_once(markers={"journald": {"cursor": "c1"}})
check("a poll with an unprocessable entry still returns", out["searched"], True)
check("and still advances the cursor", out["markers"]["journald"]["cursor"], "c2")
check("and says one entry was skipped", out["entries_skipped"], 1)
check("and the good entry is stored",
      [e.get("type") for e in out["events"]], ["successful_login"])


print("\n[2] EM3-2: the time fallback reads the oldest records first")
calls = []


def fake_run(cmd, **kw):
    calls.append(cmd)
    rc = 1 if any(a.startswith("--after-cursor") for a in cmd) else 0
    return mock.Mock(returncode=rc, stdout="", stderr="Failed to seek to cursor")


with mock.patch.object(em.subprocess, "run", side_effect=fake_run):
    em._read_journald_lines({"cursor": "old", "seqnum": 1, "seqnum_id": "x",
                             "realtime": "1790614166000000"}, lines=50)
fallback = calls[-1]
check("the fallback asks for the first 50 after the time", "--lines=+50" in fallback, True)
check("and not the newest 50", "--lines=50" in fallback, False)
check("and resumes from the last read time",
      any(a.startswith("--since=@1790614166") for a in fallback), True)


print("\n[3] EM3-3: one failed attempt is one count")


def attempt(sec, pid, ip="203.0.113.9"):
    return [
        f"2026-09-28T10:00:{sec:02d}.000000-07:00 h sshd[{pid}]: Invalid user bob from {ip} port 5000",
        f"2026-09-28T10:00:{sec:02d}.100000-07:00 h sshd[{pid}]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost={ip}",
        f"2026-09-28T10:00:{sec + 2:02d}.000000-07:00 h sshd[{pid}]: Failed password for invalid user bob from {ip} port 5000 ssh2",
    ]


def feed(lines, findings):
    for line in lines:
        em._process_entry(em._parse_syslog_line(line, "auth.log"), [], findings)


reset()
findings = []
for i in range(4):
    feed(attempt(i * 5, 100 + i), findings)
check("four real attempts (twelve lines) do not fire",
      [f for f in findings if f["type"] == "brute_force_detected"], [])
feed(attempt(40, 200), findings)
check("the fifth attempt fires, with a count of five",
      [(f["entity_value"], f["attempt_count"]) for f in findings
       if f["type"] == "brute_force_detected"], [("203.0.113.9", 5)])

reset()
line = attempt(0, 1)[2]
for _ in range(6):
    feed([line], [])
check("the same line read six times counts once",
      len(em._failed_logins["203.0.113.9"]), 1)

reset()
findings = []
# five attempts spread over 20 minutes, read in one poll: not a burst
for i in range(5):
    feed([f"2026-09-28T10:{i * 5:02d}:00-07:00 h sshd[{i}]: Failed password for ada from 198.51.100.7 port 1 ssh2"],
         findings)
check("the window runs on the event's own clock, not the read clock",
      [f for f in findings if f["type"] == "brute_force_detected"], [])

sudo = em._parse_syslog_line(
    "2026-09-28T10:00:00-07:00 h sudo: pam_unix(sudo:auth): authentication "
    "failure; logname=ada uid=1000 euid=0 tty=/dev/pts/1 ruser=ada rhost=  user=ada",
    "auth.log")
check("a pam failure from a non-sshd service still counts",
      em._counts_as_login_attempt(sudo), True)
check("sshd's own pam line does not",
      em._counts_as_login_attempt(em._parse_syslog_line(attempt(0, 1)[1], "auth.log")),
      False)


print("\n[4] EM3-4: IPv6 sources are read")
for msg, want in [
        ("Failed password for root from 2001:db8::7 port 5000 ssh2", "2001:db8::7"),
        ("Accepted publickey for ada from fe80::1%eth0 port 22", "fe80::1"),
        ("authentication failure; rhost=2001:db8::9  user=x", "2001:db8::9"),
        ("Failed password for root from 192.0.2.1 port 1 ssh2", "192.0.2.1"),
        ("Waiting from 10:30 on", None)]:
    check(f"address in {msg[:44]!r}",
          em._extract_fields({"message": msg}).get("ip_address"), want)
check("a login burst from an IPv6 source has a subject",
      em._login_source("Accepted publickey for ada from 2001:db8::7 port 22"),
      "2001:db8::7")

print("\n" + ("," * 60))
print("ALL PASS" if not fails else f"{len(fails)} FAILED: {fails}")
sys.exit(1 if fails else 0)
