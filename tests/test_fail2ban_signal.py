"""
tests/test_fail2ban_signal.py, TODO 53.15. The host's own bans are a signal,
and the brute force thresholds now sit under the host's own ban point.

WHERE THIS CAME FROM, 2026-09-06, measured rather than guessed. The brute
force re-test could not run at all: Kali got connection refused, because
fail2ban on the Linux box had banned it during the previous test and the ban
outlived that session. With fail2ban stopped, our detector fired correctly.

Two things came out of that:

  1. fail2ban bans at 5 failures in 10 minutes, its own default. Our medium
     was 10 in 60 seconds, so on any defended host the attacker was gone
     before we had seen enough, and a slow attacker fell out of our window
     completely. We would only ever have caught attacks on undefended boxes.
  2. A ban is a fact the host already established, and we were blind to it.
     Without it, "banned at five tries" and "nobody touched this box" produce
     the same quiet.

Nothing here needs SSH. The log lines are fed in directly, because what is
being checked is the reading, not paramiko.
"""
import pathlib
import sqlite3
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}"
          + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


from core import memory_engine as me            # noqa: E402

tmp = pathlib.Path(tempfile.mkdtemp())
me.DB_PATH = tmp / "t.db"
sqlite3.connect(me.DB_PATH).executescript(
    (ROOT / "Schema.SQL").read_text(encoding="utf-8"))
from core import migrations                     # noqa: E402
migrations.run_migrations(me.DB_PATH)

import tools.linux_monitor as lm                # noqa: E402

SID = "test-session"


def monitor():
    m = lm.LinuxMonitor(session_id=SID, host="198.51.100.7", user="u",
                        key_path="/nowhere", port=50022)
    # Its own dedup store, so one test's lines do not silence the next.
    m._seen_lines.clear()
    m._seen_set.clear()
    return m


class FakeClient:
    """Answers whatever command it is given from a dict of canned output."""

    def __init__(self, answers):
        self.answers = answers
        self.asked = []

    def exec_command(self, cmd, timeout=None):
        self.asked.append(cmd)
        for needle, out in self.answers.items():
            if needle in cmd:
                return None, FakeStdout(out), None
        return None, FakeStdout(""), None


class FakeStdout:
    def __init__(self, text):
        self.text = text.encode()

    def read(self, n=-1):
        return self.text[:n] if n and n > 0 else self.text


print("\n[1] the thresholds sit under the host's own ban point")
# fail2ban's default is 5 failures in 600 seconds. Ours has to fire at or
# before that, or the source is banned and we never see enough.
check("medium at 5", lm.FAILED_LOGIN_FINDING, 5)
check("high at 10", lm.FAILED_LOGIN_HIGH, 10)
check("window matches fail2ban's findtime", lm.FAILED_LOGIN_WINDOW, 600)
check("medium fires no later than fail2ban bans",
      lm.FAILED_LOGIN_FINDING <= 5, True)
check("and the window is not shorter than fail2ban's",
      lm.FAILED_LOGIN_WINDOW >= 600, True)

# AND THE CONFIG LOADER SERVES THE SAME NUMBERS. main.py had them written out
# a second time, so changing them here left every install that does not set
# them in config.json on the old values, silently. Found 2026-09-06 while
# making this change, which is the only reason it is checked.
import main                                     # noqa: E402
target = main._linux_targets({"linux_monitor": {
    "enabled": True, "user": "u", "key_path": "k",
    "hosts": [{"label": "x", "host": "198.51.100.7"}]}})[0]
check("the loader's window matches the module",
      target["failed_login_window"], lm.FAILED_LOGIN_WINDOW)
check("and its medium", target["failed_login_finding"],
      lm.FAILED_LOGIN_FINDING)
check("and its high", target["failed_login_high"], lm.FAILED_LOGIN_HIGH)


print("\n[2] a slow drip is caught now, and used to be invisible")
# Five failures spread over eight minutes: banned by fail2ban, and completely
# outside the old 60 second window.
m = monitor()
found = []
me.save_finding_original = me.save_finding
me.save_finding = lambda **kw: found.append(kw)
try:
    import time
    now = time.time()
    for i in range(5):
        m._bf["203.0.113.9"]["hits"].append(now - (480 - i * 100))
    m._track_failed_login("203.0.113.9")
    check("a medium was raised", [f["severity"] for f in found], ["medium"])
    check("and it names the source",
          found[0]["entity_value"], "203.0.113.9")
finally:
    me.save_finding = me.save_finding_original


print("\n[3] a ban is read out of the host's own log")
m = monitor()
# Stamped NOW, because a ban older than this monitor's start is history and
# is deliberately not raised. See [3b].
import time as _time                             # noqa: E402
_STAMP = _time.strftime("%Y-%m-%d %H:%M:%S", _time.localtime(_time.time() + 5))
f2b_log = (
    f"{_STAMP},101 fail2ban.filter  [1234]: INFO [sshd] Found 192.0.2.16\n"
    f"{_STAMP},900 fail2ban.actions [1234]: NOTICE [sshd] Ban 192.0.2.16\n"
)
client = FakeClient({"fail2ban.log": f2b_log})
m._f2b_seeded = True     # past the seeding read, see [3b]
found = []
events = []
me.save_finding_original = me.save_finding
me.save_event_original = me.save_event
me.save_finding = lambda **kw: found.append(kw)
me.save_event = lambda **kw: events.append(kw)
try:
    m._check_fail2ban(client)
finally:
    me.save_finding = me.save_finding_original
    me.save_event = me.save_event_original

check("one finding for the ban", len(found), 1)
check("medium", found[0]["severity"], "medium")
check("it names the banned address", found[0]["entity_value"], "192.0.2.16")
check("the title says the HOST did it",
      "banned" in found[0]["title"] and "by itself" in found[0]["title"], True)
# The reading note is the point. A ban stops the attempts, so our own count
# is what happened before it, not what the source intended.
check("and it says our count is only what came before the ban",
      "before the ban" in found[0]["description"].lower(), True)
check("the raw data credits the host, not us",
      "fail2ban" in found[0]["raw_data"]["decided_by"], True)
check("an event was recorded too", len(events), 1)
check("typed as a host ban", events[0]["event_type"], "host_ban")


print("\n[3b] history is not news, and a lifted ban is not a standing one")
# FOUND ON THE FIRST REAL RUN, 2026-09-06. The reader tails 200 lines of a
# log that goes back days, so its first read raised three fresh mediums for
# bans from two days ago, two of which had already been unbanned. History
# reported as news, the same mistake as a scan reporting a port it just went
# and looked at. So the first read SEEDS: everything already there is
# recorded as an event, and only bans that happen while we watch are raised.
import time as _t                                # noqa: E402

old_day = _t.strftime("%Y-%m-%d %H:%M:%S", _t.localtime(_t.time() - 2 * 86400))
now_str = _t.strftime("%Y-%m-%d %H:%M:%S", _t.localtime(_t.time() + 5))

m7 = monitor()
found, events = [], []
me.save_finding_original = me.save_finding
me.save_event_original = me.save_event
me.save_finding = lambda **kw: found.append(kw)
me.save_event = lambda **kw: events.append(kw)
try:
    m7._check_fail2ban(FakeClient({"fail2ban.log":
        f"{old_day},100 fail2ban.actions [1]: NOTICE [sshd] Ban 203.0.113.1\n"
        f"{old_day},200 fail2ban.actions [1]: NOTICE [sshd] Ban 203.0.113.2\n"}))
    check("a ban from two days ago raises nothing", found, [])
    check("but it is still on the record", len(events), 2)

    # Now one that happens while we are watching.
    m7._check_fail2ban(FakeClient({"fail2ban.log":
        f"{now_str},300 fail2ban.actions [1]: NOTICE [sshd] Ban 203.0.113.3\n"}))
    check("a ban happening now does raise", len(found), 1)
    check("and it is the new address",
          found[0]["entity_value"], "203.0.113.3")
finally:
    me.save_finding = me.save_finding_original
    me.save_event = me.save_event_original

m8 = monitor()
m8._f2b_seeded = True          # past the seeding read
found = []
me.save_finding_original = me.save_finding
me.save_finding = lambda **kw: found.append(kw)
try:
    m8._check_fail2ban(FakeClient({"fail2ban.log":
        f"{now_str},100 fail2ban.actions [1]: NOTICE [sshd] Ban 203.0.113.4\n"
        f"{now_str},900 fail2ban.actions [1]: NOTICE [sshd] Unban 203.0.113.4\n"}))
    check("a ban already lifted in the same read is not raised", found, [])
finally:
    me.save_finding = me.save_finding_original


print("\n[3d] an OLD unban does not clear a LATER ban of the same address")
# THE BUG, found live 2026-09-06. fail2ban bans a source, unbans it when the
# time expires, then bans it again on the next attempt. That is its normal
# life on a host under repeated attack, so the window carries a pile of old
# unbans of an address that is banned right now. The reader skipped any ban
# whose address had ever been unbanned in the window, order ignored, so those
# old unbans suppressed the real standing ban. The box was still banning the
# Kali box and we filed it as already lifted. Ban, unban, ban again, all read
# in one poll: only the last, standing ban is a finding.
m9 = monitor()
m9._f2b_seeded = True          # past the seeding read
_base = _t.time()


def _at(offset):
    return _t.strftime("%Y-%m-%d %H:%M:%S", _t.localtime(_base + offset))


found = []
me.save_finding_original = me.save_finding
me.save_finding = lambda **kw: found.append(kw)
try:
    m9._check_fail2ban(FakeClient({"fail2ban.log":
        f"{_at(2)},100 fail2ban.actions [1]: NOTICE [sshd] Ban 203.0.113.5\n"
        f"{_at(6)},100 fail2ban.actions [1]: NOTICE [sshd] Unban 203.0.113.5\n"
        f"{_at(10)},100 fail2ban.actions [1]: NOTICE [sshd] Ban 203.0.113.5\n"}))
    check("the standing re-ban is raised, the old unban does not hide it",
          len(found), 1)
    check("and it is that same re-banned address",
          (found[0]["entity_value"] if found else None), "203.0.113.5")
finally:
    me.save_finding = me.save_finding_original


print("\n[3c] the timestamp reader knows both formats and says when it does not")
check("the log file format",
      lm._f2b_time("2026-09-06 13:38:18,900 fail2ban.actions [1]: x")
      is not None, True)
check("the journal format",
      lm._f2b_time("Sep 06 13:38:18 box fail2ban.actions[1]: x") is not None,
      True)
# None is a real answer. A format we cannot read must not become "now", or a
# log full of old bans turns into a screen full of fresh findings.
check("and an unknown shape is None, not now",
      lm._f2b_time("something else entirely"), None)


print("\n[4] the same line is not raised twice")
m2 = monitor()
found = []
me.save_finding_original = me.save_finding
me.save_finding = lambda **kw: found.append(kw)
try:
    m2._f2b_seeded = True
    m2._check_fail2ban(FakeClient({"fail2ban.log": f2b_log}))
    first = len(found)
    m2._check_fail2ban(FakeClient({"fail2ban.log": f2b_log}))
    check("second poll of the same log raises nothing new",
          len(found), first)
finally:
    me.save_finding = me.save_finding_original


print("\n[5] an unban is recorded but is not a finding")
m3 = monitor()
found, events = [], []
me.save_finding_original = me.save_finding
me.save_event_original = me.save_event
me.save_finding = lambda **kw: found.append(kw)
me.save_event = lambda **kw: events.append(kw)
try:
    m3._check_fail2ban(FakeClient({"fail2ban.log":
        "2026-09-06 13:50:00,000 fail2ban.actions [1]: NOTICE [sshd] Unban 192.0.2.16\n"}))
finally:
    me.save_finding = me.save_finding_original
    me.save_event = me.save_event_original
check("no finding", found, [])
check("but it is on the record", events[0]["event_type"], "host_unban")


print("\n[6] no fail2ban is a fact about the host, not a failure")
m4 = monitor()
m4._check_fail2ban(FakeClient({}))
check("we looked and it is not there", m4._f2b_present, False)
st = m4.status()
check("status says so", st["fail2ban"], False)
check("and explains how to read a quiet log",
      "whole attempt" in st["note"], True)

m5 = monitor()
check("before looking, it is unknown rather than absent",
      m5.status()["fail2ban"], None)


print("\n[7] the journal is tried when there is no log file")
m6 = monitor()
m6._f2b_seeded = True
_J = _time.strftime("%b %d %H:%M:%S", _time.localtime(_time.time() + 5))
client = FakeClient({"journalctl -u fail2ban":
    f"{_J} box fail2ban.actions[1]: NOTICE [sshd] Ban 192.0.2.16\n"})
found = []
me.save_finding_original = me.save_finding
me.save_finding = lambda **kw: found.append(kw)
try:
    m6._check_fail2ban(client)
finally:
    me.save_finding = me.save_finding_original
check("the journal answered", len(found), 1)
check("both sources were tried, file first", len(client.asked), 2)
# Read only, and as an unprivileged user. fail2ban-client needs root and we
# poll as a normal account, which is worth keeping.
check("nothing ran fail2ban-client",
      any("fail2ban-client" in c for c in client.asked), False)


print("\n" + ("ALL PASS" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
