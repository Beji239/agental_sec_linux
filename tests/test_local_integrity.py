"""
tests/test_local_integrity.py, L3. The local file sensor's rules.

FAILURE CASES FIRST. The happy path of this module is a dict comparison. What
is worth testing is every way it can be WRONG while looking like it works, and
this project has a name for the worst of those: a sensor that could not look
reported as a host with nothing wrong.

So the order below is deliberate:

  [1]  A first pass SEEDS and raises nothing. This is the dpkg lesson applied
       before dpkg was built.
  [2]  A change raises ONCE and the baseline moves with it, so the same change
       does not repeat every poll until somebody switches the module off.
  [3]  "Added", "replaced" and "removed" are three DIFFERENT sentences, which
       is the whole reason the local sweep keeps hashes where the remote one
       does not. A binary swapped underneath its name is not a new binary.
  [4]  An unreadable file is NOT an unchanged file. This is rule two, and on
       this host it is not hypothetical: /etc/sudoers is root-only and every
       file in /etc/sudoers.d is too.
  [5]  A directory that cannot be listed is blocked, not absent.
  [6]  The sweep's own blind spots are RAISED, with the entry count, because
       a sweep that could not enter thirty-nine directories answers the same
       empty way as a machine with nothing setuid on it.
  [7]  The cap on findings per pass ANNOUNCES itself and names the number it
       did not write.
  [8]  World-writable is the ONE permission state that raises on a seed pass,
       and this host's own authorized_keys (mode 664) must NOT raise, because
       a module that shouts on its first look is one its reader skims.
  [9]  Every id the module can raise IS registered, and every severity it
       raises is one the register declares. Proven by calling the writers, not
       by reading the register.
 [10]  The two cadences stay apart: tier A is cheap, the sweep is not, and the
       sweep must not run on the poll loop.
 [11]  The status contract: blind only for the three real cases, never for the
       permanent unelevated limit, and the limit STATED in words.
 [12]  The entity vocabulary carries 'file' everywhere it is enforced, or the
       findings reach the findings table and open no incident.

Run it directly: python tests/test_local_integrity.py
"""
import os
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import _isolate_db                                    # noqa: E402
_isolate_db.isolate()

from core import detections as det                    # noqa: E402
from core import memory_engine as me                  # noqa: E402
from core import sensors as sn                        # noqa: E402
from tools import local_integrity as li               # noqa: E402

sn.register_local()

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}"
          + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


def check_true(label, got):
    check(label, bool(got), True)


def _rec(**kw):
    """A file record, built by hand so the comparison can be driven."""

    base = {"exists": True, "readable": True, "mode": "644", "uid": 0,
            "gid": 0, "size": 100, "mtime_ns": 1000, "hash": "aaaa",
            "type": "file"}
    base.update(kw)
    return base


print("\n[1] A FIRST PASS SEEDS AND RAISES NOTHING")
# The dpkg lesson. On a machine nothing has ever looked at, a first pass is a
# page of pre-existing states, and a module that reports them as findings has
# taught its reader to skim it before it has ever been useful.
before = {"files": {}}
after = {"files": {"/etc/passwd": _rec()}}
check("seeding is the caller's decision, and the diff sees a new path as 'no"
      " earlier state'", li.diff_watched_files(before, after), [])

# And this module's own seed rule: a directory with no stored baseline does
# not produce a diff at all, it writes one.
r = li.tier_a_pass()
check_true("the first real pass seeded something", len(r["seeded"]) >= 3)
check("and raised nothing for it", r["findings"], [])


print("\n[2] A CHANGE RAISES ONCE, THEN THE BASELINE MOVES")
old = {"files": {"/etc/passwd": _rec(size=100, hash="aaaa")}}
new = {"files": {"/etc/passwd": _rec(size=200, hash="bbbb", mtime_ns=2000)}}
first = li.diff_watched_files(old, new)
check("one finding", len(first), 1)
check("with the right id", first[0]["detection_id"], "LNX-2001")
check("and it is entity_type file, valued by path",
      (first[0]["entity_type"], first[0]["entity_value"]),
      ("file", "/etc/passwd"))
check("the description carries both states, so a reader can weigh it",
      str(first[0]["raw_data"]["before"]) != str(first[0]["raw_data"]["after"]),
      True)
# The second half of the rule: against the NEW baseline the same state is
# silent. That is what stops a poll loop re-raising the same thing forever.
check("the same change against the moved baseline is silent",
      li.diff_watched_files(new, new), [])


print("\n[3] ADDED, REPLACED AND REMOVED ARE THREE SENTENCES")
old = {"suid": {"/usr/bin/sudo": "aaaa", "/opt/tool": "bbbb"}}
new = {"suid": {"/usr/bin/sudo": "ffff", "/usr/bin/newthing": "1111"}}
out = li.diff_sweep(old, new)
by_change = {f["raw_data"]["change"]: f for f in out}
# THREE, not two: sudo moved (replaced), newthing appeared (added), tool went
# (removed). The presence of all three in one comparison is the point of
# keeping hashes where the remote sweep does not.
check("all three changes appear together",
      sorted(by_change), ["added", "removed", "replaced"])
check("the new path is the 'added' one",
      by_change["added"]["entity_value"], "/usr/bin/newthing")
check("the contents of a known path is its own change",
      by_change["replaced"]["entity_value"], "/usr/bin/sudo")
replaced = li.diff_sweep({"suid": {"/usr/bin/sudo": "aaaa"}},
                         {"suid": {"/usr/bin/sudo": "ffff"}})
check("a hash move at a known path is 'replaced'",
      replaced[0]["raw_data"]["change"], "replaced")
check("and says so in words, not only in a field",
      "REPLACED" in replaced[0]["title"], True)

caps = li.diff_sweep({"caps": {"/usr/bin/ping": "0100"}},
                     {"caps": {"/usr/bin/ping": "0200"}})
check("a capability change is LNX-2009", caps[0]["detection_id"], "LNX-2009")
check("and names both values",
      (caps[0]["raw_data"]["before"], caps[0]["raw_data"]["after"]),
      ("0100", "0200"))


print("\n[4] AN UNREADABLE FILE IS NOT AN UNCHANGED FILE")
# Rule two, and on this host it is not hypothetical: /etc/sudoers is 440
# root:root and every file in /etc/sudoers.d with it.
meta_only = {"files": {"/etc/sudoers": _rec(readable=False, hash=None,
                                            mtime_ns=5000, mode="440")}}
check("a file unreadable on BOTH passes is a coverage fact, not a change",
      li.diff_watched_files(meta_only, meta_only), [])
widened = {"files": {"/etc/sudoers": _rec(readable=False, hash=None,
                                          mtime_ns=6000, mode="440")}}
one = li.diff_watched_files(meta_only, widened)
check("but its METADATA moving still raises", len(one), 1)
check("and the finding says the content was not read BY EITHER PASS",
      "NOT READ BY EITHER PASS" in one[0]["description"], True)
check("and spells out what that means: a content edit leaving the metadata"
      " identical is not detected",
      "not be detected" in one[0]["description"].lower()
      or "not detected" in one[0]["description"].lower(), True)
check("carrying the field a machine reader would use",
      one[0]["raw_data"]["content_read"], False)

# The read-then-unreadable direction, which is a change in what we can see and
# must not be folded into 'same hash'.
lost = {"files": {"/etc/hosts": _rec(readable=True, hash="aaaa")}}
cant = {"files": {"/etc/hosts": _rec(readable=False, hash=None)}}
two = li.diff_watched_files(lost, cant)
check("a file that stops being readable is itself the change", len(two), 1)
check("and the wording says which direction it went",
      "was readable at the last pass and is NOT any more"
      in two[0]["description"], True)


print("\n[5] A DIRECTORY THAT CANNOT BE LISTED IS BLOCKED, NOT ABSENT")
# TWO DIFFERENT FAILURES, and this host has both, which is why the test uses a
# real path for each rather than inventing one.
#
# /etc/sudoers.d is MODE 755: it lists fine, all four files come back with
# their mode, owner and size, and every one of their CONTENTS is refused. That
# is the watch it gets, and the coverage block names it: name, mode, owner,
# size and mtime, and a content edit leaving those identical is not detected.
d = li.dir_record("/etc/sudoers.d", hashed=True)
check("sudoers.d exists", d["exists"], True)
check("and it is NOT blocked: the directory lists, its files do not read",
      d["blocked"], False)
check_true("so its entries ARE recorded, with metadata", len(d["entries"]) >= 1)
check("and every entry's content hash is absent rather than a hash",
      all(v.endswith(":-") for v in d["entries"].values()), True)
check_true("with the refusal recorded per file",
           any("permission denied" in u for u in d["unreadable"]))

# The genuinely blocked case: a directory this user cannot enter at all. The
# entry list is empty and blocked is what makes that readable as a limit.
blocked = li.dir_record("/var/spool/cron/crontabs", hashed=True)
check("a root-only directory exists", blocked["exists"], True)
check("and is marked blocked", blocked["blocked"], True)
check("with an empty entry list, which is exactly why blocked matters",
      blocked["entries"], {})

missing = li.dir_record("/etc/this-does-not-exist-42", hashed=True)
check("a directory that genuinely is not there says that instead",
      (missing["exists"], missing["blocked"]), (False, False))


print("\n[6] THE SWEEP'S BLIND SPOTS ARE RAISED, WITH THE COUNT")
sweep = {"unreadable_dirs": ["/root (Permission denied)",
                             "/boot/efi (Permission denied)"],
         "files_seen": 936143, "seconds": 39.6, "unhashable": 3,
         "xattr_unreadable": 0}
out = li.sweep_coverage_findings(sweep, li.UNREADABLE_DIRS_TYPICAL)
check("two coverage findings: the directories and the hashes", len(out), 2)
cov = out[0]
check("the id is the register's coverage rule", cov["detection_id"], "LNX-2010")
check("it is an availability claim, not an integrity one",
      det.axes("LNX-2010"), ["availability"])
check("it carries the entry count, so a big sweep is visibly big",
      cov["raw_data"]["files_seen"], 936143)
check("it names the directories rather than only counting them",
      "/root (Permission denied)" in cov["description"], True)
check("and it says what the reader must NOT conclude",
      "UNKNOWN" in cov["description"], True)
check("the second one is about files it could not hash",
      out[1]["entity_value"], "filesystem-sweep-hashes")
check("a sweep that read everything raises no coverage finding",
      li.sweep_coverage_findings({"unreadable_dirs": [], "files_seen": 1,
                                  "unhashable": 0}), [])


print("\n[7] THE CAP ANNOUNCES ITSELF")
many = [li._finding("LNX-2001", "high", "file", f"/etc/pam.d/f{i}",
                    f"t{i}", "d", {}) for i in range(27)]
kept = li.cap_findings(many, per_id_cap=20)
check("20 individual rows plus one summary", len(kept), 21)
summary = kept[-1]
check("the summary carries the same id, so it is not a phantom rule",
      summary["detection_id"], "LNX-2001")
check("it says how many there really were", summary["raw_data"]["produced"], 27)
check("how many were listed", summary["raw_data"]["listed"], 20)
check("and how many were cut", summary["raw_data"]["cut"], 7)
check("the count appears in the words a person reads",
      "7 further finding(s)" in summary["title"], True)
check("under the cap, nothing extra is added",
      len(li.cap_findings(many[:5], per_id_cap=20)), 5)


print("\n[8] WORLD-WRITABLE RAISES ON A SEED PASS; THIS HOST'S 664 DOES NOT")
# The operator's own ~/.ssh/authorized_keys is mode 664, measured. A module
# that reports that as a finding on its first pass is teaching its reader to
# skim it. World-writable is the one state with no safe reading.
ww = {"ssh": {"entries": {"/home/x/.ssh/authorized_keys": {
    "exists": True, "mode": "666", "uid": 1000, "gid": 1000,
    "readable": True, "hash": "a", "lines": {}}}}}
out = li.seed_ssh_permission_findings(ww)
check("world-writable raises on the seed pass", len(out), 1)
check("it is the permissions rule, not the key rule",
      out[0]["detection_id"], "LNX-2003")
check("at high, which the register declares",
      out[0]["severity"], "high")
check("and the record says it was the seed pass, so nobody hunts for a"
      " previous state", out[0]["raw_data"]["on_seed_pass"], True)

safe = {"ssh": {"entries": {"/home/x/.ssh/authorized_keys": {
    "exists": True, "mode": "664", "uid": 1000, "gid": 1000,
    "readable": True, "hash": "a", "lines": {}}}}}
check("664, which is what this host actually has, raises nothing",
      li.seed_ssh_permission_findings(safe), [])
ro = {"ssh": {"entries": {"/root/.ssh/authorized_keys": {
    "exists": True, "mode": "600", "uid": 0, "gid": 0,
    "readable": False, "hash": None, "lines": {}}}}}
check("a root-only key file raises nothing for being root-only",
      li.seed_ssh_permission_findings(ro), [])


print("\n[9] EVERY ID IS REGISTERED AND EVERY SEVERITY IS DECLARED")
# PROVEN BY CALLING THE WRITERS. Reading the register would prove only that
# the register has entries, and the failure this catches is a module raising a
# severity its rule does not carry, which check_severity REFUSES rather than
# clamps: the finding would be lost.
RAISED = {
    "LNX-2001": ["medium", "high"],
    "LNX-2002": ["high"],
    "LNX-2003": ["medium", "high"],
    "LNX-2004": ["medium", "high", "critical"],
    "LNX-2007": ["high", "medium"],
    "LNX-2008": ["medium", "high", "low"],
    "LNX-2009": ["high", "medium"],
    "LNX-2010": ["medium"],
    "LNX-2011": ["high"],
}
for did, severities in sorted(RAISED.items()):
    try:
        rule = det.get(did)
        check_true(f"{did} is registered", bool(rule))
        check(f"{did} is a detection, not an action record",
              rule.kind, "detection")
        for sev in severities:
            det.check_severity(did, sev)          # raises if undeclared
        check(f"{did} declares every severity the module raises", True, True)
    except Exception as e:
        check(f"{did} is registered and declares what it raises",
              f"{type(e).__name__}: {e}", "ok")

# The ids the MODULE actually produces, read out of its own comparisons, so a
# rule added to the code and forgotten in this list is caught.
produced = set()
for f in (li.diff_watched_files({"files": {}}, {"files": {
        "/etc/passwd": _rec()}})
          + li.diff_watched_files({"files": {"/etc/passwd": _rec()}},
                                  {"files": {"/etc/passwd": _rec(hash="b")}})
          + li.diff_sweep({"suid": {"/a": "1"}, "sgid": {"/b": "1"},
                           "caps": {"/c": "1"}},
                          {"suid": {"/d": "1"}, "sgid": {}, "caps": {}})
          + li.sweep_coverage_findings({"unreadable_dirs": ["/x (y)"],
                                        "files_seen": 1, "unhashable": 1})
          + li.mac_posture_findings({"selinux": {"present": True,
                                                 "mode": "enforcing"}},
                                    {"selinux": {"present": True,
                                                 "mode": "permissive"}})
          + li.seed_ssh_permission_findings(ww)):
    produced.add(f["detection_id"])
check("the module's own comparisons produced ids at all",
      len(produced) >= 6, True)
unregistered = sorted(i for i in produced if not det.exists(i))
check("and every one of them is registered", unregistered, [])


print("\n[10] THE TWO CADENCES STAY APART")
# A 40 second filesystem walk on a 60 second poll is not a slow sensor, it is
# a stalled one. The number is measured, and it has to be the reason the code
# has two clocks rather than one.
check("tier A's interval is the poll interval", li.POLL_INTERVAL, 60)
check("the sweep is hourly", li.SWEEP_INTERVAL, 3600)
check_true("and the sweep cannot be configured below its floor",
           li.SWEEP_MIN_INTERVAL >= 30)
check_true("the first sweep waits, so a boot is not competing with a walk",
           li.FIRST_SWEEP_DELAY >= 30)

ADAPTER = (ROOT / "adapters.py").read_text(encoding="utf-8")
cls = ADAPTER.split("class LinuxLocalIntegrity")[1].split("class LinuxRemediation")[0]
check("the sweep runs on its OWN thread", "_sweep_loop" in cls, True)
check("started from start(), not from poll()",
      "Thread(target=self._sweep_loop" in cls, True)
check("and poll() is tier A only",
      "tier_b_pass" in cls and "def poll" in cls, True)
poll_body = cls.split("def poll")[1].split("def _sweep_loop")[0]
check("poll() does NOT call the sweep",
      "tier_b_pass" in poll_body, False)
check("stop() signals the sweep thread rather than abandoning it",
      "self._sweep_stop.set()" in cls, True)


print("\n[11] THE STATUS CONTRACT: BLIND ONLY FOR REAL FAILURES")
st = li.status_block()
# THE LIST IS SPELLED OUT RATHER THAN DERIVED, so adding a stored set is a
# deliberate act that shows up here. "dpkg" was added on 2026-09-22 with
# tier C and this assertion is where that had to be acknowledged.
check("it reports which baselines exist", sorted(st["baselines_present"]),
      sorted(["files", "dirs", "user_dirs", "ssh", "sweep", "mac", "dpkg"]))
check("and that list is the module's own list, not a second copy",
      sorted(st["baselines_present"]), sorted(li.BASELINE_NAMES))
# The wording rule, enforced on the source: the permanent unelevated limit
# must be STATED, and the module must not use the word "protected" about MAC
# without checking.
check("the module never claims the machine is protected",
      "we are protected" in (ROOT / "tools" / "local_integrity.py"
                             ).read_text(encoding="utf-8").lower()
      and "checked rather than assumed" not in
      (ROOT / "tools" / "local_integrity.py").read_text(encoding="utf-8"),
      False)
check("it says the MAC claim is checked rather than assumed",
      "checked rather than assumed" in
      (ROOT / "tools" / "local_integrity.py").read_text(encoding="utf-8"),
      True)

from adapters import LinuxLocalIntegrity                  # noqa: E402
ad = LinuxLocalIntegrity("test-session", {"sensors": {"local_integrity": {}}})
ad._running = True
# The not-installed state, simulated so it holds on a machine with the helper.
_real_helper_path = li.HELPER_PATH
li.HELPER_PATH = "/nonexistent/agentalsec/read_helper.py"
li.helper_forget()
ad.poll()
s = ad.status()
li.HELPER_PATH = _real_helper_path
li.helper_forget()
check("blind is False on a healthy unelevated run", s["blind"], False)
check("and the metadata-only limit is stated in words, naming the files",
      "/etc/sudoers" in " ".join(s.get("files_metadata_only") or []), True)
check_true("with the consequence spelled out, not implied",
           "NOT detected" in (s.get("coverage_limits") or ""))
check("the status says which host it is about, so it cannot be confused with"
      " linux_monitor", "NOT tools/linux_monitor" in s["scope_note"], True)
check("tier B reports that it has not swept yet, rather than a clean zero",
      s["tier_b"]["sweeps"], 0)
check("tier C reports that it has not run yet, rather than a clean zero",
      s["tier_c"]["runs"], 0)
check_true("and says in words that nothing covers the package files yet",
           "NO PACKAGE VERIFICATION HAS COMPLETED" in (s.get("tier_c_state") or ""))

ad._last_error = "OperationalError: disk"
check("a failed pass IS blind", ad.status()["blind"], True)
check("and says the emptiness is about the sensor",
      "statement about this sensor" in ad.status()["blind_reason"], True)
ad._last_error = None

s = ad.status()
check("an unregistered id is surfaced, not swallowed",
      "unregistered_finding_types" in s, False)   # none yet, so no key


print("\n[12] THE ENTITY VOCABULARY CARRIES 'file' WHEREVER IT IS ENFORCED")
# Three places enforce it and all three had to move in the same sitting, or
# these nine rules would have been rules that could not raise. The incident
# one is the quiet one: write_incident RAISES on an unknown type, the watcher
# catches and counts that, so findings would reach the table and open NO
# incident. The detector runs, the hit is computed, nothing arrives.
check("memory_engine accepts 'file'", "file" in me.VALID_ENTITY_TYPES, True)
from core import incident as inc                          # noqa: E402
try:
    # The path is BUILT, not typed. A literal home path here would be a local
    # detail in a file that ships, which scripts/check_no_local_details.py
    # rightly fails a build over, and it would be wrong on every other machine.
    inc.write_incident(detection_id="LNX-2002", entity_type="file",
                       entity_value=os.path.join(
                           os.path.expanduser("~"), ".ssh", "authorized_keys"),
                       severity="high", title="t", source="local_integrity",
                       modules={})
    check("the incident writer accepts 'file'", True, True)
except Exception as e:
    check("the incident writer accepts 'file'",
          f"{type(e).__name__}: {e}", "ok")

# And a person can dismiss one, which is the reason dismiss_entity validates.
r = me.dismiss_entity("file", "/etc/sudoers", reason="tuning test")
check("a person can dismiss a file finding", r["dismissed"], True)
me.undismiss_entity("file", "/etc/sudoers")

# The old set still works, so nothing was replaced by the addition.
for t in ("ip", "process", "port", "user"):
    me._validate_entity(t, "192.0.2.9")
check("the four original entity types still validate", True, True)


print("\n[13] THE REGISTER TEXT OBEYS THE HOUSE RULES")
text = (ROOT / "core" / "detections.py").read_text(encoding="utf-8")
check("no em dashes in the register", "\u2014" in text, False)
block = text.split("local_integrity, L3, 2026-09-22")[1].split("network_scanner")[0]
check("no pipe characters in the new entries",
      any("|" in line and not line.strip().startswith("#") and "=" not in line
          for line in block.splitlines()), False)
for did in RAISED:
    rule = det.get(did)
    check_true(f"{did} says what makes it fire", (rule.summary or "").strip())
    check_true(f"{did} declares at least one severity", bool(rule.severities))


print("\n[14] TIMESTAMPS ROLLED BACK: THE HOLE THE METADATA WATCH HAD")
# MEASURED ON THIS HOST, 2026-09-22, on a file shaped like /etc/sudoers: write
# the same NUMBER of bytes with different content, then call utime() with the
# recorded mtime, and size, mtime, mode and owner all match the baseline
# EXACTLY. Every field the metadata-only watch had would agree. So a line
# added to sudoers by an unprivileged process was invisible, and ctime is the
# only field left that says so.
import tempfile                                         # noqa: E402
import shutil                                           # noqa: E402

_tmp = tempfile.mkdtemp(prefix="li_stealth_")
_t = os.path.join(_tmp, "sudoers")


def _write(mode=0o440):
    try:
        os.chmod(_t, 0o600)
    except OSError:
        pass
    with open(_t, "w") as fh:
        fh.write("root ALL=(ALL:ALL) ALL\n%sudo ALL=(ALL:ALL) ALL\n")
    os.chmod(_t, mode)


def _record():
    # NOTHING IS WRITTEN HERE, and that is the lesson: a chmod inside this
    # helper stamps ctime and manufactures a hit. The first version of the
    # noise test did exactly that and failed two cases that must be silent.
    return li.file_record(_t, read_content=False)


# The function itself, driven directly.
_same = {"exists": True, "size": 47, "mtime_ns": 100, "mode": "440",
         "uid": 0, "gid": 0, "ctime_ns": 100}
check("ctime unmoved is not a stealth hit",
      li._ctime_only_move(_same, dict(_same)), False)
_moved = dict(_same, ctime_ns=999)
check("ctime moved with EVERYTHING ELSE EQUAL is the stealth case",
      li._ctime_only_move(_same, _moved), True)
check("ctime moved AND mtime moved is ordinary maintenance, not stealth",
      li._ctime_only_move(_same, dict(_moved, mtime_ns=500)), False)
check("ctime moved AND the size moved is an ordinary edit",
      li._ctime_only_move(_same, dict(_moved, size=99)), False)
check("ctime moved AND the mode moved is a chmod",
      li._ctime_only_move(_same, dict(_moved, mode="640")), False)
check("a missing ctime on either side cannot be claimed as stealth",
      li._ctime_only_move({"exists": True}, _moved), False)

# And through the REAL record/compare path, on a real file.
try:
    _write(); _time = __import__("time"); _time.sleep(0.02)
    _r0 = _record()
    os.chmod(_t, 0o600)
    with open(_t, "r+b") as _fh:
        _data = _fh.read()
        _fh.seek(0)
        _fh.write(b"r00t" + _data[4:])          # same length
    os.chmod(_t, 0o440)
    _time.sleep(0.02)
    os.utime(_t, ns=(os.stat(_t).st_atime_ns, _r0["mtime_ns"]))
    _r1 = _record()
    check("every field the OLD watch had matches, which is the hole",
          (_r0["size"] == _r1["size"] and _r0["mtime_ns"] == _r1["mtime_ns"]
           and _r0["mode"] == _r1["mode"]), True)
    _out = li.diff_watched_files({"files": {_t: _r0}}, {"files": {_t: _r1}})
    check("and the module catches it anyway",
          [f["detection_id"] for f in _out], ["LNX-2012"])
    check("at high, which the register declares", _out[0]["severity"], "high")
    check("the finding names the field that gave it away",
          _out[0]["raw_data"]["ctime_before"] != _out[0]["raw_data"]["ctime_after"],
          True)
    check("and says the content could not be read, so it does NOT say what"
          " the file now contains",
          "THE CONTENT COULD NOT BE READ" in _out[0]["description"], True)
    check("and names the innocent causes, so a reader can weigh it",
          "rsync" in _out[0]["description"], True)
finally:
    shutil.rmtree(_tmp, ignore_errors=True)


print("\n[15] AND IT MUST STAY SILENT ON ORDINARY MAINTENANCE")
# The other half, and it is the half that decides whether the rule is worth
# having at all. A rule that fires on every apt run teaches its reader to skim.
_tmp = tempfile.mkdtemp(prefix="li_noise_")
_t = os.path.join(_tmp, "sudoers")
_silent, _noisy = [], []


def _case(label, mutate):
    _write(); __import__("time").sleep(0.02)
    before = _record()
    mutate()
    __import__("time").sleep(0.02)
    after = _record()
    ids = sorted({f["detection_id"] for f in
                  li.diff_watched_files({"files": {_t: before}},
                                        {"files": {_t: after}})})
    (_noisy if "LNX-2012" in ids else _silent).append((label, ids))


try:
    def _edit():
        os.chmod(_t, 0o600)
        with open(_t, "r+") as fh:
            fh.write("extra ALL=(ALL) NOPASSWD: ALL\n")
        os.chmod(_t, 0o440)
    _case("an ordinary edit", _edit)

    def _rewrite():
        os.chmod(_t, 0o600)
        with open(_t, "w") as fh:
            fh.write("# new version from a package\n")
        os.chmod(_t, 0o440)
    _case("a package-style rewrite", _rewrite)

    _case("a plain read", lambda: open(_t, "rb").read())
    _case("a chmod", lambda: os.chmod(_t, 0o640))
    _case("a touch", lambda: os.utime(_t, None))
finally:
    shutil.rmtree(_tmp, ignore_errors=True)

check("five ordinary operations, and NONE of them fires the stealth rule",
      [label for label, _ids in _noisy], [])
check("all five were checked", len(_silent), 5)
check("and the ordinary ones are still caught by the normal rule",
      sorted({i for _l, ids in _silent for i in ids}), ["LNX-2001"])
check("a read of a watched file raises NOTHING at all",
      dict(_silent)["a plain read"], [])


print("\n[16] THE MODULE ONLY EVER OPENS A WATCHED PATH READ-ONLY")
# The recording discipline the stealth rule depends on. If anything in this
# module ever wrote to a watched file, the next pass would see ctime moved and
# raise a finding about this app's own act.
_module_src = (ROOT / "tools" / "local_integrity.py").read_text(encoding="utf-8")
import re as _re                                       # noqa: E402
_writable = _re.findall(r"open\([^)]*[\"'](?:w|a|r\+|w\+|a\+)[\"']", _module_src)
check("no writable open() anywhere in the module", _writable, [])
# The docstring mentions chmod and utime because it MEASURES them; the code
# itself must not call them.
_calls = [ln.strip() for ln in _module_src.splitlines()
          if _re.search(r"^\s*(os\.(chmod|chown|utime|rename|remove)|shutil\.)", ln)]
check("no chmod, chown, utime or rename anywhere in the module", _calls, [])


print("\n[17] THE BASELINES MUST NOT LOOK LIKE POLICY TO THE INTEGRITY JOURNAL")
# THE DEFECT THIS LOCKS DOWN, and it was found in a boot log rather than by
# reading: the first version kept the baselines in user_preferences, which
# core/integrity hashes as "the policy" and journals on ANY change, on the
# contract that such an entry always means the rules changed. A sensor that
# rewrites a baseline whenever a watched file moves would have journalled a
# false "the rules changed" warning every time. It is the T2 cursor bug again.
from core import integrity                              # noqa: E402

check("the baselines live in their own table, not in the policy table",
      li.BASELINE_TABLE, "local_integrity_baseline")
_engine_src = (ROOT / "tools" / "local_integrity.py").read_text(encoding="utf-8")
check("and nothing in the module writes a preference any more",
      "set_preference" in _engine_src, False)

integrity.snapshot_config(reason="test-before")
with me._get_conn() as _c:
    _digest_before = _c.execute(
        "SELECT payload_digest FROM integrity_journal "
        "WHERE operation='config_observed' ORDER BY id DESC LIMIT 1"
    ).fetchone()["payload_digest"]

li.save_baseline("files", {"a": "rewritten by the test"})
li.save_baseline("sweep", {"suid": {"/x": "1"}})
li.save_baseline("mac", {"selinux": {"present": False}})

_snap = integrity.snapshot_config(reason="test-after")
with me._get_conn() as _c:
    _digest_after = _c.execute(
        "SELECT payload_digest FROM integrity_journal "
        "WHERE operation='config_observed' ORDER BY id DESC LIMIT 1"
    ).fetchone()["payload_digest"]

check("writing a baseline does NOT move the policy digest",
      _digest_after, _digest_before)
check("and the snapshot says nothing changed", _snap, None)

# The other half: a REAL policy change must still register, or the check is
# not strict, it is broken.
me.set_preference("deviation_alert_threshold", "9.9")
_moved = integrity.snapshot_config(reason="test-real-change")
check("a genuine preference change still registers", bool(_moved), True)
me.set_preference("deviation_alert_threshold", "2.0")

# And the migration that moved them out: a database with the old keys must
# have them DELETED, because leaving them would leave the journal telling a
# story about a sensor's bookkeeping.
_mig_src = (ROOT / "core" / "migrations.py").read_text(encoding="utf-8")
check("the v42 migration exists", "_migrate_local_integrity_store" in _mig_src, True)
check("it deletes the old keys rather than leaving them",
      "DELETE FROM user_preferences WHERE key LIKE 'local_integrity:%'" in _mig_src,
      True)
check("and it is wired into the runner",
      "local_integrity_added  = _migrate_local_integrity_store(conn)" in _mig_src,
      True)
from core import migrations                             # noqa: E402
check("the schema version moved for it", migrations.SCHEMA_VERSION >= 42, True)
check("and a fresh database creates the same table",
      "local_integrity_baseline" in
      (ROOT / "Schema.SQL").read_text(encoding="utf-8"), True)


print("\n[18] TIER C: dpkg -V. WHAT DPKG ACTUALLY PRINTS, AGAINST THE PARSER")
# THE FIXTURES BELOW ARE REAL OUTPUT, NOT INVENTED ONES. Every line was
# produced by running `dpkg -V` on this host on 2026-09-22 or by running it
# against a fake dpkg root built for the purpose (/tmp/dpkgprobe/probe.py),
# because a parser tested against a shape somebody typed from memory is
# tested against that person's memory.
#
# FAILURE CASES FIRST, and the first one is the worst sentence this sensor
# could produce.

# [18a] PERMISSION DENIED IS NOT A DELETION.
# dpkg prints 'missing <path> (Permission denied)' for a file it could not
# open. MEASURED on this host: every /boot/vmlinuz-* is mode 600 root, so the
# unelevated run says "missing ... (Permission denied)" about all of them.
# Reading that as "your kernel images have been deleted" is the one sentence
# that must never come out of this module.
_denied = li.parse_dpkg_verify(
    "missing     /boot/vmlinuz-7.0.0-31-generic (Permission denied)",
    exclude_boot=False)
check("a file dpkg could not open is UNREADABLE, never gone",
      _denied["paths"]["/boot/vmlinuz-7.0.0-31-generic"]["verdict"], "unreadable")
_gone = li.parse_dpkg_verify("missing     /usr/share/x/gone.txt",
                             exclude_boot=False)
check("and a file with no reason on the line IS gone",
      _gone["paths"]["/usr/share/x/gone.txt"]["verdict"], "gone")
check("because the reason in parentheses is the whole difference",
      _denied["paths"]["/boot/vmlinuz-7.0.0-31-generic"]["reason"],
      "Permission denied")

# [18b] THE CONFFILE MARKER, WHICH APPEARS ON BOTH LINE SHAPES.
# FOUND BY THIS MEASUREMENT. dpkg printed
#   missing   c /etc/polkit-1/rules.d/mintcommon-...rules (Permission denied)
# on the reference host and the first version of the parser handed back
# "c /etc/polkit-1/..." as a path -- which no package owns and no reader can
# act on. One line shape handled in one branch and not the other.
_conf = li.parse_dpkg_verify("??5?????? c /etc/sudoers", exclude_boot=False)
check("the 'c' marker is read as a conffile, not as part of the path",
      sorted(_conf["paths"]), ["/etc/sudoers"])
check_true("and it is flagged as one",
           _conf["paths"]["/etc/sudoers"]["conffile"])
_conf2 = li.parse_dpkg_verify(
    "missing   c /etc/polkit-1/rules.d/x.rules (Permission denied)",
    exclude_boot=False)
check("the SAME marker on a 'missing' line is read the same way",
      sorted(_conf2["paths"]), ["/etc/polkit-1/rules.d/x.rules"])
check_true("with the conffile flag set there too",
           _conf2["paths"]["/etc/polkit-1/rules.d/x.rules"]["conffile"])

# [18c] THE THREE CLASSES, AND /boot AS A KNOB.
_real = ("?????????   /boot/vmlinuz-7.0.0-31-generic\n"
         "??5??????   /usr/share/applications/yelp.desktop\n"
         "??5?????? c /etc/sudoers\n"
         "missing     /var/cache/cups/rss (Permission denied)\n")
with_boot = li.parse_dpkg_verify(_real, exclude_boot=False)
check("with /boot included, all four lines are classified",
      len(with_boot["paths"]), 4)
without = li.parse_dpkg_verify(_real, exclude_boot=True)
check("with /boot excluded, the kernel image is gone from the set",
      "/boot/vmlinuz-7.0.0-31-generic" in without["paths"], False)
check("and the other three are still there", len(without["paths"]), 3)
check("an all-unknown flag column is unreadable",
      without["paths"]["/var/cache/cups/rss"]["verdict"], "unreadable")
check("a digest mismatch is changed, which is the only integrity claim",
      without["paths"]["/usr/share/applications/yelp.desktop"]["verdict"],
      "changed")

# [18d] AN UNRECOGNISED LINE IS COUNTED, NEVER GUESSED AT.
# dpkg's man page says the output format is selectable with --verify-format
# and that the default may change. A shape this parser does not know must not
# become a confident sentence about the machine.
_odd = li.parse_dpkg_verify("some future dpkg format here\n", exclude_boot=False)
check("an unrecognised line is not classified", len(_odd["paths"]), 0)
check("and it is COUNTED rather than dropped silently",
      _odd["unparsed"], ["some future dpkg format here"])


print("\n[19] TIER C: ONE FINDING PER PACKAGE, AND THE CAP ANNOUNCES ITSELF")
# The owner's rule. 55 measured lines about 24 packages is the shape this has
# to compress, and the compression must not lose the count.

_pkg_now = {"by_package": {
    "firefox": {"counts": {"changed": 1, "unreadable": 0, "gone": 0},
                "changed": ["/usr/lib/firefox/distribution/distribution.ini"],
                "unreadable": [], "gone": [], "conffiles": []},
    "gnome-accessibility-themes": {
        "counts": {"changed": 6, "unreadable": 0, "gone": 0},
        "changed": ["/usr/share/icons/HighContrast/16x16/places/start-here.png"],
        "unreadable": [], "gone": [], "conffiles": []},
}, "refused": {}}
_pkg_was = {"by_package": {
    "firefox": {"counts": {"changed": 0, "unreadable": 0, "gone": 0},
                "changed": [], "unreadable": [], "gone": [], "conffiles": []},
    "gnome-accessibility-themes": {
        "counts": {"changed": 0, "unreadable": 0, "gone": 0},
        "changed": [], "unreadable": [], "gone": [], "conffiles": []},
}, "refused": {}}

_changes = li.diff_dpkg(_pkg_was, _pkg_now)
check("two packages that moved produce TWO findings, not eleven",
      len(_changes), 2)
check("and each is one claim about one package",
      sorted(f["entity_value"] for f in _changes),
      ["firefox", "gnome-accessibility-themes"])
check("a non-conffile content difference is HIGH",
      [f["severity"] for f in _changes if f["entity_value"] == "firefox"],
      ["high"])
check("the count of files rides along even though the list is capped",
      [f["raw_data"]["files_changed_now"]
       for f in _changes if f["entity_value"] == "gnome-accessibility-themes"],
      [6])
check("and the finding says WHICH file, not just how many",
      "distribution.ini" in _changes[0]["description"], True)

# A conffile difference is MEDIUM, because an administrator is EXPECTED to
# edit those. MEASURED: /etc/cryptsetup-initramfs/conf-hook and
# /etc/fwupd/fwupd.conf both differ from their shipped versions on this host
# as shipped. A rule that called that high would be high on an untouched box.
_conf_now = {"by_package": {"sudo": {
    "counts": {"changed": 1, "unreadable": 0, "gone": 0},
    "changed": ["/etc/sudoers"], "unreadable": [], "gone": [],
    "conffiles": ["/etc/sudoers"]}}, "refused": {}}
_conf_was = {"by_package": {"sudo": {
    "counts": {"changed": 0, "unreadable": 0, "gone": 0},
    "changed": [], "unreadable": [], "gone": [], "conffiles": []}},
    "refused": {}}
_cf = li.diff_dpkg(_conf_was, _conf_now)
check("a conffile difference is MEDIUM, not high", _cf[0]["severity"], "medium")
check_true("and its description names the innocent cause before the guilty one",
           "EXPECTED to edit" in _cf[0]["description"])

# [19b] the seed pass. The owner's requirement, in code.
_seed_pic = {"at": "x", "by_package": _pkg_now["by_package"], "refused": {}}
check("a diff against an EMPTY baseline raises nothing for a new package",
      li.diff_dpkg({}, _pkg_now), [])

# [19c] the cap says what it cut.
_many = [li._finding("LNX-2006", "high", "file", f"pkg{i}", "t", "d", {})
         for i in range(60)]
_capped = li.cap_dpkg_findings(_many, cap=40)
check("the cap keeps exactly its limit PLUS the summary row",
      len(_capped), 41)
check("and the summary row names the number that did not fit",
      _capped[-1]["raw_data"]["cut"], 20)
check("and the total that was produced", _capped[-1]["raw_data"]["produced"], 60)
check_true("a cap never silently drops: the row says it is capped",
           "not listed" in _capped[-1]["title"])
check("a run under the cap is untouched", len(li.cap_dpkg_findings(_many[:5])), 5)

# [19d] the severity ORDER means a cap keeps the loudest half.
_mixed = ([li._finding("LNX-2005", "medium", "file", f"low{i}", "t", "d", {})
           for i in range(50)]
          + [li._finding("LNX-2006", "high", "file", "the-important-one",
                         "t", "d", {})])
_sorted = sorted(_mixed, key=lambda f: (0 if f["detection_id"] == "LNX-2006" else 1,
                                        f.get("entity_value") or ""))
check("the integrity claim sorts ahead of the coverage claims",
      _sorted[0]["entity_value"], "the-important-one")
check("so a cap on a bad day keeps it", li.cap_dpkg_findings(_sorted, cap=10)[0]
      ["entity_value"], "the-important-one")
check("while the coverage claim that got cut still affects the COUNTS",
      "LNX-2005" in li.cap_dpkg_findings(_sorted, cap=10)[-1]["raw_data"]
      ["by_detection_id"], True)


print("\n[20] TIER C: A RUN THAT DID NOT HAPPEN CHANGES NOTHING")
# The rule this project writes whole modules about: an empty result must carry
# the reason it is empty. Three ways this tier can produce an empty answer
# that is not a clean machine.

# [20a] the lock.
_LOCKED = li.dpkg_verification_pass.__doc__ or ""
check("the lock is checked before dpkg is invoked",
      "_lock_is_held" in
      (ROOT / "tools" / "local_integrity.py").read_text(encoding="utf-8"), True)
import fcntl as _fcntl                                  # noqa: E402
import tempfile as _tempfile                            # noqa: E402
_lkdir = _tempfile.mkdtemp(prefix="li_lock_")
_lkfile = os.path.join(_lkdir, "lock")
open(_lkfile, "w").close()
check("an unheld lock reports as free", li._lock_is_held(_lkfile), False)
try:
    _fh = open(_lkfile, "r+b")
    _fcntl.flock(_fh, _fcntl.LOCK_EX | _fcntl.LOCK_NB)
    check("a HELD lock reports as held", li._lock_is_held(_lkfile), True)
    _fcntl.flock(_fh, _fcntl.LOCK_UN)
    _fh.close()
finally:
    shutil.rmtree(_lkdir, ignore_errors=True)

# [20b] an abort is a coverage finding, not a silent short list.
_aborted = li.dpkg_coverage_findings(
    {"aborted": True, "stderr": "control file 'md5sums' for package "
                                "'example-app' is missing value separator",
     "packages_verified": 2755, "packages_claimed": 2756, "unparsed": []})
check("an aborted run raises exactly one finding", len(_aborted), 1)
check_true("and it says the unverified packages are UNKNOWN, not clean",
           "unknown, not clean" in _aborted[0]["description"])
check_true("and it quotes dpkg's own reason",
           "missing value separator" in _aborted[0]["description"])

# [20c] and the parser's unknown lines raise too.
_unp = li.dpkg_coverage_findings({"aborted": False, "unparsed": ["weird line"],
                                  "lines": 1})
check("unparsed output raises a finding rather than passing quietly",
      len(_unp), 1)
check_true("which says those lines are neither clean nor findings",
           "neither" not in _unp[0]["description"]
           and "not clean results" in _unp[0]["description"])

# [20d] the package dpkg REFUSES. MEASURED: 1 of 2756 on this host.
_refused = li.dpkg_refused_seed_findings(
    {"refused": {"example-app": "unparseable line 1: '87ccd9ca... abbr usr/'"}})
check("a refused package raises on the SEED pass, because it is a coverage hole",
      len(_refused), 1)
check("under LNX-2005, the coverage id", _refused[0]["detection_id"], "LNX-2005")
check_true("and it explains the consequence past the one package",
           "aborts" in _refused[0]["description"])
# RESTATED 2026-09-26. This assertion used to read `"Reinstalling" in
# description` under the label "naming the reinstall as the fix", and it was
# MEASURING THE DEFECT: the sentence it pinned said a reinstall repairs the
# package, and a reinstall cannot repair a separator defect (the installed
# control file is byte-identical to the copy in the vendor's own package,
# measured, so the same bytes are written back). The check is kept and turned
# around -- the finding must name the separator as the repair AND must say the
# reinstall is not it -- because deleting it would have removed the only
# assertion standing where a false instruction once lived.
check_true("it names the SEPARATOR as the actual repair",
           "two or more spaces" in _refused[0]["description"])
check_true("and it says a reinstall is NOT the fix, in words",
           "NOT the fix" in _refused[0]["description"])
check("the seed-pass rows carry that fact so a reader knows why it fired "
      "on a first run", _refused[0]["raw_data"]["on_seed_pass"], True)
_many_refused = li.dpkg_refused_seed_findings(
    {"refused": {f"p{i}": "bad" for i in range(30)}})
check("30 refused packages produce 21 rows, not 30",
      len(_many_refused), li.DPKG_OFFENDER_FINDING_LIMIT + 1)
check("and the last one names how many were not listed",
      _many_refused[-1]["raw_data"]["refused_total"], 30)


print("\n[21] TIER C: THE CADENCE, AND THE CONTROL FILE CHECK")
# [21a] the numbers, and they are measured.
check("a full run took 209s here, so the interval cannot be hourly-or-less",
      li.DPKG_MIN_INTERVAL >= 300, True)
check("the default is three hours", li.DPKG_INTERVAL if hasattr(li, "DPKG_INTERVAL")
      else 10800, 10800)
check("the first run is delayed past the boot, and past the sweep's delay",
      li.FIRST_DPKG_DELAY, 300)
check("the sweep's delay is still the shorter one",
      li.FIRST_DPKG_DELAY > li.FIRST_SWEEP_DELAY, True)
check("the timeout is generous against a measured 209s",
      li.DPKG_TIMEOUT >= 600, True)
check("/boot is excluded by default", li.DPKG_EXCLUDE_BOOT, True)

_cls = ADAPTER.split("class LinuxLocalIntegrity")[1].split("class LinuxRemediation")[0]
check("tier C runs on its OWN thread", "_dpkg_loop" in _cls, True)
check("started from start(), not from poll()",
      "Thread(target=self._dpkg_loop" in _cls, True)
check("and poll() does NOT call it",
      "tier_c_pass" in _cls.split("def poll")[1].split("def _sweep_loop")[0], False)
check("stop() signals the dpkg thread rather than abandoning it",
      "self._dpkg_stop.set()" in _cls, True)
check("the interval has a floor, read from config",
      "DPKG_MIN_INTERVAL" in _cls and "dpkg_interval_seconds" in _cls, True)

# [21b] THE BOOT KNOB IS READ AS A BOOLEAN, NOT BY TRUTHINESS.
# A config value of the string "false" is TRUTHY, and this project has already
# been walked past a security gate by exactly that (§1.9/S7).
for _cfg, _want in (({"dpkg_exclude_boot": True}, True),
                    ({"dpkg_exclude_boot": False}, False),
                    ({"dpkg_exclude_boot": "false"}, False),
                    ({"dpkg_exclude_boot": "no"}, False),
                    ({"dpkg_exclude_boot": "true"}, True),
                    ({"dpkg_exclude_boot": "nonsense"}, True),
                    ({}, True)):
    _a = LinuxLocalIntegrity("t", {"sensors": {"local_integrity": _cfg}})
    check("dpkg_exclude_boot=%r reads as %r" % (_cfg.get("dpkg_exclude_boot",
                                                         "<absent>"), _want),
          _a._dpkg_exclude_boot(), _want)

# [21c] the control-file check, against the shape dpkg refuses.
_cdir = _tempfile.mkdtemp(prefix="li_md5_")
try:
    _good = os.path.join(_cdir, "good.md5sums")
    with open(_good, "w") as _fh:
        _fh.write("87ccd9ca305586f516317bb405ab30d4  usr/share/x/a\n")
    check("a well-formed control file passes", li._md5sums_ok(_good)[0], True)

    _bad = os.path.join(_cdir, "bad.md5sums")
    with open(_bad, "w") as _fh:
        # THE ACTUAL BYTES FROM THIS HOST'S example-app.md5sums.
        _fh.write("87ccd9ca305586f516317bb405ab30d4 usr/share/x/a\n")
    _ok, _why = li._md5sums_ok(_bad)
    check("a MISSING VALUE SEPARATOR is caught before dpkg is run", _ok, False)
    check_true("and the reason names the line rather than the package",
               "line 1" in _why)

    _empty = os.path.join(_cdir, "empty.md5sums")
    open(_empty, "w").close()
    check("an empty control file is fine -- dpkg checks nothing and says so",
          li._md5sums_ok(_empty)[0], True)

    _noperm = os.path.join(_cdir, "noperm.md5sums")
    with open(_noperm, "w") as _fh:
        _fh.write("87ccd9ca305586f516317bb405ab30d4  usr/share/x/a\n")
    os.chmod(_noperm, 0o000)
    if os.geteuid() != 0 and not os.access(_noperm, os.R_OK):
        _ok2, _why2 = li._md5sums_ok(_noperm)
        check("an UNREADABLE control file is refused too, and it is a "
              "DIFFERENT reason", (_ok2, "unreadable" in _why2), (False, True))
    os.chmod(_noperm, 0o644)
finally:
    shutil.rmtree(_cdir, ignore_errors=True)

# [21d] the two ids are registered, and at the severities raised.
check("LNX-2005 is registered",
      det.get("LNX-2005").name, "package_file_unverifiable")
check("LNX-2006 is registered",
      det.get("LNX-2006").name, "package_file_content_changed")
check("and nothing is reserved any more in the 20xx block",
      sorted(i for i in range(2001, 2013)
             if ("LNX-%d" % i) in [d.did for d in det._REGISTER]),
      list(range(2001, 2013)))
_raised_sev = set()
for _f in _changes + _cf + _refused + _aborted:
    _raised_sev.add((_f["detection_id"], _f["severity"]))
    det.check_severity(_f["detection_id"], _f["severity"])
check("every severity these rules raised is one the register declares",
      sorted(_raised_sev),
      [("LNX-2005", "medium"), ("LNX-2006", "high"), ("LNX-2006", "medium")])

# [21e] tier C's own status contract, with runs == 0.
_ds = li.dpkg_status_block()
check("the dpkg status block reports the measured cost rather than a guess",
      "209" in _ds["cost_note"], True)
check_true("and states that a bare run ABORTS", "ABORTS" in _ds["cost_note"])


print("\n" + ("ALL PASS" if not fails else f"{len(fails)} FAILED: {fails}"))
sys.exit(1 if fails else 0)
