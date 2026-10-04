"""
tests/test_local_integrity_fixes.py, the L3 audit round's defects, asserted.

Register section 4 (toolaudit.md), 2026-09-23. Each section below is one LI-n
from bugfinder.md's "THE LOCAL INTEGRITY ROUND ON LINUX, CAPABILITY ROUND",
and each asserts BOTH DIRECTIONS wherever the fix is a detector or a refusal:
a check that stops firing is as broken as one that fires on everything.

Written on a COPY of the operator's database (see _isolate_db) and naming no
host, account, address or path of this machine: a test that pins one box's
private facts is wrong on every other box as well.

Run it directly: python tests/test_local_integrity_fixes.py
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


print("\n[LI-1] THE HASHED DIRECTORY COMPARISON HAD NEVER RUN")
# MEASURED BEFORE THE FIX: tier_a_pass asked `not any(p in
# DIR_WATCH_PRESENCE for p in dirs)` and used the answer for every directory
# in the set, so with /usr/lib/systemd/system in it the answer was always
# "do not compare hashes" and the file-change branch was DEAD for all ten
# hashed directories. An edit to /etc/pam.d/* raised nothing.

# The bug, reproduced against the OLD decision rule, so the test fails if
# somebody reintroduces it.
_presence = li.DIR_WATCH_PRESENCE
_dirs_in_set = {p: {} for p in li.DIR_WATCH_HASHED}
old_rule = not any(p in _presence for p in _dirs_in_set)
check("the old rule says 'do not compare hashes' for the hashed set",
      old_rule, True)

# The new one, per path: a hashed directory IS compared.
stored = {"dirs": {"/etc/pam.d": {"entries": {"common-auth": "644:0:0:1279:AAAA"}}}}
current = {"dirs": {"/etc/pam.d": {"entries": {"common-auth": "644:0:0:1279:BBBB"}}}}
out = li.diff_dir_sets(stored, current, hashed=True, presence_only=_presence)
check("a content-only move in a hashed dir now raises", len(out), 1)
check("with the register's id", out[0]["detection_id"], "LNX-2001")
check("at high, the severity the register declares for contents moving",
      out[0]["severity"], "high")
check("and the finding names the file", out[0]["entity_value"],
      "/etc/pam.d/common-auth")
check("while an IDENTICAL entry raises nothing",
      li.diff_dir_sets(stored, stored, hashed=True, presence_only=_presence), [])

# The presence-only set keeps its contract: additions and removals only.
p_stored = {"dirs": {"/usr/lib/systemd/system": {"entries": {"a.service": "644:0:0:10:AAAA"}}}}
p_changed = {"dirs": {"/usr/lib/systemd/system": {"entries": {"a.service": "600:0:0:10:BBBB"}}}}
check("a content move in the presence-only set still raises nothing",
      li.diff_dir_sets(p_stored, p_changed, hashed=True,
                       presence_only=_presence), [])
p_added = {"dirs": {"/usr/lib/systemd/system": {"entries": {
    "a.service": "644:0:0:10:AAAA", "new.service": "644:0:0:11:CCCC"}}}}
_added = li.diff_dir_sets(p_stored, p_added, hashed=True,
                          presence_only=_presence)
check("but an ADDITION there still does, which is its whole job",
      [f["entity_value"] for f in _added],
      ["/usr/lib/systemd/system/new.service"])


print("\n[LI-2] 'UNREADABLE' IS NOT 'CHANGED' AND NOT 'UNCHANGED'")
# MEASURED BEFORE THE FIX: the entry value carries a hash when the file was
# read and '-' when it was not, so a pass that lost or gained the ability to
# read a file produced a different value string for a file nobody touched,
# and the only sentence available was "Watched file changed" at high. The
# live baseline on this host holds /etc/sudoers.d/0pwfeedback as
# `440:0:0:20:<hash>` while every unelevated pass records `440:0:0:20:-`.
stored = {"dirs": {"/etc/sudoers.d": {"entries": {"drop-in": "440:0:0:20:REALHASH"}}}}
unreadable_now = {"dirs": {"/etc/sudoers.d": {"entries": {"drop-in": "440:0:0:20:-"}}}}
out = li.diff_dir_sets(stored, unreadable_now, hashed=True, presence_only=_presence)
check("the read-to-unreadable transition raises exactly one finding",
      len(out), 1)
check("and it is NOT the content claim", out[0]["title"],
      "Watched file could not be read on this pass: /etc/sudoers.d/drop-in")
check("at medium, because it is a coverage fact rather than an edit",
      out[0]["severity"], "medium")
check_true("the wording says the edit would NOT be detected",
           "would NOT be detected" in out[0]["description"])
check("with both hash fields exposed to a machine reader",
      (out[0]["raw_data"]["hash_before"], out[0]["raw_data"]["hash_after"]),
      ("REALHASH", None))

# The other direction: readable for the first time is a first look, not a
# change, and it must say so.
first_look = li.diff_dir_sets(unreadable_now, stored, hashed=True,
                              presence_only=_presence)
check("unreadable-to-readable also raises one", len(first_look), 1)
check_true("and says it is the FIRST real look rather than a change",
           "first real look" in first_look[0]["description"])

# A REAL content move, with both sides read, is still high and still says so.
real = {"dirs": {"/etc/sudoers.d": {"entries": {"drop": "440:0:0:20:AAAA"}}}}
real2 = {"dirs": {"/etc/sudoers.d": {"entries": {"drop": "440:0:0:20:CCCC"}}}}
check("a real content move is still the high content claim",
      (li.diff_dir_sets(real, real2, hashed=True, presence_only=_presence)
       [0]["severity"]), "high")

# A metadata move is its own sentence, and a WIDENING is louder than a
# narrowing -- the register lets LNX-2001 carry both and the first version
# raised every metadata move at high.
meta_widen = {"dirs": {"/etc/cron.d": {"entries": {"job": "600:0:0:20:AAAA"}}}}
meta_wider = {"dirs": {"/etc/cron.d": {"entries": {"job": "664:0:0:20:AAAA"}}}}
check("a widening is high",
      li.diff_dir_sets(meta_widen, meta_wider, hashed=True,
                       presence_only=_presence)[0]["severity"], "high")
# The narrowing direction: 664 -> 600 removes bits rather than adding them,
# so the same comparison must drop to medium. A fix that called every
# metadata move high would be the first version of this code, and a fix that
# called every one medium would hide the widening.
meta_narrow = {"dirs": {"/etc/cron.d": {"entries": {"job": "600:0:0:20:AAAA"}}}}
check("a metadata move that does NOT widen is medium",
      li.diff_dir_sets(meta_wider, meta_narrow, hashed=True,
                       presence_only=_presence)[0]["severity"], "medium")
check("and a size move alone is medium too",
      li.diff_dir_sets(meta_widen,
                       {"dirs": {"/etc/cron.d": {"entries": {"job": "600:0:0:99:AAAA"}}}},
                       hashed=True, presence_only=_presence)[0]["severity"],
      "medium")

# A malformed entry is compared as an opaque string and says so rather than
# guessing which field moved.
check("a value that does not parse is reported as a shape change",
      li.diff_dir_sets({"dirs": {"/d": {"entries": {"f": "garbage"}}}},
                       {"dirs": {"/d": {"entries": {"f": "other"}}}},
                       hashed=True, presence_only=_presence)[0]["title"],
      "Watched directory entry changed shape: /d/f")


print("\n[LI-3] THE SSH DIRECTORY ITSELF IS COMPARED")
# MEASURED BEFORE THE FIX: `.ssh` is stored as a mode:uid:gid STRING while
# every file in it is a dict, and diff_ssh began with an isinstance(now, dict)
# guard, so a home whose .ssh went 700 -> 777 raised NOTHING -- the exact
# fact LNX-2003 exists for, one directory up from where it was checked.
old = {"ssh": {"entries": {
    "/home/x/.ssh": "700:1000:1000",
    "/home/x/.ssh/authorized_keys": {"readable": True, "mode": "600",
                                     "uid": 1000, "gid": 1000,
                                     "lines": {"k": "ssh-ed25519 a"}}}}}
new = {"ssh": {"entries": {
    "/home/x/.ssh": "777:1000:1000",
    "/home/x/.ssh/authorized_keys": {"readable": True, "mode": "600",
                                     "uid": 1000, "gid": 1000,
                                     "lines": {"k": "ssh-ed25519 a"}}}}}
out = li.diff_ssh(old, new)
check("a world-writable .ssh directory now raises", len(out), 1)
check("with the permissions id", out[0]["detection_id"], "LNX-2003")
check("at high, because world-writable is the loud direction",
      out[0]["severity"], "high")
check("naming the DIRECTORY rather than a file in it",
      out[0]["entity_value"], "/home/x/.ssh")
check("and saying what world-writable actually buys an attacker",
      out[0]["raw_data"]["world_writable"], True)
check("an unchanged .ssh raises nothing",
      li.diff_ssh(new, new), [])
check("a narrowing of .ssh is a change but not the high one",
      li.diff_ssh(new, old)[0]["severity"], "medium")


print("\n[LI-4] A CHANGED known_hosts IS NOT 'A KEY WAS ADDED'")
# MEASURED BEFORE THE FIX: every SSH artifact was described with the
# authorized_keys sentence. A line added to ~/.ssh/config or known_hosts
# produced "SSH key added to <path> ... A key in this file grants standing
# access that survives a password change, and it works from anywhere" --
# which is FALSE about both files. Only authorized_keys grants access.
def _ssh_file(path, lines):
    return {"ssh": {"entries": {path: {"readable": True, "mode": "644",
                                       "uid": 1000, "gid": 1000,
                                       "lines": lines}}}}


before = _ssh_file("/home/x/.ssh/known_hosts", {"h1": "ssh-ed25519 hostA"})
after = _ssh_file("/home/x/.ssh/known_hosts",
                  {"h1": "ssh-ed25519 hostA", "h2": "ssh-ed25519 hostB"})
out = li.diff_ssh(before, after)
check("a new known_hosts line still raises, because it is worth seeing",
      len(out), 1)
check("but it is not titled as a key being added",
      out[0]["title"], "New entry in /home/x/.ssh/known_hosts")
check_true("and it does NOT claim the file grants access to this machine",
           "grants nobody access TO this machine" in out[0]["description"])
check("the key sentence is gone from it",
      "standing access that survives" in out[0]["description"], False)

# The control: authorized_keys still gets the loud sentence, because there it
# is true. A fix that quietened this file too would be the same defect
# pointing the other way.
ak_before = _ssh_file("/home/x/.ssh/authorized_keys", {"k1": "ssh-ed25519 a"})
ak_after = _ssh_file("/home/x/.ssh/authorized_keys",
                     {"k1": "ssh-ed25519 a", "k2": "ssh-ed25519 b"})
ak = li.diff_ssh(ak_before, ak_after)
check("authorized_keys still raises as a key being added",
      ak[0]["title"], "SSH key added to /home/x/.ssh/authorized_keys")
check_true("and still carries the standing-access sentence",
           "standing access that survives" in ak[0]["description"])
check("at high", ak[0]["severity"], "high")

cfg_before = _ssh_file("/home/x/.ssh/config", {"c1": "Host a"})
cfg_after = _ssh_file("/home/x/.ssh/config", {"c1": "Host a", "c2": "Host b"})
cfg = li.diff_ssh(cfg_before, cfg_after)
check_true("a config change is described as client configuration",
           "SSH CLIENT" in cfg[0]["description"])


print("\n[LI-5] EVERY known_hosts LINE HAS A NAME, NOT 'unrecognised line'")
# MEASURED BEFORE THE FIX: the label was built only for authorized_keys, so
# every known_hosts line was stored as the literal string "unrecognised
# line" -- the live baseline on this host holds two of them -- and a finding
# about known_hosts therefore named nothing a reader could act on.
import tempfile                                       # noqa: E402
import shutil                                         # noqa: E402

home = tempfile.mkdtemp(prefix="li_sshlabel_")
sshdir = pathlib.Path(home) / ".ssh"
sshdir.mkdir()
(sshdir / "known_hosts").write_text(
    "hostA.example.invalid ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\n"
    "hostB.example.invalid ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD\n")
(sshdir / "config").write_text("Host alpha\n    HostName alpha.example.invalid\n")

_recorded = {}


def _fake_homes():
    return [{"user": "x", "home": home}]


_real_homes = li._homes
li._homes = _fake_homes
try:
    got = li.collect_ssh()
finally:
    li._homes = _real_homes
shutil.rmtree(home, ignore_errors=True)

kh = got["entries"][str(sshdir / "known_hosts")]["lines"]
labels = sorted(kh.values())
check("both known_hosts lines are recorded", len(kh), 2)
check("and every one has a real label rather than the placeholder",
      [l for l in labels if l == "unrecognised line"], [])
check_true("the label carries the key type and the host",
           all("ssh-" in l for l in labels))
cfg_lines = got["entries"][str(sshdir / "config")]["lines"]
check_true("and a config line carries its directive",
           any("Host" in l for l in cfg_lines.values()))


print("\n[LI-6] THE XATTR COUNTER COUNTS REFUSALS, NOT ABSENCES")
# MEASURED BEFORE THE FIX: any getxattr failure incremented
# xattr_unreadable, and the ordinary failure on this host is ENODATA -- the
# kernel ANSWERING "this file has no capability". The count came out 19,382
# in a sweep where a straight walk of /usr/bin found 1,765 ENODATA and ZERO
# real refusals, and that number rode in LNX-2010 as a blind spot.
import errno as _errno                                # noqa: E402

# Drive the real walk over a directory this process owns, comparing the
# counter against the errno classes actually met.
probe = tempfile.mkdtemp(prefix="li_xattr_")
try:
    for i in range(3):
        p = os.path.join(probe, f"exe{i}")
        open(p, "w").write("#!/bin/sh\n")
        os.chmod(p, 0o755)
    _real_getxattr = os.getxattr
    seen = {"ENODATA": 0, "other": 0}

    def counting(path, name, *a, **kw):
        try:
            return _real_getxattr(path, name, *a, **kw)
        except OSError as e:
            if e.errno == _errno.ENODATA:
                seen["ENODATA"] += 1
            else:
                seen["other"] += 1
            raise

    os.getxattr = counting
    try:
        walked = li.sweep_filesystem()
    finally:
        os.getxattr = _real_getxattr
finally:
    shutil.rmtree(probe, ignore_errors=True)

check_true("the walk met real ENODATA answers, so the case is exercised",
           seen["ENODATA"] > 0)
check("and counted NONE of them as unreadable",
      walked["xattr_unreadable"], seen["other"])

# And the finding that publishes it is raised only when the count is real,
# under its own entity so it cannot be confused with the directory finding.
check("no false xattr finding when there was no refusal",
      [f["entity_value"] for f in
       li.sweep_coverage_findings({"unreadable_dirs": [], "files_seen": 10,
                                   "unhashable": 0, "xattr_unreadable": 0})],
      [])
_real = li.sweep_coverage_findings({"unreadable_dirs": [], "files_seen": 10,
                                    "unhashable": 0, "xattr_unreadable": 7})
check("a real refusal count does raise, under its own entity",
      [f["entity_value"] for f in _real], ["filesystem-sweep-xattrs"])
check_true("and the wording says ENODATA is an answer rather than a failure",
           "ENODATA" in _real[0]["description"])


print("\n[LI-7] THE SWEEP'S SEVERITIES ARE THE REGISTER'S, PER CHANGE")
# MEASURED BEFORE THE FIX: one severity per id was used for all three
# changes, so a setuid bit CLEARED was high where LNX-2007's own text says
# medium, and a setgid file whose CONTENTS changed was medium where
# LNX-2008's text says high. Both directions were wrong.
_removed_suid = li.diff_sweep({"suid": {"/a": "h"}, "sgid": {}, "caps": {}},
                              {"suid": {}, "sgid": {}, "caps": {}})
check("a setuid bit cleared is medium, as declared",
      _removed_suid[0]["severity"], "medium")
_replaced_sgid = li.diff_sweep({"suid": {}, "sgid": {"/b": "h"}, "caps": {}},
                               {"suid": {}, "sgid": {"/b": "H"}, "caps": {}})
check("a setgid file REPLACED is high, as declared",
      _replaced_sgid[0]["severity"], "high")
_added_sgid = li.diff_sweep({"suid": {}, "sgid": {}, "caps": {}},
                            {"suid": {}, "sgid": {"/b": "h"}, "caps": {}})
check("a new setgid file is medium, as declared",
      _added_sgid[0]["severity"], "medium")
_removed_sgid = li.diff_sweep({"suid": {}, "sgid": {"/b": "h"}, "caps": {}},
                              {"suid": {}, "sgid": {}, "caps": {}})
check("a setgid bit cleared is low, as declared",
      _removed_sgid[0]["severity"], "low")
_added_suid = li.diff_sweep({"suid": {}, "sgid": {}, "caps": {}},
                            {"suid": {"/a": "h"}, "sgid": {}, "caps": {}})
check("a new setuid file is still high", _added_suid[0]["severity"], "high")

# Every severity raised above is one the register actually declares, proven
# by calling the register's own checker rather than by reading it.
for f in (_removed_suid + _replaced_sgid + _added_sgid + _removed_sgid
          + _added_suid):
    det.check_severity(f["detection_id"], f["severity"])
check("every one of those severities is DECLARED by its rule", True, True)


print("\n[LI-8] THE CONFFILE SEVERITY IS DECIDED PER PATH, NOT PER PACKAGE")
# MEASURED 2026-09-23: the first version asked `bool(now.get("conffiles"))`
# -- does this package have ANY conffile in the changed bucket -- and used
# the answer for the whole package, so a package with one changed conffile
# and one changed BINARY produced ONE row at medium. The register's words
# for LNX-2006 are "High when the file is not a conffile -- the shape of a
# binary or library replaced in place".
def _dpkg_pair(changed, conffiles, was_changed=()):
    return ({"by_package": {"pkg": {"counts": {"changed": len(was_changed)},
                                    "changed": list(was_changed),
                                    "unreadable": [], "gone": [],
                                    "conffiles": []}}, "refused": {}},
            {"by_package": {"pkg": {"counts": {"changed": len(changed)},
                                    "changed": list(changed),
                                    "unreadable": [], "gone": [],
                                    "conffiles": list(conffiles)}},
             "refused": {}})


old, new = _dpkg_pair(["/etc/pkg/thing.conf", "/usr/bin/thing"],
                      ["/etc/pkg/thing.conf"])
out = li.diff_dpkg(old, new)
check("one row for the package, as the owner's rule requires", len(out), 1)
check("and it is HIGH, because one of the files is not a conffile",
      out[0]["severity"], "high")
check("with the non-conffile path named in the data",
      out[0]["raw_data"]["nonconffiles_involved"], ["/usr/bin/thing"])
check_true("and in the words a person reads",
           "/usr/bin/thing" in out[0]["description"])

# The control: a package whose ONLY changed file is a conffile stays medium,
# because a conffile is the class an administrator is expected to edit.
old, new = _dpkg_pair(["/etc/pkg/thing.conf"], ["/etc/pkg/thing.conf"])
out = li.diff_dpkg(old, new)
check("a conffile-only change is still medium", out[0]["severity"], "medium")
check("and titled as a configuration file change", out[0]["title"],
      "Configuration file changed since install: pkg")

# And a package with no conffile at all is unchanged: high.
old, new = _dpkg_pair(["/usr/bin/thing"], [])
check("a non-conffile-only change is high",
      li.diff_dpkg(old, new)[0]["severity"], "high")


print("\n[LI-9] THE dpkg LOCK QUESTION IS ANSWERED IN THREE STATES")
# MEASURED BEFORE THE FIX, two ways at once: the probe opened the lock file
# "r+b" and dpkg's lock files are mode 640 root:root, so an unelevated caller
# got PermissionError and was told "free" for a file it never opened; and it
# tested FLOCK where dpkg and apt take a POSIX record lock, which on Linux
# the two do not see in each other.
state, why = li.dpkg_lock_state()
check_true("the probe answers with one of the three states",
           state in ("held", "free", "unknown"))
check_true("and always with a sentence", bool(why))

# The real thing: take a POSIX write lock on a file and confirm the parser
# sees it. Driven against a scratch pair rather than dpkg's own files so the
# test neither needs root nor disturbs a package manager.
import fcntl as _fcntl                                # noqa: E402

_lockdir = tempfile.mkdtemp(prefix="li_lockstate_")
_lf = os.path.join(_lockdir, "lock")
open(_lf, "w").close()
_fh = open(_lf, "r+b")
_fcntl.lockf(_fh, _fcntl.LOCK_EX | _fcntl.LOCK_NB)
try:
    st = os.stat(_lf)
    _real_paths = li.DPKG_LOCK_PATHS
    li.DPKG_LOCK_PATHS = (_lf,)
    try:
        held_state, held_why = li.dpkg_lock_state()
    finally:
        li.DPKG_LOCK_PATHS = _real_paths
finally:
    _fcntl.lockf(_fh, _fcntl.LOCK_UN)
    _fh.close()
    shutil.rmtree(_lockdir, ignore_errors=True)

check("a POSIX write lock on a lock file reads as HELD",
      held_state, "held")
check_true("and the sentence names the pid that holds it", "pid" in held_why)

# 'unknown' is its own answer rather than being folded into 'free'.
_real_paths = li.DPKG_LOCK_PATHS
li.DPKG_LOCK_PATHS = ("/nonexistent/lock-one", "/nonexistent/lock-two")
try:
    unknown_state, unknown_why = li.dpkg_lock_state()
finally:
    li.DPKG_LOCK_PATHS = _real_paths
check("a lock file that cannot be stat'ed is UNKNOWN, not free",
      unknown_state, "unknown")
check_true("with the consequence stated", "cannot say" in unknown_why)

# And the pass reports which of the three it got, so a run that proceeded on
# an UNKNOWN lock is visible rather than silent.
check_true("dpkg_verification_pass publishes its lock_state",
           "lock_state" in
           (ROOT / "tools" / "local_integrity.py").read_text(encoding="utf-8"))


print("\n[LI-10] THE `enabled` KEY IS HONOURED, IN BOTH DIRECTIONS")
# MEASURED BEFORE THE FIX: `sensors.local_integrity.enabled` was read by
# NOTHING -- zero readers in the tree -- while every neighbouring sensor
# honours its own. An operator's switch that does not switch is worse than no
# switch, because it is a control they believe they have.
from adapters import LinuxLocalIntegrity                 # noqa: E402

off = LinuxLocalIntegrity("t", {"sensors": {"local_integrity":
                                            {"enabled": False}}})
off._running = True
off.poll()
_s = off.status()
check("with the sensor OFF, the poll does no work", _s["tier_a"]["passes"], 0)
check("and the status says off-by-config rather than clean",
      _s.get("off_by_config"), True)
check_true("with a sentence saying a quiet answer is not a clean machine",
           "not a clean machine" in (_s.get("note") or ""))
check("and it is NOT reported as blind, which is a different state",
      _s["blind"], False)

on = LinuxLocalIntegrity("t", {"sensors": {"local_integrity":
                                           {"enabled": True}}})
on._running = True
on.poll()
_s2 = on.status()
check("with the sensor ON, the poll runs", _s2["tier_a"]["passes"], 1)
check("and off_by_config is absent", bool(_s2.get("off_by_config")), False)

# The default is ON, so an install that says nothing keeps the sensor that
# found this round's defects in the first place.
default = LinuxLocalIntegrity("t", {"sensors": {"local_integrity": {}}})
default._running = True
default.poll()
check("an absent key leaves it ON", default.status()["tier_a"]["passes"], 1)

# And the two heavy threads do not start either.
_src = (ROOT / "adapters.py").read_text(encoding="utf-8")
_cls = _src.split("class LinuxLocalIntegrity")[1].split("class LinuxRemediation")[0]
_start_body = _cls.split("def start")[1].split("def stop")[0]
check("start() checks enabled before spawning the sweep thread",
      "_sweep_stop = threading.Event()" in _start_body, True)
check("and the check comes FIRST, before that line",
      _start_body.index('cfg.get("enabled") is False')
      < _start_body.index("_sweep_stop = threading.Event()"), True)


print("\n[LI-11] THE SWEEP'S OWN LIMIT IS STATED, NOT IMPLIED")
_src_mod = (ROOT / "tools" / "local_integrity.py").read_text(encoding="utf-8")
check_true("the module says the sweep cannot name a package",
           "THE SWEEP IS ANONYMOUS" in _src_mod)
check_true("and points at the check that can (tier C)",
           "dpkg -V (tier C)" in _src_mod or "dpkg -V is the check" in _src_mod)


print("\n[LI-12] EVERY ID AND SEVERITY THIS ROUND TOUCHED IS STILL REGISTERED")
for did, severities in (("LNX-2001", ("medium", "high")),
                        ("LNX-2002", ("high",)),
                        ("LNX-2003", ("medium", "high")),
                        ("LNX-2007", ("medium", "high")),
                        ("LNX-2008", ("low", "medium", "high")),
                        ("LNX-2010", ("medium",))):
    rule = det.get(did)
    check_true(f"{did} is registered", bool(rule))
    for sev in severities:
        det.check_severity(did, sev)          # raises if undeclared
    check(f"{did} declares every severity raised for it", True, True)

# And the register's own text still matches what the code raises, which is
# the property LI-7 was about: the page and the code are the same claim.
check_true("LNX-2008's summary still says contents-changed is high",
           "contents changed" in det.get("LNX-2008").summary)


print("\n" + ("ALL PASS" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
