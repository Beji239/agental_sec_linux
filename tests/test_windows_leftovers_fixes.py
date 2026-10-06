"""
tests/test_windows_leftovers_fixes.py, the Windows surface is GONE from the
Linux build, and the Linux tooling it was tangled up with still works.

THE ROUND THIS FILE CLOSES. The owner's instruction, quoted: "those areas of
the app that have code specifically for windows are unnecessary in Linux
version ... Please locate those windows related parts of the code that are
showing in the setting app and uninstall them."

WHAT IT WAS ABOUT. The Settings card painted TWO RED ROWS, in every sample,
forever: "Defender detections" and "Windows Security channel". Neither could
ever go green -- they were Windows capabilities, absent by construction at any
elevation -- and the second one explained itself by naming the event monitor,
A SENSOR THAT WAS WORKING FINE. So a working sensor read as the broken thing on
the page, which is how this started.

WHAT THIS FILE ASSERTS, in three parts:

  [1] THE SURFACE IS GONE, BY NAME. Every verb, constant, table and helper that
      left this round is asserted ABSENT, so a future session that adds one
      back has to delete the check first. This is the half that cannot be got
      right by reading the diff: it is the list, and the list has to be whole.

  [2] THE LINUX TOOLING THAT SURVIVED STILL WORKS, driven rather than imported.
      list_processes, process_table, trust_of, signatures_for, odd_path_reason,
      inspect_process and the capability shim are all called here, on this
      machine, and their answers are checked. A removal round that leaves the
      survivors broken is not a removal round.

  [3] THE TWO PROPERTIES THE REMOVED CODE WAS GUARDING ARE STILL GUARDED, one
      layer down and in this platform's own words. This is the part that makes
      the round safe rather than tidy:
        * the privileged surface is still small and still refuses to be a
          general instruction
        * a dead thing is still LOUD -- asserted on the surfaces this platform
          has (the shim's refusals and the readiness card's failing-polls
          branch) rather than on a helper process that never existed here.

EVERY CHECK DRIVES A SHIPPED FUNCTION OR READS THE SHIPPED SOURCE. None of them
reimplements the thing it is checking, and the source-reading ones strip
comments first, because the paragraph explaining a removal names what was
removed.

Runs anywhere Linux does. No network, no database of its own, no root.
"""
import os
import pathlib
import sys
import _skip

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import _isolate_db                                        # noqa: E402
_isolate_db.isolate()

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}"
          + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


def check_true(label, got):
    check(label, bool(got), True)


def code_only(text):
    """
    The source with its line comments stripped.

    THE COMMENT EXPLAINING A REMOVAL NAMES WHAT WAS REMOVED, so a whole-file
    search for a deleted symbol finds the paragraph saying it is deleted and
    reports a survivor. Stripping is not tidiness; the strip is what makes the
    assertion mean what its label says.
    """
    out = []
    for line in text.splitlines():
        head = line.split("#", 1)[0]
        if head.strip():
            out.append(head)
    return "\n".join(out)


def tree_source(rel):
    return (ROOT / rel).read_text(encoding="utf-8")


# [1] THE SURFACE IS GONE, BY NAME

print("\n[1] every Windows name that left this round is absent, by name")

from core import capabilities as caps                     # noqa: E402
from core import heartbeat                                # noqa: E402
from tools import process_monitor as pm                   # noqa: E402

# THE CAPABILITY SHIM. Verbs first, then the module-level constants that
# existed only to serve them.
for verb in ("event_log_open", "event_log_bounds", "event_log_read",
             "event_log_close", "firewall_add", "firewall_delete",
             "firewall_list", "defender_detections"):
    check(f"caps.Capabilities has no {verb}", hasattr(caps.Capabilities, verb),
          False)
for const in ("WIN32_AVAILABLE", "NPCAP_KEY", "npcap_admin_only",
              "NOT_ON_THIS_PLATFORM", "MODE_INPROCESS", "set_instance",
              "PRIVILEGED_CHANNELS", "RULE_PREFIX", "NETSH_DIR",
              "CANNOT_WITHOUT_ADMIN", "LIMITED_WITHOUT_ADMIN"):
    check(f"core.capabilities has no {const}", hasattr(caps, const), False)

# AND NO ROW FOR EITHER CAPABILITY, which is the half that was on screen.
_avail = caps.get().availability()
check("no 'security_log' row is published", "security_log" in _avail, False)
check("no 'defender' row is published", "defender" in _avail, False)
check("and no row carries a platform-absence kind",
      [n for n, r in _avail.items()
       if r.get("kind") == "not_on_this_platform"], [])

# THE PROCESS MONITOR: the Windows poll loop, the Defender reader, the
# PowerShell sweep, the Windows path lists.
for name in ("_PS_SIGNATURE", "_check_chunk", "_as_text", "_short_signer",
             "_parse_defender_payload", "_group_detections", "_defender_title",
             "_defender_description", "_defender_severity", "THREAT_STATUS",
             "EXECUTION_STATUS", "DETECTION_SOURCE", "THREAT_SEVERITY",
             "SIG_CHUNK", "SIG_CHUNK_TIMEOUT", "SIG_DEADLINE",
             "ODD_PATH_MARKERS", "LOW_SIGNAL_PATHS", "WHITELISTED_PATHS",
             "SYSTEM_BINARY_ROOTS", "SYSTEM_ROOT_EXCEPTIONS",
             "SUSPICIOUS_PATHS", "_SYSTEM_DRIVE", "_on_system_drive",
             "_is_plausible_system_location", "_is_whitelisted",
             "CLEANING_ACTION"):
    check(f"tools.process_monitor has no {name}", hasattr(pm, name), False)
check("and no ProcessMonitor class", hasattr(pm, "ProcessMonitor"), False)
check("and no Defender poll helper", hasattr(pm, "_check_defender"), False)

# THE HEARTBEAT: the branch that watched a helper process this platform does
# not have.
check("core.heartbeat has no _helper_note", hasattr(heartbeat, "_helper_note"),
      False)

# AND THE SOURCE ITSELF DOES NOT CALL A WINDOWS PROGRAM. Read from the file
# this application RUNS, with comments stripped, so the explanatory prose does
# not count as a call.
for rel in ("core/capabilities.py", "tools/process_monitor.py",
            "core/heartbeat.py"):
    src = code_only(tree_source(rel))
    for token in ("win32evtlog", "powershell", "Get-MpThreatDetection",
                  "Get-AuthenticodeSignature", "netsh", "winreg", "Npcap"):
        check(f"{rel} never calls {token}", token in src, False)
    check(f"{rel} imports no Windows module",
          any(f"import {m}" in src or f"from {m}" in src
              for m in ("win32api", "win32con", "win32file", "wmi")), False)

# The stripper has to actually strip, or [1] goes green for the wrong reason.
check("a commented-out call does not count",
      "powershell" in code_only("# powershell -Command x"), False)
check("but a real one still does",
      "powershell" in code_only('x = "powershell"'), True)

# THE MOVED FILES. Out of the tree, present in the reference folder beside it.
_ref = ROOT.parent / "agental_sec_win32_reference"
check("core/privilege.py is out of the live tree",
      (ROOT / "core" / "privilege.py").exists(), False)
check("core/dpapi.py is out of the live tree",
      (ROOT / "core" / "dpapi.py").exists(), False)
check("core/dpapi_linux.py is renamed rather than left under a Windows name",
      (ROOT / "core" / "dpapi_linux.py").exists(), False)
check("and the module that replaces it is here",
      (ROOT / "core" / "secret_crypto.py").exists(), True)
if not (_ref.is_dir()):
    _skip.skip_part('the Windows reference folder is local, not in a clone')
else:
    for moved in ("core/privilege.py", "core/dpapi.py"):
        check(f"the reference folder kept {moved}", (_ref / moved).exists(), True)

    # AND NOTHING LIVE REACHES THE REFERENCE FOLDER. Asserted by running the
    # tree's OWN audit script rather than by re-listing filenames here: a hand-typed
    # list of "files that may name it" drifts the moment somebody writes a comment,
    # which is what happened to the first draft of this check. The script exists for
    # this question (scripts/audit_windows_leftovers.py), its two conclusion lines
    # are the claim, and it fails loudly if the folder was deleted rather than
    # moved.
    import subprocess as _sp                                  # noqa: E402

    _audit = _sp.run([sys.executable,
                      str(ROOT / "scripts" / "audit_windows_leftovers.py")],
                     capture_output=True, text=True, cwd=str(ROOT), timeout=120)
    check("the tree's own leftovers audit runs", _audit.returncode, 0)
    _lines = (_audit.stdout or "").splitlines()


    def _conclusion(prefix):
        hits = [ln for ln in _lines if ln.strip().startswith(prefix)]
        return hits[0].strip() if hits else "(the script did not report it)"


    check("the audit says nothing LIVE imports from the reference folder",
          _conclusion("LIVE modules that IMPORT from it:"),
          "LIVE modules that IMPORT from it: 0")
    check("and it found the reference folder rather than a deletion",
          any("reference: agental_sec_win32_reference/" in ln for ln in _lines),
          True)
    check("and it reports no win32/ folder left inside the tree",
          any("a win32/ folder inside the tree: none" in ln for ln in _lines), True)
    # Every mention it does report is a path in prose, which is the WANTED case: the
    # four refusal arms and the module headers name where the Windows file is KEPT,
    # so an operator reading one goes to the right place instead of nowhere.
    _named_line = _conclusion("LIVE modules that NAME it in prose:")
    _named = int(_named_line.split(":")[1])
    # The script prints each one, indented, under the count. THIS CHECK IS THE
    # PAIR: the count and the list have to agree, because a count nobody can check
    # is the "prose number nobody measured" fault this project keeps finding. Both
    # sides are read off the script's OWN output, so neither is typed here.
    _printed = [ln.strip() for ln in _lines
                if ln.strip().endswith(".py") and ln.startswith("      ")]
    print(f"    {_named} live file(s) name the reference folder in prose: "
          f"{', '.join(_printed)}")
    check("the count and the printed list agree", len(_printed), _named)
    check_true("every one of them is a file that exists",
               all((ROOT / p).is_file() for p in _printed))

# [2] THE LINUX TOOLING SURVIVED, DRIVEN

print("\n[2] the shared process reads still answer, on this machine")

verbs = [n for n in dir(caps.Capabilities())
         if not n.startswith("_") and callable(getattr(caps.Capabilities(), n))
         and n != "availability"]
check("the privileged surface is the six this platform has, no more",
      sorted(verbs),
      sorted(["capture_open", "process_kill", "process_details", "conn_table"]))
check("and availability() reports exactly those six capabilities",
      sorted(_avail),
      sorted(["capture", "firewall_write", "firewall_read", "process_kill",
              "process_details", "conn_table"]))

got = pm.list_processes(limit=50)
check("list_processes answers", got.get("available"), True)
check_true("with rows in it", len(got.get("processes") or []) > 0)
check("and every row carries the colour inputs",
      all("pid" in r and "name" in r for r in got["processes"]), True)

table = pm.process_table(limit=25)
check("process_table answers", table.get("available"), True)
check("every row has a colour the page knows",
      all(r.get("trust") in pm.TRUST_LEVELS for r in table["processes"]), True)
check("the counts add up to the total",
      sum(table["counts"].values()), table["total"])
check("and it says what the colours rest on",
      bool(table.get("signature_check")), True)

me_row = pm.inspect_process(os.getpid())
check("inspect_process finds this very process", me_row["found"], True)
check("and answers about it without raising",
      isinstance(me_row["process"].get("sha256"), (str, type(None))), True)

# THE SIGNATURE BASIS IS THE PACKAGE MANAGER, and it says so in this platform's
# words rather than in Authenticode's.
_tool = pm._package_tool()
check_true("this host has a package manager the sweep can ask", _tool)
sig = pm.signatures_for(["/usr/bin/bash"], {})
check("a packaged binary comes back with a verdict",
      (sig.get("/usr/bin/bash") or {}).get("status") in
      ("Valid", "HashMismatch", "NotSigned", "unknown"), True)
if _tool:
    check("and the verdict is stated as a PACKAGE claim, not a signature",
          (sig.get("/usr/bin/bash") or {}).get("kind"), "package")
    check("and its label describes a digest comparison",
          "matches the" in ((sig.get("/usr/bin/bash") or {}).get("label") or ""),
          True)

# THE FOLDER REASON IS THIS PLATFORM'S LIST, and it names the folder.
check("a temp drop is a reason", pm.odd_path_reason("/tmp/x"), "a temp folder")
check("and /dev/shm is one too",
      "shared memory" in (pm.odd_path_reason("/dev/shm/x") or ""), True)
check("while an ordinary system path is no reason at all",
      pm.odd_path_reason("/usr/bin/ls"), None)
check("and neither is a path we could not place",
      pm.odd_path_reason("C:\\Windows\\System32\\x.exe"), None)

# [3] THE TWO PROPERTIES ARE STILL GUARDED, ONE LAYER DOWN

print("\n[3] the properties the removed code guarded are still guarded here")

# THE TRUST BOUNDARY. The privileged surface refuses what it must, in this
# platform's own terms -- restated from the shim's test rather than assumed,
# because the helper design leaving is exactly the case where a boundary gets
# quietly dropped.
C = caps.Capabilities()
for banned in ("run_command", "read_file", "shell", "eval", "exec"):
    check(f"no {banned} verb on the shim", banned in verbs, False)
try:
    C.process_kill(os.getpid(), "python")
    check("the shim still refuses to end its own caller", "allowed", "refused")
except (caps.CapabilityError, caps.CapabilityUnavailable):
    check("the shim still refuses to end its own caller", "refused", "refused")

# THE DEAD THING IS LOUD. The removed branch watched a helper process; this
# platform's equivalent assertion is that a component which has STOPPED WORKING
# is named on the surfaces an operator and the model actually read -- the
# readiness card and the model path. (RT-4, asserted in full in
# tests/test_rowtruth_fixes.py; restated here in its barest form so this file
# cannot pass while that property is gone.)
from core import sensor_health as sh                      # noqa: E402
from core import settings as st                           # noqa: E402


class _Failing:
    """A module that is loaded, running, and failing every poll."""

    def status(self):
        return {"running": True, "consecutive_failures": 5,
                "last_error": "probe: the reader raised"}


_failing_rows = st._module_row("a_failing_module", _Failing())
check("a module failing every poll is not painted as merely running",
      _failing_rows["state"] in ("watch", "problem"), True)
check_true("and the row says what went wrong",
           "probe: the reader raised" in _failing_rows["detail"])

_w = sh.warnings_for("query_packets",
                     {"packet_sniffer": _Failing()})
check_true("and the model is told, not left to read an empty answer as quiet",
           any("a_failing_module" in line or "failing" in line.lower()
               or "consecutive" in line.lower() for line in _w)
           or any("packet_sniffer" in line for line in _w))

# THE MODEL PATH NAMES NO WINDOWS CAPABILITY. Read from the shipped map rather
# than from the sentence a caller builds, because the map is what a future
# session edits.
_bad_deps = sorted({d for deps in sh.DEPENDS.values() for d in deps
                    if d.startswith(sh.CAP)
                    and d[len(sh.CAP):] not in _avail})
check("no tool rests on a capability this platform does not have",
      _bad_deps, [])
check("and query_events rests on the SENSOR, not on a Windows channel",
      sh.depends_on("query_events"), ("event_monitor",))
check("so does search_logs", sh.depends_on("search_logs"), ("event_monitor",))


print("\n" + ("ALL CHECKS PASSED" if not fails else f"FAILURES: {fails}"))
if not fails:
    _skip.exit_if_skipped()
sys.exit(1 if fails else 0)
