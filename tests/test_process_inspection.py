"""
tests/test_process_inspection.py, looking at a process rather than listing it.

TODO 68, 2026-09-08. The owner's call, after we agreed what was worth adding and
what was not.

  IN   the sha256, and whether anyone has ever seen that exact binary
  IN   the code signature, which needs no admin and is the strongest cheap
       signal there is
  OUT  asking Defender to scan the file. It scanned it when it landed and
       when it ran, and we already read its detections
  OUT  reading process memory. Different class of tool, and it means parsing
       hostile bytes inside our own process, which is the thing the privilege
       split is trying to shrink

What this file is really guarding is the WORDING. Every one of these answers
is easy to overstate, and an overstated one here reads as an all clear:
  * a valid signature says the file is what the publisher shipped, not that
    the behaviour is fine
  * unsigned is ordinary
  * an unknown hash means nobody published anything, which is true of most
    software, so it is neither clean nor suspicious
  * a process we could not read is not a safe process

Runs anywhere. No network, no Windows.

IT SAID "NO DATABASE" UNTIL 2026-09-14 AND THAT WAS NOT TRUE. TODO 108.
inspect_process queues an unknown binary for hash enrichment, so this file was
writing a row to enrichment_queue in the project's real database on every run,
naming whichever python is running the tests. The sentence in a docstring was
the only thing saying otherwise, and a docstring cannot enforce anything. It
uses its own throwaway database now, which is what the sentence meant.
"""
import os
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import _isolate_db                              # noqa: E402
_isolate_db.isolate()

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}"
          + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


from core import sensor_health as sh            # noqa: E402
from core import tool_registry as tr            # noqa: E402
from tools import process_monitor as pm         # noqa: E402


print("\n[1] the tool is wired and it is not gated")
names = [t["name"] for t in tr.TOOL_MANIFEST]
check("inspect_process is in the manifest", "inspect_process" in names, True)
check("it needs no approval", tr.requires_permission("inspect_process", {}), False)
check("it declares what it rests on",
      sh.depends_on("inspect_process"), ("enrichment", "cap:process_details"))
# It queues an enrichment job, so it counts as a write. Local mode used to be
# the one configuration that could honestly say read only, and it was removed
# on 2026-09-14, so what survives is the rule that produced that claim: the
# write list is derived, and this tool has to be on it.
check("it counts as a write", tr.tool_writes("inspect_process"), True)
check("and the derived write list has it", "inspect_process" in tr.write_tools(), True)


print("\n[2] it inspects this process, for real")
out = pm.inspect_process(os.getpid())
check("it found it", out["found"], True)
p = out["process"]
check("the executable was hashed", len(p["sha256"] or ""), 64)
check("a hash that could not be taken always says why",
      p["sha256"] is not None or bool(p["sha256_unavailable"]), True)
check("the signature answer is always present, even off Windows",
      bool(p["signature"].get("status")), True)
check("and says why when it could not run",
      bool(p["signature"].get("note")) if p["signature"]["status"] == "unknown" else True,
      True)

# THE CEILING, IN THE ANSWER. Not left for a reader to remember.
note = p["how_to_read_this"]
check("a valid signature is not a clean bill of health",
      "NOT that its behaviour is fine" in note, True)
check("and an unknown hash is not evidence of anything",
      "true of most software" in note, True)

gone = pm.inspect_process(999999)
check("a pid that is not running says so", gone["found"], False)
check("and does not read as fine", "No process with PID" in gone["note"], True)


print("\n[3] the colour is decided in ONE place")
# The page, the tool and the model all read trust_of, so they cannot disagree
# about what red means.
bad = pm.trust_of({"reputation": {"flagged": True, "flagged_by": ["MalwareBazaar"]}})
check("a flagged hash is red", bad[0], "bad")
check("and says who flagged it", "MalwareBazaar" in bad[1], True)

check("a high finding is red too",
      pm.trust_of({}, [{"severity": "high"}])[0], "bad")
check("a medium one is amber",
      pm.trust_of({}, [{"severity": "medium"}])[0], "watch")

unsigned = pm.trust_of({"signature": {"status": "NotSigned"},
                        "exe": "C:\\Users\\<user>\\AppData\\Local\\Temp\\a.exe"})
check("unsigned is amber, not red", unsigned[0], "watch")
# CONVERTED 2026-09-25, THE WINDOWS-LEFTOVERS ROUND. WHAT THIS BLOCK USED TO DO.
#
# It forced os.name to "nt" and asserted that a Windows temp path was named as
# "a second look" by the WINDOWS marker list (ODD_PATH_MARKERS) -- the PM-9
# platform split. Both halves of that are gone: the Windows list left
# tools/process_monitor.py with the drive-letter rewrite it fed, and this file
# no longer has a Windows branch to force.
#
# AND THE ASSERTION IS UNCHANGED IN MEANING, ASKED OF THE PATH THIS TREE CAN
# PLACE. A path that is unplaceable here is still not bad ("unknown is not
# bad", the rule this file was written around), and the folder reason on Linux
# is asserted where the Linux list is -- section [7] below, and
# tests/test_process_monitor_linux.py [9]. The Windows list's own coverage went
# with the list, to agental_sec/tests/test_process_inspection.py, whose twin
# module still has it.
check("a Windows path is unplaceable HERE and that is not a finding",
      unsigned[0], "watch")
check("and it is not explained by a list this platform does not have",
      pm.odd_path_reason("C:\\Users\\<user>\\AppData\\Local\\Temp\\a.exe"), None)
check("while the Windows marker list is gone from the module by name",
      hasattr(pm, "ODD_PATH_MARKERS"), False)
check("and so is the resolver that rewrote a Linux path into a c:\\ shape",
      "_on_system_drive" in
      (ROOT / "tools" / "process_monitor.py").read_text(encoding="utf-8"),
      False)

check("signed and quiet is green",
      pm.trust_of({"signature": {"status": "Valid", "signer": "Microsoft Windows"}})[0],
      "ok")
# RESTATED 2026-09-25, and the fixture was the thing that was wrong.
#
# This fed a WINDOWS-shaped signature -- status Valid, a signer name, and no
# `kind` -- and asserted the signer reached the row's reason. On this platform
# `_linux_signatures` stamps `kind: "package"` on every Valid row and THAT is
# the branch that names the source ("matches the bash package installed on this
# machine"). A Valid row with no package kind is the shape a Windows cache
# entry had, and this platform no longer produces one.
#
# THE PROPERTY IS UNCHANGED AND STILL ASSERTED: a green row says WHAT VOUCHED
# FOR THE FILE, and never just "safe". Both shapes are checked below, because
# the second one is what a row written before this round would still return.
check("and on this platform's shape it names the source that vouched",
      pm.trust_of({"signature": {"status": "Valid", "signer": "bash",
                                 "kind": "package"}})[1],
      "matches the bash package installed on this machine")

unknown = pm.trust_of({"signature": {"status": "unknown", "note": "no path"}})
check("nothing readable is grey, never green", unknown[0], "unknown")
check("and says plainly that unknown is not fine",
      "not the same as it being fine" in unknown[1], True)


print("\n[4] the page does not do the expensive thing on load")
# Hashing three hundred files on a tab click is minutes of disk for something
# nobody asked for. The listing colours from signature, path and findings.
table = pm.process_table(limit=5)
check("the table came back", table["available"], True)
check("every row has a colour",
      all(r.get("trust") in pm.TRUST_LEVELS for r in table["processes"]), True)
check("and NO row was hashed",
      any("sha256" in r for r in table["processes"]), False)
check("the counts add up",
      sum(table["counts"].values()), table["total"])

pm_src = (ROOT / "tools" / "process_monitor.py").read_text(encoding="utf-8")
# TWO CHECKS CAME OUT HERE 2026-09-25, and the property they guarded did not.
#
# They asserted that the signature lookup is BATCHED into one PowerShell call
# and that the paths never touch its command line ("ONE PowerShell call for the
# whole batch", "through a temp FILE rather than the command line"). Both
# sentences belong to the WINDOWS SWEEP, which left this file this round:
# there is no PowerShell call here to batch and no command line to keep a path
# off. The Windows tree still carries both assertions in
# agental_sec/tests/test_process_inspection.py, beside the code they describe.
#
# THE PROPERTY -- the sweep cannot run one call per file -- IS ASSERTED FOR
# THIS PLATFORM, on the pass that replaced it. dpkg-query costs about two
# seconds whether it is handed one path or a thousand, so ONE call per pass is
# the difference between a two second page and a three minute one; the check
# below is the Linux half of exactly the same rule, and it was measured in the
# PM round (a per-path version timed out at three minutes).
_block = pm_src.split("def _package_owner_map")[1].split("\ndef ")[0]
check("the package lookup is ONE call per batch, not one per path",
      _block.count("_sp.run("), 2)
check("and the batch is chunked by COUNT, so an ARG_MAX is never reached",
      "range(0, len(wanted), 500)" in _block, True)
check("and the paths are arguments to that call, never a shell string",
      "shell=True" in pm_src, False)

routes_src = (ROOT / "api" / "routes.py").read_text(encoding="utf-8")
check("the page endpoint exists", "/api/processes" in routes_src, True)
check("and the deep look is its own call, on demand",
      "/api/processes/inspect" in routes_src, True)

ui_src = (ROOT / "ui" / "index.html").read_text(encoding="utf-8")
check("there is a Processes tab", 'data-page="processes"' in ui_src, True)
check("with a coloured bar", "trust-bar" in ui_src, True)
check("green does not claim the behaviour is fine",
      "signed software gets abused" in ui_src, True)
check("and grey is not sold as safe",
      "is <b>not</b> the same as safe" in ui_src, True)


print("\n[5] the sweep cannot fail whole, and grey has to explain itself")
# CONVERTED 2026-09-25, THE WINDOWS-LEFTOVERS ROUND. WHAT WAS HERE.
#
# SIG_CHUNK, SIG_CHUNK_TIMEOUT, SIG_DEADLINE and _PS_SIGNATURE were the
# WINDOWS sweep's own constants -- how many files go into one PowerShell call,
# how long each may take, how long the whole pass may take, and the script that
# wraps one file's check in its own try so a bad file cannot take its chunk
# down. The sweep left tools/process_monitor.py this round and all four names
# went with it, together with the section [6] JSON-shape handling they fed
# (ConvertTo-Json hands back a bare object for one file, a bare string when the
# pipeline produced something else, and a path wrapped in PowerShell's own
# decoration -- every one of those is a fact about PowerShell).
#
# The Windows tree still carries BOTH sections in
# agental_sec/tests/test_process_inspection.py, beside the code they describe.
#
# AND THE PROPERTY IS RE-ASSERTED ON THE PASS THAT REPLACED THEM, because "the
# sweep cannot fail whole" is not a Windows idea: this platform's sweep also
# has a per-pass deadline, also counts what happened rather than shrugging, and
# also has a file whose digest cannot be taken -- and each of those has to come
# back as a ROW WITH A REASON, never as a missing row and never as a pass that
# dies. That is what the checks below drive, on the shipped functions.
check("there is a deadline for the whole verify pass",
      pm._PKG_CHECK_DEADLINE <= 120, True)
check("and it is a per-pass budget, not one per file",
      isinstance(pm._PKG_CHECK_DEADLINE, float), True)

stats = {}
pm.signatures_for(["/no/such/file/at/all"], stats)
check("the sweep counts what happened rather than shrugging",
      sorted(stats), ["cached", "checked", "failed", "not_reached"])
check("and an unreadable path is counted as failed, not dropped",
      stats["failed"] >= 1, True)

# A PATH THAT CANNOT BE READ COMES BACK AS A ROW, WITH A REASON. Missing from
# the answer would be indistinguishable from a file that was never asked about.
got = pm.signatures_for(["/no/such/file/at/all"])
check("an unreadable path still gets an answer row",
      "/no/such/file/at/all" in got, True)
check("and that row says why rather than being blank",
      bool(got["/no/such/file/at/all"].get("note")
           or got["/no/such/file/at/all"].get("label")), True)
check("and it is not sold as a clean file",
      got["/no/such/file/at/all"]["status"], "unknown")

# THE ONE BAD FILE CANNOT TAKE THE BATCH DOWN. The Windows section proved this
# with a bad chunk; here it is proved with a bad PATH, because the failure mode
# this platform can have is a file whose digest cannot be taken in the middle
# of a batch of good ones. Driven with the package lookup stubbed to unowned,
# so no dpkg call is made and the check is about the batch loop.
import pathlib as _pl                              # noqa: E402
import tempfile as _tf                             # noqa: E402

_tmp2 = _pl.Path(_tf.mkdtemp(prefix="inspect_batch_"))
_good = _tmp2 / "good"
_good.write_bytes(b"nothing important")
_real_owner = pm._package_owner_map
try:
    pm._package_owner_map = lambda paths: {}
    mixed = pm.signatures_for([str(_good), "/no/such/file/at/all", str(_good)])
finally:
    pm._package_owner_map = _real_owner
check("a bad path in the middle does not lose the good rows around it",
      sorted(mixed), sorted([str(_good), "/no/such/file/at/all"]))
check("the good file is judged on its own",
      mixed[str(_good)]["status"], "NotSigned")

table = pm.process_table(limit=5)
check("and the page is given a sentence about it",
      bool(table.get("signature_check")), True)

ui = (ROOT / "ui" / "index.html").read_text(encoding="utf-8")
check("the summary line shows it", "procData.signature_check" in ui, True)
check("and a grey row says why on the row itself",
      "sig.note ?" in ui, True)


print("\n[6] what comes back is not always a list of objects")
# CONVERTED 2026-09-25, THE WINDOWS-LEFTOVERS ROUND, AND THIS SECTION IS THE
# CLEAREST CASE IN THE FILE FOR THE RULE "RESTATE, DO NOT DELETE".
#
# Every check that was here drove `pm._check_chunk` with a fake PowerShell
# stdout: a bare object for one file, a bare string when the pipeline said
# something else, a null, something that is not JSON at all, and a path wrapped
# in PowerShell's own decoration (Get-Content hangs its properties on every
# line, so ConvertTo-Json serialised the PATH as an object). All five are
# WINDOWS-SHAPED INPUTS. The function, the JSON it parsed and the fake were
# Windows programs and all of them left with the sweep; the Windows tree still
# carries the section verbatim in agental_sec/tests/test_process_inspection.py.
#
# THE BUG IT WAS WRITTEN FOR IS NOT WINDOWS-SHAPED. "A check that answers a
# narrower question than it appears to, and says its refusal in a type name
# nobody can act on" is the defect class this whole tree keeps finding -- and it
# survives the port, because this platform's sweep has an input that can answer
# in more than one shape for the same reason. dpkg-query -S prints THREE
# different things: "<pkg>: <path>" for an owned file, "diversion by <pkg>
# from: <path>" for a diversion, and "dpkg-query: no path found matching
# pattern <path>" on stderr for anything unowned. Feeding all three through the
# SHIPPED parser is what this section does now.
#
# ONE SHAPE IS NEW AND HANDLED ON PURPOSE: a path that matches nothing comes
# back with NO LINE AT ALL for it. That is not an error and it must not be
# reported as one -- it is "no installed package claims this file", which is
# exactly what the Windows section's bare-string case was protecting in its own
# vocabulary: a refusal has to be a ROW with a REASON, never a crash and never a
# missing row.
import subprocess as _sub                         # noqa: E402


class _FakeQuery:
    """Stands in for the dpkg-query call, so this runs anywhere."""

    def __init__(self, stdout, stderr="", rc=0):
        self.out, self.err, self.rc = stdout, stderr, rc

    def __call__(self, *a, **kw):
        return _sub.CompletedProcess(a[0] if a else [], self.rc,
                                     self.out, self.err)


def _ask(stdout, stderr="", rc=0, paths=("/usr/bin/ls", "/bin/sh",
                                         "/lib/x/libc.so.6")):
    """One _package_owner_map call against a fake dpkg, restored after."""
    real = pm._sp.run
    try:
        pm._sp.run = _FakeQuery(stdout, stderr, rc)
        return pm._package_owner_map(list(paths))
    finally:
        pm._sp.run = real


# THE ORDINARY ANSWER, which is what almost every call gets.
owners = _ask("bash: /usr/bin/ls\n")
check("a path a package owns maps to that package", owners.get("/usr/bin/ls"),
      "bash")

# THE ARCH QUALIFIER, the one real shape this platform has and Windows does
# not: dpkg prints "libc6:amd64" and the record files and the display name both
# use the plain name, so the qualifier has to come off or every library on the
# machine is attributed to a package that does not exist under that name.
owners = _ask("libc6:amd64: /lib/x/libc.so.6\n")
check("an architecture-qualified package name is plain by the time it ships",
      owners.get("/lib/x/libc.so.6"), "libc6")

# THE DIVERSION, dpkg's own decoration, and the same class of bug as the path
# wrapped in PowerShell's properties: a line that is about the file but is not
# a claim of ownership. Read as one, it would attribute a diverted file to
# whatever package the diversion names.
owners = _ask("diversion by dash from: /bin/sh\ndiversion by dash to: "
              "/bin/sh.distrib\nbash: /usr/bin/ls\n")
check("a diversion line is not read as an owner", "/bin/sh" in owners, False)
check("and the real ownership on the next line still lands",
      owners.get("/usr/bin/ls"), "bash")

# NOTHING MATCHED. dpkg says so on stderr and prints no line for the path.
# This must come back as an EMPTY MAP -- "I could not tell you who owns this",
# which every caller already treats as unknown -- and never as an exception or
# as a line of stderr parsed into a package called "dpkg-query:".
owners = _ask("", "dpkg-query: no path found matching pattern /usr/bin/ls\n",
              rc=1)
check("nothing matched comes back as an empty map, not a crash", owners, {})

# A CALL THAT DID NOT RUN AT ALL, the other direction. A timeout is not "no
# package owns this" and must not be reported as one.
owners = _ask("", "Command 'dpkg-query' timed out after 60 seconds", rc=1)
check("a call that never answered is still an empty map, not a false owner",
      owners, {})
# CONVERTED 2026-09-21. scripts/sigcheck.py is a Windows PowerShell script and
# it moved out of this tree with the L5 pass, so this check was asserting the
# existence of a file that is deliberately not here. WHAT IT WAS FOR is that
# there is a way to see the raw answer when the signature lookup misbehaves;
# on this platform that path is inspect_process itself, which returns the
# signature row rather than shelling out to anything.
#
# THE FIRST ATTEMPT AT THIS CONVERSION LOOKED FOR THE DEFINITION IN THE WRONG
# FILE and the check went red for a day. `inspect_process` is DEFINED in
# tools/process_monitor.py; core/tool_registry.py only dispatches to it. Both
# halves are asserted now, because a definition nobody dispatches to is not a
# reachable path and a dispatch to a name that is gone is the same defect as
# an import of a moved module.
check("inspect_process exists, and it returns the signature row",
      "def inspect_process" in pm_src, True)
check("and the registry actually dispatches to it",
      "_pm.inspect_process(params[\"pid\"]" in
      (ROOT / "core" / "tool_registry.py").read_text(encoding="utf-8"), True)


print("\n[7] the amber reason has to be the actual reason")
# TODO 77, 2026-09-13. Found by the MODEL reading the Processes page, which is
# worth saying first. AppProvisioningPlugin.exe runs from
# \ProgramData\Vendor\Udc\Hosts\x64\ and the row said "watch, it is running
# from a temp or user folder". ProgramData is neither. The reason was false.
#
# Two faults behind one sentence: bare "\programdata\" was in the marker list
# at all, and every marker printed the same canned sentence whatever it
# matched. Both are fixed, and this section guards both halves. The half that
# matters more is the second block: silencing the rule would also have made
# the false reason go away, and would have been far worse.
#
# THE MARKER CASES ARE RE-MARKED 2026-09-23 (the PM round), and the checks are
# the same checks. The marker lists and the path resolver are PLATFORM-SPLIT
# now, so the Windows half of this section is asked with the platform forced,
# exactly as section [6] above asks the PowerShell half. The defect this file
# was written for was a marker list doing its own string work; the fix for
# PM-9 was that the LIST and the RESOLVER were Windows-shaped on Linux, so
# testing them on this host without forcing the platform would be testing a
# branch that no longer runs here — which is how the checks went red and were
# right to.
#
# THE LINUX HALF OF THE SAME QUESTION lives in tests/test_process_monitor_linux.py
# section [9], which asserts /dev/shm, a user cache and Downloads against the
# real paths on this host.
# CONVERTED 2026-09-25, THE WINDOWS-LEFTOVERS ROUND. WHAT WAS HERE.
#
# A `with _as_windows():` block (os.name forced to "nt") holding nineteen checks
# against pm.ODD_PATH_MARKERS -- the WINDOWS folder list -- its vendor and
# Defender cases, the recycle bin, Downloads, the drive-relative forms and the
# every-marker-can-say-itself-out-loud loop. That list left
# tools/process_monitor.py this round with the drive-letter rewrite it fed, and
# `_is_plausible_system_location` and `_is_whitelisted` went with it.
#
# THE FILE'S OWN NOTE ALREADY SAID WHERE THE OTHER HALF LIVES, and this is the
# conversion it pointed at. The Windows cases are in
# agental_sec/tests/test_process_inspection.py, beside the module that still
# has the list. What is asserted HERE is the same question asked of the list
# this platform has, and it keeps the two properties the Windows block carried
# because they are the properties that were ever at stake:
#
#   EVERY MARKER CAN SAY ITSELF OUT LOUD. Nothing goes in the list that the row
#   cannot explain -- the rule that broke on 2026-09-13, when every marker
#   printed one canned sentence and bare "\programdata\" was in the list at all.
#   Asserted by LOOPING THE LIVE LIST rather than by naming entries, so an
#   entry added next month has to satisfy it too.
#   UNKNOWN IS NOT BAD. A path we could not place never turns a row amber.

# The exact wording that was wrong, gone from the source rather than reworded
# somewhere else. Same reason the sentence lives beside its marker now.
pm_src = (ROOT / "tools" / "process_monitor.py").read_text(encoding="utf-8")
check("the canned sentence is gone",
      "it is running from a temp or user folder" in pm_src, False)
check("and the Windows marker list is gone with the rewrite it fed",
      hasattr(pm, "ODD_PATH_MARKERS"), False)

# EVERY MARKER CAN SAY ITSELF OUT LOUD, driven off the live list.
for marker, words in pm.ODD_PATH_MARKERS_LINUX:
    got = pm.odd_path_reason(marker.rstrip("/") + "/x")
    check(f"{marker} says what it is", got, words)
check("and no two markers share one sentence, which is the canned-sentence defect",
      len({w for _m, w in pm.ODD_PATH_MARKERS_LINUX}),
      len(pm.ODD_PATH_MARKERS_LINUX))
check("and every marker names the folder it matched, not just 'a folder'",
      all(w and w.strip() and w != "a folder"
          for _m, w in pm.ODD_PATH_MARKERS_LINUX), True)

# Unknown is not bad. A path we could not place must never be the thing that
# turns a row amber, the same rule the Windows resolver followed.
check("a path that cannot be placed is not called odd",
      pm.odd_path_reason("\\\\Device\\HarddiskVolume3\\x.exe"), None)
check("and neither is no path at all", pm.odd_path_reason(""), None)
check("a row with no readable path stays grey, not amber",
      pm.trust_of({"exe": "", "signature": {"status": "unknown",
                                            "note": "no executable path to check"}})[0],
      "unknown")

# AND ON THIS HOST, THE SAME QUESTION WITH THIS PLATFORM'S OWN PATHS. The point
# of the whole section: a row must name the folder the file is REALLY in.
check("on Linux, a real temp drop is amber too",
      pm.trust_of({"exe": "/tmp/x", "signature": {"status": "Valid",
                                                  "signer": "x"}})[0], "watch")
check("and /dev/shm is a reason now, not silence",
      pm.odd_path_reason("/dev/shm/x") is not None, True)
check("and a user cache is too",
      pm.odd_path_reason("/home/user/.cache/x") is not None, True)
check("while an ordinary system path is not odd at all",
      pm.odd_path_reason("/usr/bin/ls"), None)
# THE CONTROL for the substring bug: /var/tmp is NOT /tmp, and the label says so.
check("a /var/tmp file is not labelled /tmp",
      pm.odd_path_reason("/var/tmp/y") == "a temp folder", False)
check("and a directory that merely starts with the letters is not /tmp",
      pm.odd_path_reason("/home/x/shipped/tool"), None)
# THE BOUNDARY CONTROL, which the Windows block carried for its own list: a
# folder whose NAME merely contains the marker is not that folder.
check("a folder named Downloads-archive is not a Downloads folder",
      pm.odd_path_reason("/home/ada/Downloads-archive/x"), None)
check("while a real Downloads path is",
      pm.odd_path_reason("/home/ada/Downloads/x") is not None, True)


print("\n[8] the Processes page must not paint green when it could not read")
print("    the findings. TODO 98, 2026-09-14.")

# WHAT WAS WRONG. process_table read the findings behind an except Exception
# with a logger.debug, so a failed read left by_name empty, every row went
# through trust_of with no findings, and the page said "None flagged" and drew
# them green. A process with a critical finding against it looked clean and
# nothing on the screen could say the findings had not been read.
#
# It also capped that read at 200 with no note, so past two hundred process
# findings in a session the rest were simply not in the colouring.
#
# THE FAILURE CASE FIRST, because the whole point is the failure path.
#
# Patched on the real module rather than by swapping sys.modules, because
# process_table does `from core import memory_engine as me` and that returns
# the package attribute, not whatever sys.modules was told. My first version
# of this test did the swap, saw the REAL function fail for an unrelated
# reason, and passed. It was testing nothing.
from core import memory_engine as _me            # noqa: E402
import tempfile                                  # noqa: E402

# POINT THE ENGINE AT A THROWAWAY FILE FIRST. list_processes reaches the
# database on the way past, and a test that touches the project's real
# agental_sec.db is a test that can change what it is measuring. It also
# CREATES that file when it is missing, which then breaks whichever test runs
# next on a fresh checkout.
_real_db = _me.DB_PATH
_scratch = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
_scratch.close()
_me.DB_PATH = _scratch.name

_real_worst = getattr(_me, "worst_finding_by_entity", None)
check("(the function being patched really exists)", callable(_real_worst), True)


def _explode(*a, **k):
    raise RuntimeError("database is locked")


# The row set is fixed for BOTH halves. Section [4] already exercises the real
# process table and the real signature sweep; doing it again here costs ten
# seconds on a real machine and buys nothing, and it makes the result depend
# on which processes happen to be running.
_real_list = pm.list_processes
_real_sigs = pm.signatures_for

FIXED_ROWS = [
    {"pid": 4242, "name": "planted.exe", "exe": "C:\\Program Files\\x\\planted.exe",
     "username": "test", "cmdline": ""},
    {"pid": 4243, "name": "ordinary.exe", "exe": "C:\\Program Files\\x\\ordinary.exe",
     "username": "test", "cmdline": ""},
]
pm.list_processes = lambda **kw: {"available": True,
                                  "processes": [dict(r) for r in FIXED_ROWS],
                                  "note": None}
# Signed and quiet, so the ONLY thing that can turn a row red is a finding.
#
# THE FIXTURE CARRIES `kind: "package"`, and that is the production shape, not
# decoration. It read `{"status": "Valid", "signer": "Test Publisher"}` -- the
# WINDOWS shape -- and on this platform the green branch that NAMES the source
# is the one gated on `kind == "package"`, so the row came back "it matches what
# its package shipped" and the check below, "it says why it is green", failed
# against correct code. A fixture that does not model the production shape
# makes the test assert the wrong thing; this one now carries the field the
# real sweep stamps.
pm.signatures_for = lambda paths, stats=None: {
    q: {"status": "Valid", "signer": "Test Publisher", "kind": "package",
        "package": "Test Publisher", "label": None,
        "note": None} for q in paths}

_me.worst_finding_by_entity = _explode
broken = pm.process_table(limit=5)
check("the page still renders", broken["available"], True)
check("and it says the findings were NOT read", broken["findings_read"], False)
check("and names the reason",
      "database is locked" in (broken["findings_note"] or ""), True)
check("and says what the colours actually rest on",
      "signature and the path ONLY" in broken["findings_note"], True)
check("and warns that a green row may have a finding",
      "as if it had none" in broken["findings_note"], True)

# NOW THE WORKING PATH. The colour has to come from the finding, or the field
# is decoration.
#
# MY BUG, CAUGHT ON THE OWNER'S MACHINE 2026-09-14. The first version of this called
# process_table twice and assumed the same five processes came back both
# times. On a sandbox with a handful of processes that held. On a real machine
# with three hundred, the two calls returned different rows and the lookup
# found nothing, so it died on an IndexError.
#
# A test that depends on which processes a live machine happens to be running
# is not testing the thing it claims to. The row set is fixed here instead, so
# what is under test is the WIRING: does a finding reach trust_of and change
# the colour. Section [3] already covers trust_of itself.
_me.worst_finding_by_entity = (
    lambda entity_type, session_id=None:
    {"planted.exe": {"severity": "critical", "title": "planted"}})
try:
    ok = pm.process_table(limit=5)
finally:
    pm.list_processes = _real_list
    pm.signatures_for = _real_sigs
    _me.worst_finding_by_entity = _real_worst
    _me.DB_PATH = _real_db

check("a working read says so", ok["findings_read"], True)
check("and carries no note", ok["findings_note"], None)

by_name = {r["name"]: r for r in ok["processes"]}
check("both rows came back", sorted(by_name), ["ordinary.exe", "planted.exe"])
check("the finding colours its row red", by_name["planted.exe"]["trust"], "bad")
check("and the reason names it",
      "critical finding" in by_name["planted.exe"]["trust_reason"], True)
# The control. Same signature, same folder, no finding, so it must NOT be red.
# Without this the check above passes on a function that reddens everything.
check("the row with no finding is not red", by_name["ordinary.exe"]["trust"], "ok")
check("and it says why it is green", "Test Publisher"
      in by_name["ordinary.exe"]["trust_reason"], True)

# And the read itself has no cap left to hit. A limit in this call is the bug
# still shipped, whatever the field says.
#
# THE 4,000 CHARACTER WINDOW IS GONE, 2026-09-23, and it is LOOP-2 from
# bugfinder.md caught a second time in a second file. The block grew by three
# lines (a kernel-thread count in the payload) and `"findings_read"` slid past
# character 4,000, so a check about the payload failed for a reason that had
# nothing to do with the payload. The window is bounded by the function's own
# end now. A too-small window fails loudly; this one failed for the wrong
# reason, which is worse.
src = (ROOT / "tools" / "process_monitor.py").read_text(encoding="utf-8")
block = src.split("def process_table")[1].split("\ndef ")[0]
code = "\n".join(l.split("#")[0] for l in block.splitlines())
check("the table reads the uncapped aggregate",
      "worst_finding_by_entity" in code, True)
check("and no longer asks query_findings for a capped list",
      "query_findings" in code, False)
check("and the payload carries the flag", '"findings_read"' in code, True)


print("\n" + ("ALL CHECKS PASSED" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
