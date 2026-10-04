"""
tests/test_privilege.py, TODO 3.1 step 1, the elevation register.

Step 1 of PRIVILEGE_SPLIT_PLAN.md: move the register out of main.py and make
an unregistered module fatal. No behaviour change, which is most of what this
suite checks, a refactor that quietly altered the startup report would be a
bad start to a security change.

The enforcement is the new part, and it is the same argument as
finding_policy's unregistered sensor: a module that never declared its
requirement fails one capability silently on an unelevated run, and the
startup report has no line to print about it.

WHICH REGISTER THIS READS, corrected 2026-09-21. It imported
`core.privilege`, and on this host that is the WINDOWS register: it is
byte-identical to the Windows tree's copy, it lists Windows module names, and
its consequence strings name Npcap and the Windows Security channel. Every
assertion below was therefore checking a list that this app does not load and
that the operator never sees, which is the "test the other tree" failure in
its quietest form -- the file was green for months.

`core/privilege_linux` is what `main.py` imports and what the startup report
prints. The RULES this file was written for are unchanged and are asserted
against it. Where a count differs the Linux answer is the correct one for
this platform and is asserted by value; where the platform has no such concept
(a dropped token, a helper process) the check says so instead of looking for
the Windows artifact.
"""
import sys, pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

fails = []
def check(label, got, want):
    """THE LABEL IS DELIMITED, 2026-09-25, register PS-13.

    The negative-control harness reads the failing set back through a
    bracketed regex, so a file that prints `<label>: <value>` with no boundary
    reads as ZERO failures while it is really failing -- measured on
    tests/test_ebpf_fixes.py, where the PS-15 reversion exited 1 and the
    reader counted none. `[` and `]` never appear in a label here.
    """
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  [{label}]: {got!r}" + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)

from core import privilege_linux as pv


print("\n[1] the two that need elevation here. It was three on Windows")
# THE RULE IS THE CHECK, NOT THE COUNT: a module LEAVING this list is a real
# reduction in what has to run with rights, so it is asserted rather than left
# to drift. On Linux the list is SHORTER than Windows' three, and that is the
# measured answer rather than a missing entry:
#
#   event_monitor   is NEEDS on Windows (the Security channel will not open)
#                   and DEGRADES here, because journald still yields the
#                   reading user's own entries, so the module runs and loses
#                   only the other users' lines.
#   remediation     NEEDS on both, in each platform's own words.
#   packet_sniffer  NEEDS on both, in each platform's own words.
check("needs elevation",
      sorted(n for n, _ in pv.modules_by_level(pv.NEEDS)),
      ["packet_sniffer", "remediation"])
check("and event_monitor degrades here rather than failing, because "
      "journald still yields this user's own entries",
      pv.requires_elevation("event_monitor").level, pv.DEGRADES)
check("the VPN module claims no elevation at all",
      pv.requires_elevation("vpn_state").level, pv.NONE)
check("and the old name is gone, so a stale reference fails loudly",
      "vpn_manager" in pv.REQUIREMENTS, False)
# RESTATED 2026-09-25, register PS-13 OPTION (c). The old assertion named
# exactly three here, and port_scanner was made the fourth and port_owner the
# fifth in the same pass -- both for measured reasons, both written in the
# register entry. port_scanner's old NONE row said "elevating buys a scan
# nothing it does not already have" and that was false twice over: the SYN
# scan it described did not exist, and a self-scan's OWNER lookup loses every
# root-owned listener unelevated (measured: 0 of 13). port_owner had NO row
# anywhere at all. The check below asserts the NEW list BY NAME, so the next
# module that changes level has to say so here rather than drift.
check("degrades but works",
      sorted(n for n, _ in pv.modules_by_level(pv.DEGRADES)),
      ["event_monitor", "network_scanner", "port_owner", "port_scanner",
       "process_monitor"])
# The consequence string must name the loss a reader would otherwise
# under-plan for. On Windows that is Defender's detections; HERE it is the
# other users' command lines, and the check asserts THIS platform's sentence
# because THIS is the string the startup report prints.
check("and its consequence names the loss, not just the module name",
      "Command lines and executable paths unreadable" in
      pv.requires_elevation("process_monitor").consequence, True)
check("and the rest need nothing",
      len(pv.modules_by_level(pv.NONE)) > 10, True)


print("\n[2] an unregistered module is FATAL, not assumed harmless")
raised = False
try:
    pv.requires_elevation("module_someone_adds_next_month")
except pv.UnregisteredModule as e:
    raised = True
    check("the error explains the silent failure it prevents",
          "silently" in str(e), True)
check("raised", raised, True)
check("a registered one answers",
      pv.requires_elevation("packet_sniffer").level, pv.NEEDS)
check("including a 'needs nothing' answer, which is a claim not a gap",
      pv.requires_elevation("dns_monitor").level, pv.NONE)


print("\n[3] elevation is three-valued: yes, no, and cannot tell")
e = pv.is_elevated()
check("returns a bool or None, never a guess", e in (True, False, None), True)
# The Linux module states the same rule in its own words: None is a real
# answer and guessing would mislead about what the sensors can do. Asserted on
# THIS file, because that is the module whose answer this app reports.
src = (ROOT / "core" / "privilege_linux.py").read_text(encoding="utf-8")
check("and says why None is a real answer",
      "None is a real answer" in src, True)


print("\n[4] posture() names the excess, which is the whole point of 3.1")
# TODO 3.1's actual subject, and it reads differently per platform on purpose:
# Windows' excess is a whole unelevated-app-plus-helper design to remove, and
# here the same question is answered by capabilities on the binary. So the
# counts are asserted BY VALUE against the Linux register rather than against
# the Windows one, and the number that matters is that a module holding rights
# it never uses is COUNTED and named in the summary.
p = pv.posture()
check("reports elevation", "elevated" in p, True)
check("lists what is unavailable unelevated",
      len(p["unavailable_when_unelevated"]),
      len(pv.modules_by_level(pv.NEEDS)))
check("which is two on this platform, and it says so rather than reusing "
      "another platform's three",
      len(p["unavailable_when_unelevated"]), 2)

# REWRITTEN 2026-09-23, AND THE OLD ASSERTION IS WORTH WRITING DOWN BECAUSE IT
# WAS MEASURING THE BUG. It said `len(p["degraded_when_unelevated"]) == 4`,
# which was true and was the DEFECT: the list was built from
# modules_by_level(DEGRADES) and is_elevated() ALONE, so every module DECLARED
# to degrade was reported as degrading, whether or not it did. Measured on
# this host, event_monitor degrades at NOTHING -- the account is in `adm`,
# auth.log is group-readable and journalctl answers -- and this check was
# green while the startup report told the operator the opposite on every boot
# (bugfinder.md EM-9, register section 3).
#
# So the assertion is not deleted and it is not loosened into "some number":
# it now checks BOTH HALVES of the new contract -- every module still DECLARED
# to degrade is still in the declared list, and the MEASURED list can only
# ever be a subset of it, containing the ones whose probe said they lose
# something. A module silently vanishing from both lists would fail here.
declared = p["degraded_declared"]
measured = [n for n, _ in p["degraded_when_unelevated"]]
check("every declared degrade is still declared",
      sorted(declared),
      ["event_monitor", "network_scanner", "port_owner", "port_scanner",
       "process_monitor"])
check("and the MEASURED list is a subset of the declared one, never "
      "more", set(measured) <= set(declared), True)
check("the probe ran and its verdict is published",
      isinstance(p["event_log_probe"].get("readable"), bool), True)
if p["event_log_probe"]["readable"] and not p["elevated"]:
    # the machine can read its own logs, so the sentence that said it could
    # not must not be printed
    #
    # GUARDED ON `not elevated` TOO, 2026-09-25. MEASURED inside
    # `unshare -Urn` (where the SYN-scan tests drive the raw path): euid IS 0
    # in a user namespace, posture() correctly takes its elevated branch, and
    # the "NOT among them" sentence belongs to the UNELEVATED summary. Without
    # this guard the check fails against correct code on that host -- an
    # expectation captured under different conditions, which is the fixture
    # defect the tool-audit round names.
    check("a module that PROBED fine is not painted as degraded",
          "event_monitor" in measured, False)
    check("and the summary says so rather than leaving the reader to "
          "guess whether it was forgotten",
          "log reader is NOT among them" in p["summary"], True)
elif p["elevated"]:
    check("an elevated run says what it has rather than what is missing",
          "Running as root" in p["summary"], True)
else:
    check("a module that probed as refused IS named, with its "
          "measurement attached",
          "MEASURED on this host" in
          dict(p["degraded_when_unelevated"]).get("event_monitor", ""), True)
check("the others are still measured as degrading, which is what they were "
      "before this round",
      sorted(n for n in measured if n != "event_monitor"),
      ["network_scanner", "port_owner", "port_scanner", "process_monitor"])
# AND WHY PORT_SCANNER LEFT THE 'NEEDS NOTHING' LIST AND CAME BACK TO THIS
# ONE, 2026-09-25, register PS-13. This is now a THREE-STATE history and the
# file says so rather than showing only where it landed:
#
#   1. The row read "TCP SYN scan requires root. Falls back to TCP connect()
#      scan" -- AND NO SYN SCAN EXISTED anywhere in the tree. `_check_port`
#      had been socket.create_connection since the first commit, so the
#      connect scan was not a fallback from a SYN scan; it was the only scan
#      the module had, and it needs no capability.
#   2. The correction set the row to NONE with the sentence "elevating buys a
#      scan nothing it does not already have". THAT WAS ALSO FALSE, and
#      measurably: a self-scan attaches tools/port_owner's answer to every
#      open port, and unelevated that answer matched 0 of this host's 13
#      listeners. The audit had measured `_check_port` and generalised it to
#      the whole module -- a claim about a part written as a claim about the
#      tool.
#   3. The owner took the third design, in the owner's own words: "do option C and
#      when done report back". So the SYN scan was BUILT, and the row is
#      DEGRADES again -- this time with a consequence sentence that names the
#      two things actually lost (the SYN scan; the owner lookup) and with the
#      level backed by two PROBES in posture() rather than a constant.
check("port_scanner is back among the degraded, and for the reason the SYN "
      "scan and the owner lookup both give",
      "port_scanner" in declared, True)
check("and its consequence names the OWNER loss, which is the half the first "
      "correction missed",
      "OWNER" in pv.requires_elevation("port_scanner").consequence, True)
check("and the SYN-scan half of the loss too",
      "SYN" in pv.requires_elevation("port_scanner").consequence, True)
check("and it is still REGISTERED, rather than deleted from the register",
      pv.requires_elevation("port_scanner").level, pv.DEGRADES)
# THE MODULE THAT HAD NO ROW AT ALL. This check is the register's own opening
# argument turned on the register: requires_elevation RAISES for an
# unregistered module because "a module that never declared its requirement
# fails one capability silently on an unelevated run", and tools/port_owner.py
# was exactly that module until this round.
# THE MODULE THAT HAD NO ROW AT ALL, fixed in the same pass. ASSERTED BY
# MEMBERSHIP FIRST, because `requires_elevation` RAISES for an unregistered
# module -- deliberately, and the register's own tests rely on that -- so a
# check that calls it directly DIES instead of FAILING when the entry is
# removed, and a check that dies measures nothing (the rule the negative
# control harness exists to enforce, one layer in).
check("port_owner is registered, having had NO entry at all before PS-13",
      "port_owner" in pv.REQUIREMENTS, True)
if "port_owner" in pv.REQUIREMENTS:
    check("and it declares DEGRADES, not NEEDS and not NONE",
          pv.requires_elevation("port_owner").level, pv.DEGRADES)
    check("and its consequence names the measured loss rather than a guess",
          "unreadable" in pv.requires_elevation("port_owner").consequence,
          True)
else:
    check("and it declares DEGRADES, not NEEDS and not NONE",
          "the module is not registered at all", pv.DEGRADES)
    check("and its consequence names the measured loss rather than a guess",
          "the module is not registered at all", "unreadable in it")
# THE TWO PROBES, PUBLISHED AS DATA. EM-9's rule: a verdict about this host is
# probed, and the measurement is what a reader gets, not a boolean restated as
# prose. Both keys exist on every posture() call whatever they find, because a
# card that has to re-probe to explain itself would be a second measurement of
# the same thing.
check("the raw-socket probe ran and is published",
      p.get("syn_scan_probe", {}).get("available") in (True, False), True)
check("and it carries its reason either way",
      bool(p.get("syn_scan_probe", {}).get("reason")), True)
check("the port-owner probe ran and is published",
      p.get("port_owner_probe", {}).get("readable") in (True, False), True)
check("and it counts the refusals rather than only flagging one",
      isinstance(p.get("port_owner_probe", {}).get("refused"), int), True)
if not p["syn_scan_probe"]["available"]:
    # This run cannot send SYNs, so the MEASURED port_scanner sentence must
    # SAY so -- a row that lists the loss without the measurement would be
    # the EM-9 defect (a verdict printed from a constant).
    check("a SYN-capability refusal is measured onto the row, not assumed",
          "MEASURED on this host" in
          dict(p["degraded_when_unelevated"]).get("port_scanner", ""), True)
check("and port_owner's row carries its measurement too",
      "MEASURED on this host" in
      dict(p["degraded_when_unelevated"]).get("port_owner", ""), True)
if p["elevated"]:
    check("and counts modules holding rights they never use",
          p["excess_privilege_modules"] > 10, True)
    check("saying so in the summary", "never use" in p["summary"], True)
else:
    check("an unelevated run says a quiet dashboard is not a quiet network",
          "not evidence of a quiet network" in p["summary"], True)


print("\n[5] main.py still reports the same thing, via the register it loads")
import ast
main_src = (ROOT / "main.py").read_text(encoding="utf-8")
tree = ast.parse(main_src)
# The register must no longer be DEFINED in main, only imported/derived.
assigns = [n for n in ast.walk(tree) if isinstance(n, ast.Assign)
           for t in n.targets if isinstance(t, ast.Name)
           and t.id == "_NEEDS_ELEVATION"
           and isinstance(n.value, (ast.List, ast.Tuple))]
check("the list literal is gone from main.py", assigns, [])
# CONVERTED 2026-09-21. The Windows tree's main.py imports core.privilege.
# This tree's imports core.privilege_linux, and asserting the Windows spelling
# here would be asserting that main.py loads the register of ANOTHER PLATFORM.
# WHAT THE CHECK IS FOR is unchanged: the register has to be IMPORTED by the
# entry point rather than inlined beside the report, so there is one list and
# both readers get the same answer.
check("main imports the register rather than inlining it",
      "from core import privilege_linux as priv" in main_src, True)
check("and it is the Linux register, not the Windows one",
      "from core import privilege as priv" in main_src, False)
check("and the startup report still exists", "_report_privileges" in main_src, True)

# The consequence strings a user reads must be unchanged by the move. THIS ONE
# IS READ FROM THE PLATFORM'S OWN REGISTER, and the two fields answer two
# different questions: `reason` names the mechanism the OS withholds, and
# `consequence` names what the operator LOSES. Both are asserted, because a
# consequence that understates the loss is worse than no string at all --
# somebody reads it, decides they can live without it, and quietly loses the
# threat map.
_pkt = pv.requires_elevation("packet_sniffer")
check("the reason names the mechanism this platform withholds",
      "CAP_NET_RAW" in (_pkt.reason or ""), True)
check("and the consequence names the loss in the operator's terms",
      "no packet rows" in _pkt.consequence, True)
check("and the Windows-only mechanism is not named in this tree's register",
      "Npcap" in (_pkt.reason or "") or "Npcap" in _pkt.consequence, False)


print("\n[6] THE DESIGN IS DIFFERENT ON THIS PLATFORM, so this checks THIS one")
# CONVERTED 2026-09-21, and this is a FORK rather than a port.
#
# The Windows tree's privilege split is: an unelevated app, a helper process
# that holds the rights, and a dropped token in the child. All of the files
# that block names -- PRIVILEGE_SPLIT_PLAN.md, core/helper_server.py,
# core/helper_client.py, core/token_drop.py -- are Windows programs and they
# moved OUT of this tree with the L5 pass. There is nothing here for those
# checks to read.
#
# THE LINUX ANSWER IS A DIFFERENT SHAPE and it is already built: there is no
# helper process and no token to drop, because the rights question is answered
# by CAPABILITIES on the binary, not by who launched it. core/privilege_linux
# is what decides, and the launchers are .desktop entries rather than a
# bootstrap. So this block checks the Linux half, and the RULE it was written
# for is unchanged: the thing that holds the rights has to be a boundary, and
# the document has to say where the work actually stopped.
priv = (ROOT / "core" / "privilege_linux.py")
check("the Linux privilege module is here", priv.exists(), True)
text = priv.read_text(encoding="utf-8")
check("and it says what it can and cannot do",
      "CAP_NET_RAW" in text or "capabilit" in text.lower(), True)
check("the shim is what the capabilities attach to",
      (ROOT / "core" / "capabilities.py").exists(), True)
# THE HONEST HALF, and it is the half the Windows version of this file was
# written around too: a document that claims a property nobody has watched is
# the failure. The Linux tree states its privilege model in SETUP.md.
install = (ROOT / "SETUP.md").read_text(encoding="utf-8")
check("the install guide states the privilege model",
      "capabilit" in install.lower() or "sudo" in install.lower()
      or "root" in install.lower(), True)
check("and there is a launcher that asks for it",
      (ROOT / "scripts" / "run_elevated.sh").exists(), True)

# THE HONEST HALF, CONVERTED 2026-09-21. The Windows tree's half was "the code
# exists and the token work has not run yet, and there is a script to look
# before trusting it". The Linux tree has the same obligation in a different
# place, and the RULE is what carries across: a tree that claims a privileged
# property nobody has watched must say so in writing, and must ship a way to
# check it before believing it.
#
# On this platform the unproven part is the ELEVATED firewall path -- the
# unelevated refusals were all run, and the real-rule run needs the owner's
# password. T1_FIREWALL_TRUTH.md is where that is written down, and it says it
# in those words rather than leaving the reader to infer it from a missing
# result.
t1 = (ROOT / "T1_FIREWALL_TRUTH.md").read_text(encoding="utf-8")
check("the handoff says which part is not yet proven",
      "not yet proven against the real firewall" in t1, True)
check("and names it as needing the owner's password, not as done",
      "needs your password" in t1, True)
check("and there is a way to look before trusting it",
      (ROOT / "scripts" / "verify_firewall.py").exists(), True)
# The look-before-trusting script has to refuse to run the refusal-path tests
# as root, or "it refused" would be measured on a process that has the rights
# to do the thing, which measures nothing.
_vf = (ROOT / "scripts" / "verify_firewall.py").read_text(encoding="utf-8")
check("and that check refuses to measure refusals as root",
      "Refusing to run the refusal-path tests as root" in _vf, True)

print("\n" + ("ALL CHECKS PASSED" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
