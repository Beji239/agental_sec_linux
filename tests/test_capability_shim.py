"""
tests/test_capability_shim.py, the privileged capability surface.

THIS FILE IS NOW THE LINUX SURFACE'S TEST, and what it checks is what is still
LOAD-BEARING here: the shim refuses to be a general instruction, and the
operations this platform really performs (killing a process, reading process
details, the connection table, capture) are the only ones on it.

CONVERTED 2026-09-25, THE WINDOWS-LEFTOVERS ROUND. WHAT WAS HERE AND WHY IT
WENT. Every check below was written against the TWELVE primitives of the
Windows tree's plan -- capture, the four Security-channel calls, netsh firewall
add/delete/list, process kill and details, the connection table, and Defender's
detections. Seven of those twelve were Windows programs: `win32evtlog` for the
event channel and `netsh advfirewall`/`Get-MpThreatDetection` for the other
three capabilities. None of them can run on this host, none of them had a
caller in this tree, and the capability ROWS for two of them were the permanent
red lines on the Settings card that this round exists to remove.

The rule this file was written for is unchanged and is still asserted:
A PRIVILEGED OPERATION MUST GO THROUGH core.capabilities, so there is one place
that decides whether this app may do it and one place to audit. What changed is
the LIST of privileged operations this platform has. Deleting a check for a
netsh call that can no longer be made would be losing the property; restating
it against the operations that remain is keeping it.

The removed seven are not silently dropped: section [1b] asserts they are GONE,
by name, so a future session that adds one back has to delete that check first.

Runs anywhere. Nothing below needs Windows, pywin32, scapy or administrator
rights, because everything privileged is either refused before it runs or
stubbed.
"""
import os
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


from core import capabilities as caps  # noqa: E402

C = caps.Capabilities()


print("\n[1] the surface is small, and it is THIS platform's shape")
verbs = [n for n in dir(C) if not n.startswith("_")
         and callable(getattr(C, n)) and n != "availability"]
check("four primitives across four capabilities", sorted(verbs), sorted([
    "capture_open",
    "process_kill", "process_details", "conn_table",
]))
# The named-and-shamed list from the plan. These are not missing by accident,
# and a future session adding one should have to delete this line first.
for banned in ("run_command", "read_file", "powershell", "exec", "shell"):
    check(f"no {banned} verb", banned in verbs, False)


print("\n[1b] and the WINDOWS primitives are gone by name, not by accident")
# The seven that left with their programs. Asserted rather than assumed,
# because the failure this catches is somebody re-adding a verb that has no
# implementation on this platform and putting a permanently-unavailable row
# back on the card.
for gone in ("event_log_open", "event_log_bounds", "event_log_read",
             "event_log_close", "firewall_add", "firewall_delete",
             "firewall_list", "defender_detections"):
    check(f"{gone} is not on the surface", hasattr(C, gone), False)
# And the module-level constants that existed only for them.
for gone in ("WIN32_AVAILABLE", "NPCAP_KEY", "npcap_admin_only",
             "NOT_ON_THIS_PLATFORM", "MODE_INPROCESS", "set_instance",
             "PRIVILEGED_CHANNELS", "RULE_PREFIX", "NETSH_DIR"):
    check(f"caps.{gone} is gone", hasattr(caps, gone), False)
check("no 'security_log' capability row is published",
      "security_log" in C.availability(), False)
check("no 'defender' capability row is published",
      "defender" in C.availability(), False)


print("\n[2] process_kill refuses what it must, and validates its arguments")
# THE TRUST BOUNDARY, restated against the verb that is left. This is the
# operation that can end somebody's process, so it is the one that gets the
# argument checks.
for bad, why in [("abc", "a non-numeric pid"),
                 (0, "pid 0"),
                 (2 ** 40, "a pid past the ceiling"),
                 (None, "nothing at all")]:
    try:
        C.process_kill(bad, "x")
        check(f"refused {why}", "allowed", "refused")
    except (caps.CapabilityError, caps.CapabilityUnavailable):
        check(f"refused {why}", "refused", "refused")

# REM-1, one layer down: the boundary does not end its own caller. This is the
# defect the remediation round measured through the shipped adapter.
try:
    C.process_kill(os.getpid(), "python")
    check("refused to kill the calling process", "allowed", "refused")
except (caps.CapabilityError, caps.CapabilityUnavailable) as e:
    check("refused to kill the calling process", "refused", "refused")
    check("and says which process it is",
          "the process making this call" in str(e), True)


print("\n[3] process_details reads, and only reads")
# Added on the owner's call so command lines do not go blank on a shared machine.
# The check that matters is that it stays a read: it takes numbers and gives
# back strings, and it cannot be handed anything else.
if caps.PSUTIL_AVAILABLE:
    got = C.process_details([os.getpid()])
    check("it answers for a live pid", os.getpid() in got, True)
    check("with the three fields and nothing more",
          sorted(got[os.getpid()]), ["cmdline", "exe", "username"])
    check("a pid that does not exist is simply absent, not an error",
          C.process_details([2 ** 30]), {})
for bad, why in [("all", "a string instead of a list"),
                 (None, "nothing at all"),
                 (1234, "a bare number"),
                 (list(range(caps.MAX_DETAIL_PIDS + 1)), "more pids than exist"),
                 ([("rm", "-rf")], "a pid that is not a number")]:
    try:
        C.process_details(bad)
        check(f"refused {why}", "allowed", "refused")
    except (caps.CapabilityError, caps.CapabilityUnavailable):
        check(f"refused {why}", "refused", "refused")


print("\n[3b] the connection table takes no arguments, so there is nothing to abuse")
# It is the one verb with no parameters at all, and that is the property: a
# caller cannot ask it to look at anything in particular.
if caps.PSUTIL_AVAILABLE:
    rows = C.conn_table()
    check("it answers with a list", isinstance(rows, list), True)
    if rows:
        check("each row has exactly the four fields",
              sorted(rows[0]), ["name", "pid", "port", "proto"])
        check("and a zero pid is never attached to a real socket",
              any(r["pid"] == 0 for r in rows), False)


print("\n[4] missing and refused are different sentences")
check("CapabilityUnavailable is not a CapabilityError",
      issubclass(caps.CapabilityUnavailable, caps.CapabilityError), False)
avail = C.availability()
# THE ROWS ARE THIS PLATFORM'S, and every one of them is a capability it HAS.
# The set changed this round: the two Windows rows are gone with their verbs.
check("availability reports every capability this platform has",
      sorted(avail), sorted(["capture", "process_kill", "process_details",
                             "conn_table", "firewall_write", "firewall_read"]))
for name, row in avail.items():
    if not row["available"]:
        check(f"{name} says what is missing", bool(row["why_not"]), True)
    # No row may carry a kind that means "this platform does not have it": in
    # this tree a capability row that can never go green is the defect.
    check(f"{name} carries a kind this platform can act on",
          row["kind"] in ("available", "limited", "unavailable"), True)


print("\n[4b] availability asks BOTH halves, library AND rights")
# The first version of availability() only asked whether the library was
# installed. On an unelevated run it reported all eight available directly
# under a card row saying three modules were unavailable for want of rights.
# Two rows on one card contradicting each other is worse than no card.
from core import privilege_linux as priv  # noqa: E402
_real = priv.is_elevated
try:
    priv.is_elevated = lambda: False
    un = C.availability()
    for name in caps.CANNOT_WITHOUT_ELEVATION:
        check(f"{name} is not available unelevated", un[name]["available"], False)
        # A missing library outranks a missing right, and says so. Only check
        # the wording where the library IS present, otherwise this asserts
        # that the machine running the test has scapy.
        why = un[name]["why_not"] or ""
        if "not installed" not in why:
            check(f"and {name} blames rights, not a missing library",
                  bool("not elevated" in why or "root" in why), True)
    for name in caps.LIMITED_WITHOUT_ELEVATION:
        if not un[name]["available"]:
            continue                     # the library is genuinely missing
        check(f"{name} still works unelevated", un[name]["available"], True)
        check(f"but {name} says how much narrower", bool(un[name]["limited"]),
              True)
    priv.is_elevated = lambda: True
    el = C.availability()
    check("nothing is held back by rights when elevated",
          [n for n in caps.CANNOT_WITHOUT_ELEVATION
           if el[n]["available"] is False and "not elevated" in
           (el[n]["why_not"] or "")], [])
finally:
    priv.is_elevated = _real


print("\n[5] the readiness card asks the shim what is available")
# The card used to say only whether a module was RUNNING. Whether the machine
# will let it is a different question, and this process cannot answer it by
# looking, only the shim can.
from core import settings as st  # noqa: E402
prows = st._privilege_rows()
check("it produces rows", len(prows) > 0, True)
check("all under one area",
      sorted({r["area"] for r in prows}), ["Privileged access"])
check("and it says what rights this run has",
      any(r["title"] == "Administrator rights" for r in prows), True)
check("every row has a state the card knows how to paint",
      all(r["state"] in ("ok", "off", "problem") for r in prows), True)
check("and a row that is not ok says why",
      all(r["detail"] for r in prows if r["state"] != "ok"), True)
# THE TWO ROWS THIS ROUND REMOVED, asserted gone. If either comes back, the
# card is painting a Windows capability at the operator again.
check("no Windows capability row on the card",
      [r["title"] for r in prows
       if r["title"] in ("Windows Security channel", "Defender detections")], [])
# The contradiction check, in the card's own words this time: it must not
# claim capabilities are fine on a run it just said was not elevated.
priv.is_elevated = lambda: False
try:
    unrows = st._privilege_rows()
    said_not_elevated = any(r["title"] == "Administrator rights"
                            and r["state"] == "problem" for r in unrows)
    claimed_all = any("all 6 available" in r["detail"] for r in unrows)
    check("an unelevated run is reported as a problem", said_not_elevated, True)
    check("and the card does not then claim every capability is fine",
          claimed_all, False)
finally:
    priv.is_elevated = _real
check("readiness() actually includes them",
      "_privilege_rows()" in (ROOT / "core" / "settings.py").read_text(
          encoding="utf-8").split("def readiness")[1].split("def ")[0], True)


print("\n[6] nothing outside the shim touches a privileged thing")
# Negative assertions on source text, deliberately. Positive assertions on
# exact source lines break when somebody renames a variable; these break only
# when a direct privileged call comes BACK, which is the thing worth being
# told about.
BANNED = {
    # A PRIVILEGED operation must go through core.capabilities, so there is one
    # place that decides whether this app may do it and one place to audit.
    # remediation_linux CHANGES the firewall and kills processes, so it is the
    # module that has to go through the shim.
    "tools/remediation_linux.py":      ["subprocess.run("],
    # The Linux capture path must use the adapter's capability check rather
    # than opening a socket itself.
    "tools/packet_sniffer_linux.py":   ["from scapy.all import sniff"],
    "tools/iptables_manager.py":       ["subprocess.run(\"nft "],
    # tools/process_monitor is a SHARED READ module now (the Windows poll loop,
    # its Defender half and its PowerShell signature sweep left 2026-09-25).
    # Nothing in it may call PowerShell again.
    "tools/process_monitor.py":        ["powershell", "Get-MpThreatDetection",
                                        "Get-AuthenticodeSignature"],
}


def _code_only(text):
    """
    The source with its comments taken out.

    2026-09-13, TODO 89. This check read the WHOLE file, so writing a comment
    explaining why Get-MpThreatDetection is not called here failed the
    assertion that it is not called here. The rule is "no privileged CALL",
    not "never say the name out loud", and a check that cannot tell a comment
    from a call is answering a narrower question than its label claims, which
    is the same fault this suite keeps finding in the app itself.

    Line comments only. Good enough on purpose: a banned call hidden inside a
    triple-quoted string is not a thing that happens by accident, and a
    cleverer stripper would be a parser nobody asked for.
    """
    out = []
    for line in text.splitlines():
        head = line.split("#", 1)[0]
        if head.strip():
            out.append(head)
    return "\n".join(out)


for rel, banned in BANNED.items():
    src = _code_only((ROOT / rel).read_text(encoding="utf-8"))
    for token in banned:
        check(f"{rel} no longer calls {token}", token in src, False)
    # WHO IMPORTS THE SHIM DEPENDS ON WHICH MODULE THIS IS.
    #
    #   remediation_linux  TAKES the privileged action (it kills processes,
    #                      blocks addresses, quarantines files), so IT is the
    #                      module that must go through core.capabilities.
    #   iptables_manager   is the TOOL remediation calls, one layer below. It
    #                      is not a second boundary and it does not import the
    #                      shim; requiring it to would mean two modules
    #                      deciding whether this app may act.
    #
    # The tokens above are still checked on both, because a direct call is a
    # direct call whoever makes it.
    if rel.endswith("remediation_linux.py"):
        check(f"{rel} imports the shim",
              "from core import capabilities" in src, True)

# The stripper has to actually strip, or this whole section goes quietly green
# for the wrong reason. A check that can only pass is not a check.
check("a commented out call does not count",
      "psutil.net_connections" in _code_only("# psutil.net_connections()"), False)
check("but a real one still does",
      "psutil.net_connections" in _code_only("x = psutil.net_connections()"), True)
check("and a trailing comment does not hide the code before it",
      "psutil.net_connections" in _code_only("x = psutil.net_connections()  # ok"),
      True)

shim_src = _code_only((ROOT / "core" / "capabilities.py").read_text(
    encoding="utf-8"))
# The Windows programs the shim used to name. This is the whole point of the
# round in one assertion: the file that decides what this app may do must not
# be able to call a Windows component, on any code path.
for token in ("win32evtlog", "netsh", "powershell", "Get-MpThreatDetection",
              "winreg", "Npcap"):
    check(f"and the shim itself never names {token}", token in shim_src, False)


print("\n[7] one instance, and one kind of instance")
# The Windows tree swapped in a helper-backed surface here at step 3. That
# design (and its protocol, its client and its launcher) is a Windows program
# and lives in agental_sec_win32_reference/ now; this platform grants rights to
# the BINARY, so there is nothing to swap and nothing that can go stale behind
# the instance the app is holding.
check("get() is a singleton", caps.get() is caps.get(), True)
check("and it is a plain Capabilities", type(caps.get()), caps.Capabilities)
check("with no mode to be in", hasattr(caps.get(), "mode"), False)


print("\n" + ("ALL CHECKS PASSED" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
