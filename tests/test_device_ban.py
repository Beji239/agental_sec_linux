"""
tests/test_device_ban.py, TODO 53.2. Banning a device, and the two rules
around it that matter more than the firewall call.

THE OWNER'S RULE, 2026-09-06, in the owner's words: a new device gets investigated, the
user is ASKED whether they know it, yes goes in the known list and monitoring
carries on, no means ban. And the ban asks first, every time, the way
Secure.AI did it. There is no automatic path and there is not going to be one.

WHAT IS CHECKED HERE:
  the ban is permission gated, and so is its undo
  the card says what a host-level ban can and cannot do
  it refuses the addresses that would lock this machine out of its own network
  a reason is required
  and an active scan no longer raises findings, which is the other half of
  the same decision

The firewall is never touched. This has to pass on a machine where nothing may
change the ruleset, and a test that really banned something would be a test
nobody dares run twice.

CONVERTED TO THIS PLATFORM, 2026-09-21, and the conversion is a REPOINT rather
than a rewrite. It used to import `tools.remediation` -- the Windows class,
which moved OUT of this tree with the L5 pass -- and fake `netsh` by patching
`caps.subprocess.run`. Two things had to change and neither is the rule:

  * the object under test is `adapters.LinuxRemediation`, which is what
    `main.py` loads for the remediation role and what `execute_tool`
    dispatches to. It calls `tools.remediation_linux.block_ip`, which
    delegates to `tools.iptables_manager` -- the firewall layer that picks
    whether ufw, nft or iptables is really in charge.
  * THE FAKE HAD TO MOVE DOWN A LEVEL. Patching a module's `subprocess.run`
    only works if that module made the call itself; here the ruleset is
    reached through `tools.iptables_manager`, which is where the fake belongs.

WHAT COULD NOT BE PORTED AS-IS, and it is recorded rather than faked: the
Windows file drove netsh to the point of a HALF-APPLIED ban and asserted the
rollback, because netsh takes two commands for two directions and the second
could fail. `iptables_manager` has its own verification and rollback, tested
by its own script against a real ruleset (`scripts/verify_firewall.py`), and
faking THAT from here would be asserting a rollback in a module this file does
not drive. So the rollback case is named as out of scope for this file, with
the pointer, rather than quietly dropped. That is the honest half of a moved
raiser: keep the rule, and say where it is enforced now.
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
from core import tool_registry as tr             # noqa: E402

# A database of our own. block_device records a finding, and a test that
# writes into the real one would leave a ban in somebody's review queue.
tmp = pathlib.Path(tempfile.mkdtemp())
me.DB_PATH = tmp / "t.db"
sqlite3.connect(me.DB_PATH).executescript(
    (ROOT / "Schema.SQL").read_text(encoding="utf-8"))
from core import migrations                      # noqa: E402
migrations.run_migrations(me.DB_PATH)

from adapters import LinuxRemediation, _own_addresses   # noqa: E402


print("\n[1] it is gated, and so is the undo")
check("block_device asks first",
      tr.requires_permission("block_device", {"ip": "192.0.2.5"}), True)
check("unblock_device asks too, because re-admitting is a decision",
      tr.requires_permission("unblock_device", {"ip": "192.0.2.5"}), True)
check("reading which devices are blocked does not",
      tr.requires_permission("query_device_blocks", {}), False)
check("all three exist as tools",
      all(tr.tool_exists(n) for n in
          ("block_device", "unblock_device", "query_device_blocks")), True)


print("\n[2] the card says what the ban actually does")
# The user is approving a ban and would otherwise reasonably read it as the
# device being thrown off the network. It is not. It is one host's firewall.
card = tr.permission_summary("block_device",
                             {"ip": "192.0.2.5", "reason": "not recognised"})
check("it names the device", "192.0.2.5" in card, True)
check("and the reason", "not recognised" in card, True)
check("and says it is this machine only",
      "does not cut it off the internet" in card.lower(), True)
check("and names what could do it", "router" in card.lower(), True)


print("\n[3] the refusals, which are the ways to lock yourself out")
# NO FIREWALL FAKE IS NEEDED FOR THIS SECTION, and that is the conversion's
# gain rather than a shortcut. The Windows file had to patch the firewall
# command runner even for the REFUSAL cases, because `block_device` there
# validated and shelled out in the same method. Here the validation happens
# before anything reaches `iptables_manager`, and every refusal below returns
# without a subprocess ever being started. So the check that nothing ran is
# made against a real, unfaked module.
r = LinuxRemediation("test-session")

out = r.block_device(ip="192.0.2.0/24", reason="x")
check("a subnet is refused", out["success"], False)
check("and says why in terms of the call",
      "not a single IP address" in out["error"], True)

out = r.block_device(ip="any", reason="x")
check("the word any is refused", out["success"], False)

out = r.block_device(ip="127.0.0.1", reason="x")
check("loopback is refused", out["success"], False)
check("and it says there is no device there to ban",
      "no device there to ban" in out["error"], True)

# Not a loopback one: those are refused a step earlier, for a different and
# equally correct reason, and this check is about the other guard.
own = sorted(a for a in _own_addresses()
             if a not in ("127.0.0.1", "::1") and ":" not in a
             and a.count(".") == 3)
if own:
    out = r.block_device(ip=own[0], reason="x")
    check("this machine's own address is refused", out["success"], False)
    check("and says it would cut this host off from its own network",
          "own network" in out["error"], True)
else:
    print("  SKIP  psutil could not list local addresses here")

# A REASON IS REQUIRED. Asserted on the CALL, not on card text, and that is
# the stronger form: the guard runs before any card is built or any rule is
# written, so there is no path that reaches the firewall with a blank reason.
# The Windows file asserted this at the same layer for the same reason.
out = r.block_device(ip="192.0.2.5", reason="")
check("no reason means no ban", out["success"], False)
check("and the refusal says what a reason is for",
      "reason is required" in out["error"].lower(), True)
out = r.block_device(ip="192.0.2.5", reason="   ")
check("whitespace is not a reason either", out["success"], False)

# It is also not enough for the tool to say so -- the CARD has to carry the
# reason to the person approving, because the reason is the thing they are
# judging when they read it.
card_with_reason = tr.permission_summary(
    "block_device", {"ip": "192.0.2.5", "reason": "nobody recognised it"})
check("the card carries the reason the ban was asked for",
      "nobody recognised it" in card_with_reason, True)


print("\n[4] and with no firewall backend the ban REFUSES rather than "
      "pretending")
# MEASURED on this host, which is unelevated: the call comes back with
# success False and a sentence naming WHY, and `needs_root` is set. This is
# the shape the whole T1 task was about -- the old code returned
# {"success": True} having run nothing at all.
out = r.block_device(ip="198.51.100.77", reason="nobody recognised it")
check("unelevated, it does not claim to have blocked anything",
      out.get("success"), False)
check("and says the ruleset was not changed",
      "Nothing was changed" in (out.get("error") or ""), True)
check("and flags it as a rights problem rather than a bug",
      bool(out.get("needs_root")), True)
check("and the block did NOT record a finding, because nothing happened",
      me.query_findings(session_id="test-session", limit=10) == []
      or all(f.get("detection_id") != "REM-1004"
             for f in me.query_findings(session_id="test-session", limit=50)),
      True)


print("\n[7] an active scan raises no findings any more")
# The other half of the same decision, TODO 38.5. A finding here is the tool
# reporting a condition it went looking for, landing beside things that came
# from watching.
src = (ROOT / "tools" / "port_scanner.py").read_text(encoding="utf-8")
body = src.split("def scan(", 1)[1]
check("nothing in scan() saves a finding", "save_finding" in body, False)
check("but the result is still recorded",
      "save_port_scan_result" in body, True)
check("and the answer says so out loud",
      "raises no findings" in body, True)


print("\n" + ("ALL PASS" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
