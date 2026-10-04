"""
tests/test_finding_policy.py, TODO 8.4, one rule that three sensors cite.

Section 8.2 warned that "does absence raise, does drift raise, does DNS
novelty raise" is one question asked three times, and that answering them
separately produces three inconsistent mechanisms. It was then answered
separately, three times, in three modules, and the third answer was no
answer at all: dns_monitor called save_finding nowhere.

The damaging part was never the thresholds disagreeing. It was that a sensor
raising nothing is indistinguishable, from outside, from a sensor nobody
finished. This suite mostly guards that: silence must be a decision somebody
wrote down, and a new sensor must not be able to be quiet by omission.
"""
import sys, pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

fails = []
def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}" + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)

from core import finding_policy as fp
from core import memory_engine as me


print("\n[1] an unregistered sensor is FATAL, not defaulted")
# The whole enforcement. A default would let a new sensor silently inherit
# somebody else's threshold, which is how the three mechanisms arose.
raised = False
try:
    fp.should_raise("some_sensor_invented_next_year", 999)
except fp.UnregisteredSensor as e:
    raised = True
    check("the error says silence must be written down",
          "silence has to be a decision" in str(e), True)
check("raised", raised, True)


print("\n[2] three outcomes, never two")
check("raise exists", fp.RAISE, "raise")
check("hold exists, observed but under the bar", fp.HOLD, "hold")
check("never exists, does not raise, by decision", fp.NEVER, "never")


print("\n[3] absence: the threshold is unchanged and now comes from one place")
check("still 8 sweeps", fp.policy_for("presence_absence").threshold, 8)
check("and matches the constant the scanner used",
      fp.policy_for("presence_absence").threshold, me.ABSENCE_FINDING_AFTER)
check("under the bar HOLDS", fp.should_raise("presence_absence", 7)["decision"], fp.HOLD)
check("at the bar raises", fp.should_raise("presence_absence", 8)["decision"], fp.RAISE)
check("a HOLD explains itself rather than vanishing",
      "the bar is 8" in fp.should_raise("presence_absence", 3)["reason"], True)


print("\n[4] drift: one changed field, and the reason says why one is enough")
check("threshold", fp.policy_for("device_drift").threshold, 1)
check("no change holds", fp.should_raise("device_drift", 0)["decision"], fp.HOLD)
check("one change raises", fp.should_raise("device_drift", 1)["decision"], fp.RAISE)
r = fp.policy_for("device_drift")
check("the low bar is justified by the slow cadence, in writing",
      "cadence" in r.rationale, True)


print("\n[5] DNS: silence is now a DECLARATION with a reason attached")
d = fp.should_raise("dns_novelty", 10_000)
check("does not raise however much evidence", d["decision"], fp.NEVER)
check("and says why", len(d["reason"]) > 100, True)
check("and says where the signal IS used instead",
      bool(d["contributes_to"]), True)
print(f"       contributes to: {d['contributes_to'][:60]}...")


print("\n[6] explain_silence answers 'quiet, or not wired up?'")
silent = {s["sensor"] for s in fp.explain_silence()}
check("dns is listed as deliberately silent", "dns_novelty" in silent, True)
check("every silent sensor carries a reason",
      all(s["reason"] for s in fp.explain_silence()), True)
check("and none of them claims to raise",
      any(s["raises"] for s in fp.explain_silence()), False)


print("\n[7] the harvester was registered the night it was built")
# The reason for doing 8.4 now rather than later: a new sensor had just been
# added, and without a register it would have become the fourth inconsistent
# mechanism.
check("announcements do not raise",
      fp.should_raise("announcement_identity", 50)["decision"], fp.NEVER)
check("because the strings are attacker-authorable",
      "controls the device" in fp.policy_for("announcement_identity").rationale, True)
check("but a CONTRADICTION of an enrolled identity does raise",
      fp.policy_for("announcement_contradiction").decision_when, fp.RAISE)
check("on one occurrence, like absence",
      fp.policy_for("announcement_contradiction").threshold, 1)
print("       a violated human declaration raises on one; a statistical")
print("       wobble does not raise at all. That is the same rule twice,")
print("       not two rules.")


print("\n[8] the sensors actually cite the register rather than re-deciding")
for mod, kind in (("tools/network_scanner.py", "presence_absence"),
                  ("tools/probe.py", "device_drift")):
    src = (ROOT / mod).read_text(encoding="utf-8")
    check(f"{mod.split('/')[-1]} imports the policy",
          "finding_policy" in src, True)
    check(f"{mod.split('/')[-1]} asks it about {kind}",
          f'should_raise("{kind}"' in src, True)

dns = (ROOT / "tools" / "dns_monitor.py").read_text(encoding="utf-8")
check("dns_monitor states its silence at the top of the file",
      "RAISES NO FINDINGS, AND THAT IS A DECISION" in dns, True)
# Checked with the AST, not by grepping text. Three checks in one day have
# now failed against the COMMENT explaining the very thing being asserted,
# test_icmp_routing, test_announce_harvester, and this one. Grepping source
# for a word tests the prose. Parsing it tests the code.
import ast as _ast
_calls = {
    n.func.attr for n in _ast.walk(_ast.parse(dns))
    if isinstance(n, _ast.Call) and isinstance(n.func, _ast.Attribute)
}
check("and calls save_finding nowhere in actual code",
      "save_finding" in _calls, False)
check("the word appears only in the comment explaining the decision",
      "save_finding" in dns, True)


print("\n[9] every registered rule is complete enough to act on")
for entry in fp.summary():
    kind = entry["sensor"]
    rule = fp.policy_for(kind)
    check(f"{kind}: has a rationale", len(rule.rationale) > 80, True)
    if entry["raises"]:
        check(f"{kind}: a raising rule states its threshold and unit",
              bool(rule.threshold is not None and rule.unit), True)
    else:
        check(f"{kind}: a silent rule says where the signal goes instead",
              bool(rule.contributes_to), True)

check("the register covers every sensor discussed in 8.4",
      {"presence_absence", "device_drift", "dns_novelty"} <= set(fp.FINDING_RULES),
      True)

print("\n" + ("ALL CHECKS PASSED" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
