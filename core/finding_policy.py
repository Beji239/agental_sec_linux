# core/finding_policy.py
# AgentalSec V2, when does an observation become a finding?
#
# TODO 8.4. Section 8.2 warned that "does absence raise a finding, does drift
# raise a finding, does DNS novelty raise a finding" is one question asked
# three times, and that answering them separately produces three inconsistent
# mechanisms. It was then answered separately, three times, in three modules:
#
#   absence      raises after 8 consecutive misses, with its own cooldown
#   drift        raises on any change, on the probe's three-week cadence
#   DNS novelty  raises never, dns_monitor calls save_finding nowhere
#
# Nobody decided that. Each module made a locally reasonable call and the
# three disagree. The damaging one is the third: from outside, a sensor that
# raises nothing looks exactly like a sensor with nothing to report. You
# cannot tell "the network was quiet" from "nobody wired this up", and that
# is the failure this whole codebase is organised against.
#
# WHAT THIS MODULE IS, AND WHAT IT DELIBERATELY IS NOT
#
# It is a REGISTER of decisions, not a detector. It does not look at traffic
# and it does not score anything. Each sensor that could raise a finding has
# exactly one entry here saying what its rule is and why, including the
# sensors whose rule is "this never raises alone".
#
# The enforcement is the point: policy_for() RAISES on an unregistered
# sensor. A new sensor cannot be quiet by omission. Somebody has to write
# down what its silence means before it is allowed to be silent, which is
# the single property that was missing.
#
# Thresholds live here rather than in each module so that changing one is a
# decision recorded in one place, and so that two sensors cannot drift apart
# without the diff showing it.

import logging

logger = logging.getLogger(__name__)


class UnregisteredSensor(Exception):
    """
    A sensor asked whether to raise, and no policy exists for it.

    This is deliberately fatal rather than a default. A default would let a
    new sensor inherit somebody else's threshold silently, which is how the
    three mechanisms this module exists to reconcile came about.
    """


# The three answers a policy can give. Never two, the middle one is what
# makes quiet legible.
RAISE   = "raise"     # enough evidence; write a finding
HOLD    = "hold"      # observed, recorded, below the bar. NOT nothing.
NEVER   = "never"     # this signal does not raise on its own, by decision


class Rule:
    """One sensor's answer, with the reasoning attached to it."""

    def __init__(self, decision_when, threshold, unit, rationale,
                 contributes_to=None, cites=None):
        self.decision_when = decision_when   # RAISE or NEVER
        self.threshold = threshold           # None when decision is NEVER
        self.unit = unit                     # what the threshold counts
        self.rationale = rationale
        self.contributes_to = contributes_to  # for NEVER: where it IS used
        self.cites = cites                   # the constant this mirrors

    def evaluate(self, evidence: float | int) -> dict:
        if self.decision_when == NEVER:
            return {
                "decision": NEVER,
                "reason": self.rationale,
                "contributes_to": self.contributes_to,
            }
        if evidence is None:
            return {"decision": HOLD, "reason": "no evidence counted yet",
                    "threshold": self.threshold, "unit": self.unit}
        if evidence >= self.threshold:
            return {"decision": RAISE, "evidence": evidence,
                    "threshold": self.threshold, "unit": self.unit,
                    "reason": self.rationale}
        return {
            "decision": HOLD, "evidence": evidence,
            "threshold": self.threshold, "unit": self.unit,
            "reason": (f"observed {evidence} {self.unit}, the bar is "
                       f"{self.threshold}. Recorded, not raised."),
        }


# THE REGISTER

FINDING_RULES: dict[str, Rule] = {

    "presence_absence": Rule(
        decision_when=RAISE,
        threshold=8,
        unit="consecutive missed presence sweeps",
        cites="memory_engine.ABSENCE_FINDING_AFTER",
        rationale=(
            "A permanent device is one the USER declared should always be "
            "here, so its absence is a violated declaration, which is the "
            "one thing this tool raises on without hedging. Eight sweeps is "
            "about two hours, long enough to survive a reboot, a sleep "
            "cycle or a DHCP renewal, short enough to still be the same "
            "evening. Only devices marked permanent qualify; an ordinary "
            "device going quiet is not a claim about anything."
        ),
    ),

    "device_drift": Rule(
        decision_when=RAISE,
        threshold=1,
        unit="fingerprint fields changed since enrollment",
        cites="tools/probe.py",
        rationale=(
            "The fingerprint is only recomputed every three weeks, and only "
            "for devices the user vouched for. By the time it is compared at "
            "all, both sides are things a human asserted. A single changed "
            "field is therefore already a contradiction of a declaration, "
            "not a fluctuation, and the low threshold is bought by the slow "
            "cadence rather than in spite of it."
        ),
    ),

    "dns_novelty": Rule(
        decision_when=NEVER,
        threshold=None,
        unit="first contacts with an unseen name",
        contributes_to=("beacon_interval analysis; behavioural baselines; "
                        "the model's own reading via query_dns"),
        rationale=(
            "A name never resolved before is the single most common event on "
            "any network with a browser on it. Raising on it would produce "
            "findings faster than anyone can read them, and this codebase "
            "already documents where that leads: a system that trains its "
            "operator to ignore its own sensors. "
            "So DNS novelty does NOT raise alone, BY DECISION, recorded "
            "here, and not by nobody having wired it up. It is evidence that "
            "makes other findings stronger, and it stays fully queryable. "
            "If this is ever revisited, the version worth building is "
            "novelty COMBINED with something else: a new name on a metronome "
            "cadence, or a new name from a device whose baseline is "
            "otherwise stable and narrow."
        ),
    ),

    "announcement_identity": Rule(
        decision_when=NEVER,
        threshold=None,
        unit="device self-descriptions harvested from broadcast traffic",
        contributes_to="the device inventory and enrollment queue",
        rationale=(
            "Registered the same night the harvester was built, so that it "
            "could not become the fourth inconsistent mechanism while the "
            "ink was wet. Every string it collects is chosen by the device, "
            "therefore by whoever controls the device; a finding raised from "
            "it would be a finding an attacker can author on demand. "
            "Announcements populate the inventory and put unknown devices in "
            "front of a human for enrollment. That is a queue, not an alert."
        ),
    ),

    "announcement_contradiction": Rule(
        decision_when=RAISE,
        threshold=1,
        unit="devices whose announced identity contradicts an enrolled one",
        rationale=(
            "The exception to the rule above, and the reason the rule above "
            "is safe. A device the user NAMED and vouched for, now "
            "announcing itself as something else, is a violated declaration "
            ", the same shape as absence. One occurrence is enough because "
            "the comparison is against a human's assertion, not against a "
            "statistical norm. Not yet implemented; registered so that when "
            "it is, it inherits this threshold instead of inventing one."
        ),
    ),
}


def policy_for(sensor_kind: str) -> Rule:
    """
    The rule for a sensor. Raises if none is registered.

    Fatal on purpose. A sensor with no entry here would otherwise be quiet
    for an unrecorded reason, and unrecorded quiet is exactly the state 8.4
    exists to make impossible.
    """
    rule = FINDING_RULES.get(sensor_kind)
    if rule is None:
        raise UnregisteredSensor(
            f"No finding policy for sensor kind '{sensor_kind}'. Add an entry "
            f"to core/finding_policy.FINDING_RULES, including if the answer "
            f"is that it never raises, silence has to be a decision "
            f"somebody wrote down, not an omission."
        )
    return rule


def should_raise(sensor_kind: str, evidence=None) -> dict:
    """
    Ask the register whether this observation clears the bar.

    Returns a decision dict; never a bare boolean. A caller that wants a
    boolean can test `["decision"] == RAISE`, but the reason travels with it
    so a HOLD can be logged as a held observation rather than vanishing.
    """
    return policy_for(sensor_kind).evaluate(evidence)


def explain_silence() -> list[dict]:
    """
    Every sensor that does NOT raise, and why.

    The answer to "is this quiet because nothing happened, or because
    nothing is wired up". Surface this next to any empty findings list.
    """
    return [
        {
            "sensor": kind,
            "raises": False,
            "reason": rule.rationale,
            "contributes_to": rule.contributes_to,
        }
        for kind, rule in FINDING_RULES.items()
        if rule.decision_when == NEVER
    ]


def summary() -> list[dict]:
    """The whole register, for a status page or a reviewer."""
    return [
        {
            "sensor": kind,
            "raises": rule.decision_when == RAISE,
            "threshold": rule.threshold,
            "unit": rule.unit,
            "cites": rule.cites,
            "contributes_to": rule.contributes_to,
        }
        for kind, rule in FINDING_RULES.items()
    ]
