"""
tests/test_sensor_health.py, the model has to be told when a sensor is blind.

WHERE THIS CAME FROM. 2026-09-07. Three dashboard surfaces were corrected that
afternoon for the same fault, a sensor that could not see reported as fine.
All three fixes were on SCREENS. Then the owner asked the question that mattered:
the model does not look at screens.

On a run where capture is blind, query_packets returns []. Nothing in that
answer said the sensor was never able to look. The model reads [] as a quiet
network, and unlike a wrong tile, that conclusion gets WRITTEN DOWN, into the
behavioural tables, where a later session reads it as measured fact.

So every tool declares what its answer rests on, an undeclared tool is fatal,
and a degraded dependency travels with the result into the model's context.

Runs anywhere. No database, no network, no Windows.
"""
import pathlib
import re
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


from core import sensor_health as sh          # noqa: E402
from core import capabilities as caps         # noqa: E402
from core import privilege_linux as pv        # noqa: E402


class machine_is_fine:
    """
    Pretend this machine allows everything, for the checks that are about the
    MODULE half rather than the capability half.

    Needed because the suite runs on a host where scapy may be absent, so
    "capture is unavailable" is a true answer and not the thing under test.
    Restored on exit, always.

    WIN32_AVAILABLE WAS IN THIS LIST until 2026-09-25, when the pywin32 import
    and the `security_log` row it fed left core/capabilities.py. There is no
    Windows half of the capability table to pretend about any more.
    """

    def __enter__(self):
        self._saved = (caps.SCAPY_AVAILABLE,
                       caps.PSUTIL_AVAILABLE, pv.is_elevated)
        caps.SCAPY_AVAILABLE = caps.PSUTIL_AVAILABLE = True
        pv.is_elevated = lambda: True
        return self

    def __exit__(self, *a):
        (caps.SCAPY_AVAILABLE,
         caps.PSUTIL_AVAILABLE, pv.is_elevated) = self._saved
        return False


class Fake:
    def __init__(self, status=None):
        self._status = status

    def status(self):
        if self._status is None:
            raise RuntimeError("this module's health check is broken")
        return self._status


HEALTHY = {"running": True}
BLIND = {"running": True, "blind": True,
         "blind_reason": "installed, but this process is not elevated, so "
                         "Npcap will not open an adapter"}


print("\n[1] EVERY tool declares what it rests on, or the suite fails")
# The enforcement, and the reason this file is not just three unit tests. A
# tool added next month that says nothing looks identical to one that really
# depends on nothing, and its empty answer on a blind run is unexplained.
src = (ROOT / "core" / "tool_registry.py").read_text(encoding="utf-8")
names = set(re.findall(r'"name":\s*"([a-z_]+)"', src))
check("the manifest was found at all", len(names) > 40, True)
check("no tool is missing a declaration",
      sorted(n for n in names if n not in sh.DEPENDS), [])
check("and nothing is declared that is not a tool",
      sorted(k for k in sh.DEPENDS if k not in names), [])

raised = False
try:
    sh.depends_on("some_tool_added_next_month")
except sh.UnregisteredTool as e:
    raised = True
    check("the error explains what goes wrong without it",
          "quiet network" in str(e), True)
check("an undeclared tool raises", raised, True)
check("declaring nothing is allowed, and is a claim",
      sh.depends_on("query_database_size"), ())


print("\n[2] a healthy run adds nothing at all")
mods = {"packet_sniffer": Fake(HEALTHY), "event_monitor": Fake(HEALTHY)}
with machine_is_fine():
    check("no warnings", sh.warnings_for("query_packets", mods), [])
    check("and no envelope, so nothing is added to the result",
          sh.envelope_for("query_packets", mods), None)


print("\n[3] a blind sensor reaches the model, in words")
mods = {"packet_sniffer": Fake(BLIND)}
w = sh.warnings_for("query_packets", mods)
check("it warns", len(w) >= 1, True)
check("it names the sensor and says BLIND",
      "packet_sniffer is BLIND" in w[0], True)
check("and carries the sensor's own reason",
      "not elevated" in w[0], True)

env = sh.envelope_for("query_packets", mods)
check("the envelope lists what is degraded", len(env["degraded"]) >= 1, True)
check("and tells the reader what to do with it",
      "not evidence that nothing happened" in env["how_to_read_this"]
      or "not evidence" in env["how_to_read_this"], True)
check("naming the exact trap: silence is not quiet",
      "not evidence of a quiet network" in env["how_to_read_this"], True)


print("\n[4] the other three ways a dependency goes bad")
check("not loaded is its own sentence",
      "NOT LOADED" in sh.warnings_for("query_packets",
                                      {"packet_sniffer": None})[0], True)
check("a module absent from the dict is also not loaded",
      "NOT LOADED" in sh.warnings_for("query_packets", {})[0], True)
check("not answering carries the failure count and the error",
      sh.warnings_for("list_monitored_hosts", {"linux_monitor:192.0.2.8": Fake(
          {"running": True, "reachable": False, "consecutive_failures": 3,
           "last_error": "could not open an SSH session"})}),
      ["linux_monitor:192.0.2.8 is NOT ANSWERING, 3 polls in a row have "
       "failed: could not open an SSH session"])
check("not running says so",
      "NOT RUNNING" in sh.warnings_for("web_search", {"web_search": Fake(
          {"running": False, "reason": "no backend answered"})})[0], True)
check("a status() that throws is a finding, not a crash",
      "could not report its own health" in
      sh.warnings_for("query_packets", {"packet_sniffer": Fake(None)})[0], True)


print("\n[5] one declared dependency, several loaded hosts")
# linux_monitor is registered per host as linux_monitor:<address>. A tool
# declaring "linux_monitor" has to match all of them, or the second host is
# silently unwatched by this check.
mods = {"linux_monitor:192.0.2.8": Fake(HEALTHY),
        "linux_monitor:192.0.2.9": Fake({"running": True, "reachable": False,
                                         "last_error": "timed out"})}
w = sh.warnings_for("list_monitored_hosts", mods)
check("only the unhealthy host is named", len(w), 1)
check("and it is the right one", "192.0.2.9" in w[0], True)


print("\n[6] what the MACHINE refuses, not just what the module says")
from core import privilege_linux as privilege  # noqa: E402
_real = privilege.is_elevated
try:
    privilege.is_elevated = lambda: False
    w = sh.warnings_for("block_port", {"remediation": Fake(HEALTHY)})
    check("an action the machine will refuse is flagged before it runs",
          any("firewall_write" in line for line in w), True)
    w = sh.warnings_for("kill_process", {"remediation": Fake(HEALTHY)})
    check("and a capability that is merely narrower says that instead",
          any("narrower than usual" in line for line in w), True)
    privilege.is_elevated = lambda: True
    check("elevated, the same tools are clean",
          sh.warnings_for("block_port", {"remediation": Fake(HEALTHY)}), [])
finally:
    privilege.is_elevated = _real


print("\n[7] the write tools are covered, which is where the damage lasts")
# A wrong tile annoys somebody for a minute. A baseline written from a window
# the sensor could not see is read as measured fact by every later session.
for tool in ("write_behavioral_observation", "update_behavioral_baseline",
             "write_deviation", "query_behavioral_baseline"):
    check(f"{tool} rests on capture",
          any("packet_sniffer" in d or "capture" in d
              for d in sh.depends_on(tool)), True)


print("\n[8] it actually travels in the envelope, end to end")
from core import tool_registry as tr           # noqa: E402
tr._modules = {"packet_sniffer": Fake(BLIND)}
real_dispatch = tr._dispatch
try:
    tr._dispatch = lambda name, params: {"packets": []}
    out = tr.execute_tool("query_packets", {})
    check("the tool still succeeds", out["error"], None)
    check("the payload is untouched", out["result"], {"packets": []})
    check("and the envelope carries the warning",
          "sensor_health" in out, True)
    check("with the reading note the model needs",
          "quiet network" in out["sensor_health"]["how_to_read_this"], True)

    tr._modules = {"packet_sniffer": Fake(HEALTHY)}
    with machine_is_fine():
        out = tr.execute_tool("query_packets", {})
    check("and adds nothing when the sensor is fine",
          "sensor_health" in out, False)
finally:
    tr._dispatch = real_dispatch


print("\n[9] the model is told what the block means")
prompt = (ROOT / "core" / "agent_loop.py").read_text(encoding="utf-8")
check("the prompt names the field", "sensor_health" in prompt, True)
check("it says empty is not quiet",
      "EMPTY ANSWER IS NOT THE SAME AS A QUIET NETWORK" in prompt, True)
check("and forbids writing a baseline off a blind window",
      "Do NOT write a behavioural observation" in prompt, True)


print("\n[10] the model can also ASK, not only be told")
# Being warned inside a result is the important half. The other half is being
# able to check before drawing a conclusion, which is what an analyst does.
from core import tool_registry as tr2          # noqa: E402
names = [x["name"] for x in tr2.TOOL_MANIFEST]
check("the tool exists", "query_sensor_health" in names, True)
check("it is read only", tr2.tool_writes("query_sensor_health"), False)
check("and asks no permission", tr2.requires_permission("query_sensor_health", {}), False)
check("and it is not on the derived write list",
      "query_sensor_health" in tr2.write_tools(), False)

tr2._modules = {"packet_sniffer": Fake(BLIND), "linux_monitor:192.0.2.8": None}
rep = tr2._sensor_health_report()
check("it reports elevation", "elevated" in rep, True)
check("it names the blind sensor", rep["modules"]["packet_sniffer"]["blind"], True)
check("a module that never loaded says so",
      rep["modules"]["linux_monitor:192.0.2.8"]["loaded"], False)
check("it lists what the machine allows", "capture" in rep["capabilities"], True)
check("and hands over the whole dependency map",
      len(rep["tool_dependencies"]) > 40, True)

one = tr2._sensor_health_report("query_packets")
check("asked about one tool, it answers about that one",
      one["tool_dependencies"], ["packet_sniffer", "cap:capture"])
check("and says what is wrong with it right now",
      any("BLIND" in line for line in one["tool_degraded_now"]), True)
check("an unknown tool name is answered, not raised",
      "No sensor dependency entry" in
      tr2._sensor_health_report("not_a_tool")["tool_degraded_now"][0], True)


print("\n[11] OFF is not BROKEN")
# 2026-09-07, from the first live run. router_monitor is switched off in
# config.json and never enters the modules dict, so the check called it NOT
# LOADED and the model reported a deliberate configuration choice as a
# degradation. Both explain an empty answer. Only one is worth fixing, and a
# warning list that mixes them is a list somebody learns to skip.
w = sh.warnings_for("query_router_config", {})
check("it still explains the empty answer", len(w), 1)
check("but says OFF, not broken", "OFF, not broken" in w[0], True)
check("and names it as a choice",
      "configuration choice" in w[0], True)
check("and still refuses to let it read as quiet",
      "rather than a quiet network" in w[0], True)
check("a module that is genuinely absent still says so honestly",
      "NOT LOADED" in sh.warnings_for("query_packets", {})[0], True)


print("\n[12] a claim of measurement is REFUSED, not merely discouraged")
# The prompt already tells the model not to write a measured row on a blind
# run. This is the same argument quarantine_file makes about the permission
# card: a gate that asks a reader to be the denylist is not a denylist.
ok, why = sh.measurement_is_possible(
    "write_behavioral_observation",
    {"packet_sniffer": Fake(BLIND), "event_monitor": Fake(BLIND)})
check("with every sensor blind, measurement is impossible", ok, False)
check("and it names them", "packet_sniffer is BLIND" in why, True)

ok, _ = sh.measurement_is_possible(
    "write_behavioral_observation",
    {"packet_sniffer": Fake(BLIND), "event_monitor": Fake(HEALTHY)})
check("ONE healthy sensor is enough to allow it", ok, True)
check("a tool with no live sensors is never blocked",
      sh.measurement_is_possible("supersede_observation", {})[0], True)

tr._modules = {"packet_sniffer": Fake(BLIND), "event_monitor": Fake(BLIND)}
real = tr._dispatch
try:
    out = tr.execute_tool("write_behavioral_observation",
                          {"entity_type": "ip", "entity_value": "192.0.2.1",
                           "behavior_key": "typical_dest_ips",
                           "behavior_value": "x", "basis": "measured"})
    check("the write is refused", out["result"]["success"], False)
    check("the refusal says why", "Nothing could have measured" in
          out["result"]["error"], True)
    check("and names the valid alternatives",
          "model_conclusion" in out["result"]["error"], True)

    tr._dispatch = lambda n, p: {"success": True, "id": 1}
    out = tr.execute_tool("write_behavioral_observation",
                          {"entity_type": "ip", "entity_value": "192.0.2.1",
                           "behavior_key": "typical_dest_ips",
                           "behavior_value": "x", "basis": "model_conclusion"})
    check("but the honest basis still writes on the same blind run",
          out["result"]["success"], True)
    check("carrying the warning with it",
          "sensor_health" in out, True)
finally:
    tr._dispatch = real


print("\n[13] the operator decides, and a timeout is not a decision")
# 2026-09-07, from the elevated run. Asked to block port 445, the model
# declined to act at all and justified it with an invented mechanism. The
# approval card is the operator's gate. Objecting is the model's job; deciding
# is not.
loop_src = (ROOT / "core" / "agent_loop.py").read_text(encoding="utf-8")
check("the prompt tells it to object and still send the card",
      "OBJECT LOUDLY, THEN SEND THE CARD ANYWAY" in loop_src, True)
flat = " ".join(loop_src.split())
check("and that no finding is a reason to object, not to refuse",
      "It is not a reason to refuse" in flat, True)
check("it names the two cases where refusing IS right",
      "the machine will refuse it anyway" in loop_src, True)
check("and the invented mechanism is written down as the reason",
      "talks SMB over 445" in loop_src, True)

# A card nobody answered is not a person saying no.
check("expired is a third answer, not folded into denied",
      '"expired"' in loop_src, True)
check("the model is told plainly it was not a refusal",
      "it is NOT a refusal" in loop_src, True)
# The window check that used to live here (PERMISSION_TIMEOUT = 600) is gone
# on purpose. There is no window any more, see [16].


print("\n[14] a row we caused cannot have a second cause invented for it")
# The note naming the real cause was already on every self-induced row, and
# the model walked past it forty rows deep and supplied a mechanism of its
# own. So it is summarised once at the top of the answer instead.
tr._modules = {}
real = tr._dispatch
try:
    import core.memory_engine as _me
    real_qp, real_scope = _me.query_packets, _me.packet_search_scope
    _me.query_packets = lambda **kw: [
        {"src_ip": "192.0.2.5", "dst_ip": "192.0.2.8", "self_induced": True,
         "self_induced_note": "caused by this tool's own port scan of 192.0.2.8"},
        {"src_ip": "192.0.2.7", "dst_ip": "192.0.2.8", "self_induced": False},
    ]
    _me.packet_search_scope = lambda **kw: {"searched": "test"}
    out = tr.execute_tool("query_packets", {})
    block = out["result"]["self_induced_rows"]
    check("the block appears when any row is ours", block["count"], 1)
    # RENAMED 2026-09-14, TODO 98. len(rows) is what came back after the
    # limit, so "of_total" read as a share of everything that matched when it
    # was a share of the sample. The scope block carries the real total.
    check("and says how many of how many came back", block["of_returned"], 2)
    check("and no longer calls that a total", "of_total" in block, False)
    check("it quotes the recorded cause",
          "own port scan of 192.0.2.8" in block["causes"][0], True)
    check("and forbids inventing another one",
          "do not supply a" in block["how_to_read_this"], True)

    _me.query_packets = lambda **kw: [{"src_ip": "192.0.2.7", "self_induced": False}]
    out = tr.execute_tool("query_packets", {})
    check("nothing is added when no row is ours",
          "self_induced_rows" in out["result"], False)
finally:
    _me.query_packets, _me.packet_search_scope = real_qp, real_scope
    tr._dispatch = real

loop_src2 = (ROOT / "core" / "agent_loop.py").read_text(encoding="utf-8")
check("the prompt names the block too",
      "self_induced_rows" in loop_src2, True)


print("\n[15] a behaviour value has a shape, not just a spellable key")
# The router note went into active_hours because the key was spellable and
# nothing looked at the value. A wrong key is loud. A wrong value in a right
# key is silent and gets read later as a measurement.
from core import memory_engine as me            # noqa: E402
for key, bad, why in [
    ("active_hours", "the gateway, worth watching because it defeats sensors",
     "prose in an hours key"),
    ("active_hours", "25", "an hour that does not exist"),
    ("open_ports_inbound", "the LG control channel", "prose in a ports key"),
    ("open_ports_inbound", "70000", "a port that does not exist"),
    ("typical_dest_ips", "x" * 400, "a paragraph in any key"),
]:
    try:
        me._validate_behavior_value(key, bad)
        check(f"refused {why}", "allowed", "refused")
    except me.BadInput as e:
        check(f"refused {why}", "refused", "refused")
        if key == "active_hours" and "gateway" in bad:
            check("and the refusal says where prose belongs",
                  "context" in str(e), True)

for key, good in [("active_hours", "22"), ("active_hours", "9-17"),
                  # The suite caught this one immediately: a list that was
                  # json-dumped arrives with brackets and is perfectly valid.
                  ("active_hours", "[1,2]"), ("open_ports_inbound", "[8009, 8443]"),
                  ("active_hours", "8,9,10"), ("active_hours", "22:00 UTC"),
                  ("open_ports_inbound", "8009,8443"),
                  ("typical_dest_ips", "192.0.2.29"),
                  ("user_action_history", "owner confirmed this device")]:
    try:
        me._validate_behavior_value(key, good)
        check(f"still allows {good!r} in {key}", "allowed", "allowed")
    except me.BadInput:
        check(f"still allows {good!r} in {key}", "refused", "allowed")


print("\n[16] a card has no clock on it")
# 2026-09-08, the owner's call. A card is the moment somebody goes and LOOKS: Task
# Manager, Defender, the address in another window. A stopwatch on that turns
# care into a cancelled action. So the wait ends on approve or deny and at no
# other time, with two things carried in behind it: a keepalive so a dead tab
# is noticed rather than waited on forever, and a shutdown release so Ctrl+C
# is not held up by a card nobody is at.
import asyncio                                    # noqa: E402
from core import agent_loop as al                 # noqa: E402

check("the old cap is gone from the source", "PERMISSION_TIMEOUT" in loop_src, False)
check("the wait has no timeout argument",
      "async def _wait_for_permission(call_id: str, decision: dict" in loop_src, True)
check("there is a keepalive interval", hasattr(al, "CARD_KEEPALIVE_SECONDS"), True)
check("and a way for shutdown to release a card", hasattr(al, "begin_shutdown"), True)
check("the prompt tells the model nothing expires",
      "THE CARD HAS NO CLOCK ON IT" in loop_src, True)
check("and not to hurry the person",
      "Do not hurry them" in loop_src, True)

CARD = {"call_id": "c1", "action": "Block port 445", "reason": "test"}


async def drive(call_id, card, answer_after, answer=None, shutdown=False):
    """Run the wait for real, answer it from the side, collect the keepalives."""
    decision, beats = {}, []

    async def answerer():
        await asyncio.sleep(answer_after)
        if shutdown:
            al.begin_shutdown()
        else:
            al.set_permission_decision(call_id, answer)

    task = asyncio.ensure_future(answerer())
    async for beat in al._wait_for_permission(call_id, decision, card):
        beats.append(beat)
        # The card is on a screen and waiting, so it must be findable while
        # this is going on. That is what the reload path reads.
        if len(beats) == 1:
            check("the open card is visible while it waits",
                  [c["call_id"] for c in al.open_cards()], [call_id])
    await task
    return decision, beats


al.CARD_KEEPALIVE_SECONDS = 1     # so the test is seconds, not minutes

# Waits through several keepalives and only ends when a person answers.
decision, beats = asyncio.new_event_loop().run_until_complete(
    drive("c1", CARD, answer_after=2.4, answer=True))
check("it waited rather than giving up", len(beats) >= 2, True)
check("every beat is the marker the UI throws away",
      all(al.CARD_WAITING_MARKER in b for b in beats), True)
check("and the answer is the person's", decision.get("value"), True)
check("the card is cleared once answered", al.open_cards(), [])

decision, _ = asyncio.new_event_loop().run_until_complete(
    drive("c2", dict(CARD, call_id="c2"), answer_after=0.2, answer=False))
check("deny still ends it", decision.get("value"), False)

# Shutdown is the only thing left that ends a wait without a person.
try:
    decision, _ = asyncio.new_event_loop().run_until_complete(
        drive("c3", dict(CARD, call_id="c3"), answer_after=0.2, shutdown=True))
    check("shutdown releases an open card", decision.get("value"), "expired")
    check("and does not leave it lying around", al.open_cards(), [])
finally:
    al._shutting_down = False

# The route half. Every card the pending route hands back is a lost one, and a
# click on a card nobody is waiting for must not come back as if it worked.
routes_src = (ROOT / "api" / "routes.py").read_text(encoding="utf-8")
check("the pending route reads the real register",
      "agent_loop.open_cards()" in routes_src, True)
check("approve refuses a card that is no longer open",
      routes_src.count("_card_is_open(call_id)"), 2)
check("with a status that says so, not a 200", "409" in routes_src, True)

ui_src = (ROOT / "ui" / "index.html").read_text(encoding="utf-8")
check("the UI swallows the keepalive instead of printing it",
      "__CARD_WAITING__" in ui_src, True)
check("it asks what was open after a reload", "showLostCards" in ui_src, True)
check("and a lost card gets no buttons to press",
      "lost when the page reloaded" in ui_src, True)


print("\n" + ("ALL CHECKS PASSED" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
