"""tests/test_tool_envelope.py, item 1.8 and item 2.1."""
import sys, sqlite3, tempfile, pathlib
ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
fails = []
def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}" + ("" if ok else f"  (want {want!r})"))
    if not ok: fails.append(label)

tmp = pathlib.Path(tempfile.mkdtemp()); db = tmp / "t.db"
from core import memory_engine as me
me.DB_PATH = db
c = sqlite3.connect(db); c.executescript((ROOT/"Schema.SQL").read_text(encoding="utf-8")); c.commit(); c.close()
from core import migrations; migrations.run_migrations(db)
from core import sensors as sn; sn.register_local()
from core import tool_registry as tr
tr.set_session("s") if hasattr(tr, "set_session") else None

print("\n[1] item 1.8: an unknown tool sets the ENVELOPE error")
out = tr.execute_tool("no_such_tool_at_all", {})
check("envelope error is set", bool(out["error"]), True)
check("and names it", "Unknown tool" in out["error"], True)
check("result is None, not an error-shaped payload", out["result"], None)
print("       the old shape was {'result': {'error': ...}, 'error': None},")
print("       which every caller branching on error read as success")

print("\n[2] a tool whose module is absent is also an envelope error")
# 2026-09-05: this used to call vpn_connect, which stopped being a tool on
# 2026-09-03 when 8.3 removed it. So it was hitting the UNKNOWN TOOL path
# from section [1] again, under a heading claiming to test the absent MODULE
# path, and the check below had been failing every run since that day.
# Nobody saw it because nothing ran the tests as a set, which is what
# scripts/run_tests.py now exists for.
#
# It takes a tool that really exists and removes its module instead, which is
# the actual condition being asserted: registered, dispatchable, and the thing
# behind it did not load.
_saved = tr._modules.get("web_search")
tr._modules["web_search"] = None
try:
    out = tr.execute_tool("web_search", {"query": "anything"})
finally:
    tr._modules["web_search"] = _saved

check("envelope error set", bool(out["error"]), True)
check("named as unavailable", "unavailable" in out["error"].lower(), True)
check("and says which module", "web_search" in out["error"], True)
check("result is None here too", out["result"], None)

print("\n[3] the old return-an-error-dict shape is gone from dispatch")
src = (ROOT/"core"/"tool_registry.py").read_text(encoding="utf-8")
check("no bare Unknown tool return", 'return {"error": f"Unknown tool' in src, False)
check("no module-not-loaded returns", 'return {"error": "vpn_manager module not loaded"}' in src, False)
# 2026-09-02: this was an EXACT count of 17, and the file had 18 before today's
# work even started, so the check had been red for a while and was telling
# nobody anything. An exact count is the wrong assertion here: it goes stale
# every time a tool is added, which is a thing that happens on purpose, and a
# test that fails for the correct reason trains you to ignore it.
#
# What the section is actually asserting is that the OLD shape is gone and that
# guards raise. Both of the checks above test that directly. This one is now a
# floor, so it still catches a wholesale revert to error dicts and stops
# failing every time the manifest grows.
check("guards raise rather than return an error dict",
      src.count("raise ToolUnavailable") >= 17, True)
# And the two new enrichment guards specifically, since they were added today.
check("enqueue_enrichment guards its module",
      'if name == "enqueue_enrichment"' in src, True)
check("query_enrichment guards its module",
      'if name == "query_enrichment"' in src, True)

print("\n[4] item 2.1: the blinding ceiling counts and refuses")
b = me.blinding_budget()
check("starts empty", b["spent_by_model"], 0)
check("ceiling exposed", b["ceiling"], me.BLINDING_CEILING)
for i in range(me.BLINDING_CEILING):
    me.dismiss_entity("ip", f"192.0.2.{i+10}", reason="test", dismissed_by="model")
b = me.blinding_budget()
check("spent counts model dismissals", b["spent_by_model"], me.BLINDING_CEILING)
check("at ceiling", b["at_ceiling"], True)
check("remaining floors at zero", b["remaining"], 0)

refused = False
try:
    me.dismiss_entity("ip", "192.0.2.99", reason="one too many", dismissed_by="model")
except me.BlindingCeilingReached as e:
    refused = True
    print(f"       refused: {str(e)[:70]}...")
check("the model is refused past the ceiling", refused, True)
check("and the entity was NOT dismissed",
      me.is_dismissed("ip", "192.0.2.99"), False)

print("\n[5] a USER is never refused, it is their network")
me.dismiss_entity("ip", "192.0.2.200", reason="user says so", dismissed_by="user")
check("user dismissal succeeded", me.is_dismissed("ip", "192.0.2.200"), True)
b = me.blinding_budget()
check("counted separately", b["dismissals_user"], 1)
check("and does not raise the model's spend", b["spent_by_model"], me.BLINDING_CEILING)

print("\n[6] the ceiling is volume, not judgement, and says so")
check("note explains itself", "of" in b["note"] and "ceiling" not in b["note"].split()[0], True)
check("window is rolling hours, not a calendar day", b["window_hours"], 24)
src2 = (ROOT/"core"/"memory_engine.py").read_text(encoding="utf-8")
check("counted from the rows, not a separate counter",
      "FROM dismissed_findings" in src2, True)

print("\n" + ("ALL CHECKS PASSED" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
