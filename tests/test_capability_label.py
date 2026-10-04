"""
tests/test_capability_label.py, the interface must not claim read-only
while the manifest carries write tools.

2026-08-29. The dashboard rendered `model-q:14b - 23 tools - read-only` for
local mode. The local manifest contained four tools that write. The local
model was asked whether it could write to the database, said yes, and named
them, and was more accurate than the interface describing it.

That is the worst shape of wrong label in this project: a SECURITY claim on
screen, contradicted by a manifest three files away. A user reading
"read-only" would reasonably run the local model less carefully, which is
backwards, because write_behavioral_observation is ungated and quietly
poisoning the baseline is the patient route to blinding this tool.

The label is now derived from the manifest. This suite exists so it can never
be asserted again.

2026-09-14: local mode was removed, TODO 105, and with it the only
configuration this app could honestly call read only. The rule the incident
produced did NOT go with it. There is one manifest now, it carries write
tools, and the label has to say so. These checks are the same checks pointed
at the one manifest that is left.
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

from core import tool_registry as tr


print("\n[1] the label matches the manifest, whatever the manifest holds")
# This never asserts WHICH tools are there. It asserts the only thing that
# must stay true through any change to the manifest: the label and the
# manifest agree.
writes = tr.write_tools()
label = tr.capability_label()
check("label says read-only if and only if nothing writes",
      label == "read-only", writes == [])
check("this manifest has writers, so the label must not say read-only",
      label != "read-only", True)
check("and the label counts them rather than describing them",
      label, f"{len(writes)} write tools")
print(f"       label: {label} -> {len(writes)} tool(s)")


print("\n[2] 'read-only' is only ever returned when it is TRUE")
# The single property worth pinning, and it is checked against a FAKE empty
# manifest as well as the real one, so the true branch is exercised rather
# than assumed. If a future manifest genuinely has no write tools, the label
# may say so, and only then.
real_manifest = tr.TOOL_MANIFEST
try:
    tr.TOOL_MANIFEST = [{"name": "query_findings"}, {"name": "query_events"}]
    check("an all-read manifest may say read-only", tr.capability_label(), "read-only")
    check("and its write list is empty", tr.write_tools(), [])

    tr.TOOL_MANIFEST = [{"name": "query_findings"}, {"name": "kill_process"}]
    check("one writer is enough to lose the claim",
          tr.capability_label(), "1 write tools")
finally:
    tr.TOOL_MANIFEST = real_manifest
check("(the real manifest is back)", len(tr.TOOL_MANIFEST) > 50, True)


print("\n[3] an unclassified tool counts as a WRITE, not as harmless")
# Failing closed. Over-counting writes makes the label pessimistic;
# under-counting makes it a false safety claim, which is what happened.
check("an invented tool name is treated as a write",
      tr.tool_writes("some_tool_added_next_month"), True)
check("a query_ tool is a read", tr.tool_writes("query_packets"), False)
check("a named exception is a read", tr.tool_writes("web_search"), False)


print("\n[4] every named read-only exception really is one")
# Checked against the dispatch body, not against the name. A tool named
# list_* that quietly upserts would be exactly the drift this file guards.
import re
src = (ROOT / "core" / "tool_registry.py").read_text(encoding="utf-8")
for name in sorted(tr._READ_ONLY_EXTRA):
    m = re.search(rf'if name == "{name}":(.{{0,500}})', src, re.S)
    body = m.group(1) if m else ""
    wrote = any(w in body for w in ("save_", "upsert", "INSERT", "update_",
                                    "dismiss_", "resolve_"))
    check(f"{name} writes nothing in dispatch", wrote, False)


print("\n[5] the status payload carries the derived facts to the dashboard")
from core import agent_loop
st = agent_loop.model_status()
for key in ("write_tools", "write_tool_count", "capability_label"):
    check(f"model_status exposes {key}", key in st, True)
check("count matches the list", st["write_tool_count"], len(st["write_tools"]))


print("\n[6] the hardcoded label is gone from the interface")
ui = (ROOT / "ui" / "index.html").read_text(encoding="utf-8")
check("no literal 'tools \u00b7 read-only' template remains",
      "tools \u00b7 read-only" in ui, False)
check("the page reads the derived label instead",
      "modelState.capability_label" in ui, True)

print("\n" + ("ALL CHECKS PASSED" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
