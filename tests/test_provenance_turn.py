"""
tests/test_provenance_turn.py — what the TURN recorded, not what the set says.

WHY THIS FILE EXISTS, 2026-09-23
A review of the agent loop found that the provenance flag travels backwards.
`agent_loop.run()` collected the name of every tool whose result came back
TRUSTED into `_untrusted_seen` and dropped every tool whose result came back
UNTRUSTED — the exact inversion of the variable's name, the comment above the
line, and what `tests/test_provenance.py` describes. So an observation derived
from fenced, attacker-controllable text was written to the database as CLEAN,
and an observation resting on this app's own measurement was written as
attacker-derived.

`test_provenance.py` could not catch it and still cannot: sections [2] and [3]
SET `_untrusted_seen` by hand and then assert what the writer does with a set
somebody else filled. That is the right test for the writer. This file is the
missing half — it drives the REAL `run()` loop and asserts the row the writer
produced, so the wiring between the loop and the database is under test and
not assumed.

THE SUBSTITUTIONS ARE NAMED ON PURPOSE. `_stream_model` is stubbed because a
model call is money and a network; `execute_tool` is stubbed for the READ and
left REAL for the WRITE, because the write is the thing being measured and a
stub of it would assert this file against itself. Everything else — run(),
the per-round bookkeeping, sanitize, the memory_engine writer — is the shipped
code path.
"""
import asyncio
import json
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


tmp = pathlib.Path(tempfile.mkdtemp())
db = tmp / "t.db"

from core import memory_engine as me                      # noqa: E402
me.DB_PATH = db
c = sqlite3.connect(db)
c.executescript((ROOT / "Schema.SQL").read_text(encoding="utf-8"))
c.commit()
c.close()
from core import migrations                               # noqa: E402
migrations.run_migrations(db)
from core import sensors as sn                            # noqa: E402
sn.register_local()
from core import agent_loop, tool_registry as tr, sanitize  # noqa: E402

SID = "turn-session"

# The real dispatcher, kept for the WRITE path. It is captured before any
# substitution so the substitution below cannot be shadowed by it.
real_execute_tool = tr.execute_tool

stream_calls = {"list": []}


def drive_turn(tool_name: str, params: dict) -> list:
    """
    Run one REAL turn: the model asks for `tool_name`, the loop executes it,
    the model answers. Returns the source list the loop recorded for the turn.

    `execute_tool` is replaced with a stub that answers the READ with the same
    envelope shape the registry produces, and hands the WRITE to the real
    dispatcher. That is the minimum substitution that still lets the row be
    real.
    """
    state = {"round": 0}

    async def fake_stream(messages, allowlist=None, usage_out=None):
        if state["round"] == 0:
            state["round"] = 1
            yield {"type": "tool_calls",
                   "calls": [{"id": "c1", "name": tool_name,
                              "params": params, "parse_error": ""}]}
        else:
            yield {"type": "text", "token": "done."}

    def fake_execute(name, call_params):
        stream_calls["list"].append(name)
        if name == tool_name and name != "write_behavioral_observation":
            return {"result": {"rows": []}, "error": None,
                    "untrusted": sanitize.is_untrusted(name)}
        return real_execute_tool(name, call_params)

    agent_loop._stream_model = fake_stream
    agent_loop.execute_tool = fake_execute
    agent_loop.requires_permission = lambda *a, **k: False
    agent_loop._history.clear()
    agent_loop._untrusted_seen.clear()

    async def drive():
        async for _tok in agent_loop.run("look at the capture"):
            pass

    asyncio.run(drive())
    return agent_loop.untrusted_sources_this_turn()


def row_for(entity_value: str):
    with sqlite3.connect(db) as conn:
        return conn.execute(
            "SELECT evidence_untrusted, evidence_sources FROM behavioral_session"
            " WHERE entity_value = ? ORDER BY id DESC", (entity_value,)).fetchone()


print("\n[1] A TURN THAT READ FENCED TEXT, and then wrote an observation")
print("    query_packets is the clearest case in the whole set: packet rows")
print("    are bytes somebody else chose, and every observation built on them")
print("    is built on that text.")
print(f"    sanitize says query_packets is untrusted: "
      f"{sanitize.is_untrusted('query_packets')}")

sources = drive_turn("query_packets", {"limit": 1})
check("the fenced read is what the turn recorded", sources, ["query_packets"])

me.write_behavioral_observation(
    entity_type="ip", entity_value="192.0.2.77",
    behavior_key="active_hours", behavior_value="[9,17]",
    session_id=SID, context="derived from captured traffic")
untrusted, named = row_for("192.0.2.77")
check("THE ROW IS MARKED UNTRUSTED", untrusted, 1)
check("and it names the tool the text came from",
      json.loads(named) if named else None, ["query_packets"])


print("\n[2] THE NEGATIVE CONTROL: a turn that read only a trusted tool")
print("    query_host_info is this app's own reading of this machine, which")
print("    is the definition of a measurement rather than attacker text. The")
print("    same turn and the same writer must leave the row CLEAN, or the")
print("    check above is asserting a constant.")
sources = drive_turn("query_host_info", {})
check("nothing untrusted was read", sources, [])

me.write_behavioral_observation(
    entity_type="ip", entity_value="192.0.2.78",
    behavior_key="active_hours", behavior_value="[8,16]",
    session_id=SID, context="from this machine's own host info")
untrusted, named = row_for("192.0.2.78")
check("the row is clean", untrusted, 0)
check("and names no source", named, None)


print("\n[3] the two rows differ, which is the whole claim")
a = row_for("192.0.2.77")
b = row_for("192.0.2.78")
check("one reading of the wire and one reading of the machine are not"
      " recorded as the same kind of evidence", a[0] == b[0], False)

print("\n" + ("ALL CHECKS PASSED" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
