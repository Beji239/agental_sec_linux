"""
tests/test_observation_basis.py, what KIND of thing is this baseline row.

TODO 43, schema v26. Two real rows from one afternoon forced this.

The owner is right that enrichment facts belong in the baseline: a model that
re-looks-up the same address every session is the waste the enrichment engine
exists to stop, and not logging is worse than logging. The argument was only
ever about which column, and about keeping the source and the expiry attached
so a stale fact can be spotted.

The third value came from a different row the same afternoon. The model
concluded the packet recorder had a byte-order bug and wrote that here. It is
wrong, `src` comes straight out of scapy. Unmarked, the next session reads it
as something this tool MEASURED and stops investigating.

So what is actually tested here:

  1. Three kinds stay three kinds and are never summed.
  2. NULL, from rows written before v26, is 'unrecorded' and is NEVER counted
     as measured. Same rule as the untrusted/clean/unknown split next to it.
  3. external_intel cannot be filed without a source.
  4. An expired lookup makes the row STALE, so a later session re-checks
     rather than trusting it forever.
  5. The default is model_conclusion, which is the safe direction to be wrong.

Run it directly: python tests/test_observation_basis.py
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


def check_true(label, got):
    check(label, bool(got), True)


tmp = pathlib.Path(tempfile.mkdtemp()) / "t.db"
conn = sqlite3.connect(tmp)
conn.executescript((ROOT / "Schema.SQL").read_text(encoding="utf-8"))
conn.commit()
conn.close()

from core import memory_engine as me                  # noqa: E402
me.DB_PATH = tmp

from core import enrichment as en                     # noqa: E402
en.requests.get = lambda *a, **k: (_ for _ in ()).throw(
    AssertionError("a test tried to make a real HTTP request"))
en._MIN_INTERVAL = {}

SID = "test-session"


def write(value, basis=None, ref=None, key="typical_dest_ips"):
    return me.write_behavioral_observation(
        entity_type="ip", entity_value=value, behavior_key=key,
        behavior_value="x", session_id=SID, basis=basis, basis_ref=ref)


print("\n[1] the default is model_conclusion, and it says so out loud")
# Leaving it out must not quietly produce a strong-looking row. Over-marking
# makes a row look weaker than it is; under-marking makes a guess look like a
# measurement, and this project has been bitten by the second one twice.
r = write("203.0.113.1")
check("write succeeded", r["success"], True)
check("basis defaulted", r["basis"], "model_conclusion")
check_true("and the model is told at the moment it files",
           "DEFAULT" in r["basis_note"])
check_true("with the two ways to correct it",
           "basis='measured'" in r["basis_note"]
           and "basis='external_intel'" in r["basis_note"])


print("\n[2] an external fact cannot be filed without a source")
# An external claim with no source is exactly what this column exists to
# prevent. Refused rather than accepted-and-marked, because a sourceless
# external_intel row is indistinguishable from a conclusion anyway.
r = write("203.0.113.2", basis="external_intel")
check("refused", r["success"], False)
check_true("and it says why", "basis_ref" in r["error"])
check_true("and what to pass", "enrichment:<indicator>" in r["error"])

r = write("203.0.113.2", basis="external_intel", ref="enrichment:203.0.113.2")
check("with a source it is accepted", r["success"], True)
check_true("and the note says it will expire", "STALE" in r["basis_note"])

r = write("203.0.113.3", basis="nonsense")
check("an unknown basis is refused", r["success"], False)
check_true("naming the valid ones", "model_conclusion" in r["error"])


print("\n[3] three kinds stay three kinds, and NULL is not measured")
# The rule the untrusted/clean/unknown split next to this one already follows:
# populations that mean different things are reported apart and never summed.
# A row from before v26 was never asked the question. That is not the same as
# having answered 'measured'.
with me._get_conn() as c:
    for basis, ref in (("measured", None),
                       ("measured", None),
                       ("external_intel", "enrichment:8.8.8.8"),
                       ("model_conclusion", None),
                       (None, None)):
        c.execute("""INSERT INTO behavioral_session
                     (session_id, entity_type, entity_value, behavior_key,
                      behavior_value, written_by, basis, basis_ref)
                     VALUES (?,'ip','198.51.100.5','typical_dest_ips','x',
                             'model',?,?)""", (SID, basis, ref))

prov = me.observation_provenance("ip", "198.51.100.5")
b = prov["basis"]
check("measured counted", b["counts"]["measured"], 2)
check("external counted", b["counts"]["external_intel"], 1)
check("conclusions counted", b["counts"]["model_conclusion"], 1)
check("and the pre-v26 row is 'unrecorded'", b["counts"]["unrecorded"], 1)
check_true("unrecorded is explained as NOT measured",
           "NOT the same as measured" in b["how_to_read_this"])


print("\n[4] a baseline that is mostly the model's own reasoning says so")
# The failure this whole column is for. Five conclusions and nothing else
# reads, at a glance, exactly like five confirmations.
with me._get_conn() as c:
    for _ in range(5):
        c.execute("""INSERT INTO behavioral_session
                     (session_id, entity_type, entity_value, behavior_key,
                      behavior_value, written_by, basis)
                     VALUES (?,'ip','198.51.100.6','typical_dest_ips','x',
                             'model','model_conclusion')""", (SID,))
note = me.observation_provenance("ip", "198.51.100.6")["basis"]["note"]
check_true("it names them as the model's own", "MODEL'S OWN CONCLUSIONS" in note)
check_true("says nothing outside the tool backs them",
           "Nothing outside this tool backs them" in note)
check_true("and says to treat them as a prior, not a fact",
           "not as established facts" in note)


print("\n[5] an expired lookup makes the row stale, which is the owner's call")
# The owner's reasoning, and I think it is right: an unflagged stale fact costs nothing
# right up until it is wrong, and then it is silently wrong. A flagged one
# costs one query_enrichment call, which is free while the row is fresh.
en.SOURCES_BY_KIND["ip"] = [
    ("rdap",   lambda i: ({"organisation": "Example Org"}, "https://x.test", None)),
    ("ip_api", lambda i: ({"organisation": "Example Org Inc"}, "https://y.test", None)),
]
en.store(en.research("8.8.8.8"))
check("the lookup is fresh", en.read("8.8.8.8")["stale"], False)
check("so the observation is not stale",
      me._enrichment_is_stale("enrichment:8.8.8.8"), False)

# Push it past its expiry the way time would.
with me._get_conn() as c:
    c.execute("UPDATE enrichment SET expires_at='2020-01-01T00:00:00+00:00' "
              "WHERE indicator='8.8.8.8'")
check("now the lookup is stale", en.read("8.8.8.8")["stale"], True)
check("and so is the observation resting on it",
      me._enrichment_is_stale("enrichment:8.8.8.8"), True)

prov = me.observation_provenance("ip", "198.51.100.5")["basis"]
check("the stale ref is named", prov["stale_external_refs"], ["enrichment:8.8.8.8"])
check_true("and the note says to re-run the lookup",
           "enqueue_enrichment" in prov["note"])

# A citation whose lookup has been pruned entirely is the LEAST verifiable
# state there is: the claim is still here and the thing it rested on is gone.
check("a missing lookup counts as stale",
      me._enrichment_is_stale("enrichment:192.0.2.99"), True)
check("a non-enrichment ref is simply unknowable",
      me._enrichment_is_stale("some-other-source"), None)


print("\n[6] the tool passes it through, and the manifest asks for it")
from core import tool_registry as tr                  # noqa: E402
schema = next(t for t in tr.TOOL_MANIFEST
              if t["name"] == "write_behavioral_observation")
props = schema["input_schema"]["properties"]
check_true("basis is offered", "basis" in props)
# FOUR SINCE v32, 2026-09-14. operator_stated is what the owner said when the
# model asked the owner something it could not work out itself. Checked as an exact
# SET rather than a count, so a fifth value has to be added here deliberately
# rather than slipping in.
check_true("with the four values",
           set(props["basis"]["enum"]) == {"measured", "external_intel",
                                           "model_conclusion",
                                           "operator_stated"})
# And the manifest must not drift from the engine's own set. The manifest is
# what the model reads; VALID_OBSERVATION_BASIS is what actually refuses. A
# value in one and not the other is either a tool that offers something the
# engine rejects, or an engine that silently accepts something undocumented.
check_true("the manifest matches the engine's own set",
           set(props["basis"]["enum"]) == me.VALID_OBSERVATION_BASIS)
check_true("basis_ref is offered", "basis_ref" in props)
# Not required, deliberately: a missing basis defaults to the weak value
# rather than failing the write. A tool that refuses the ordinary call is a
# tool the model stops calling.
check("basis is not required",
      "basis" in schema["input_schema"]["required"], False)
check_true("and the description tells the model to write lookups down",
           "not pay to look the same thing up again" in schema["description"])


print("\n" + ("ALL PASS" if not fails else f"{len(fails)} FAILED: {fails}"))
sys.exit(1 if fails else 0)
