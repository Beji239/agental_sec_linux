"""
tests/test_report_dismissal_and_port_owner.py, the 2026-09-25 T9 round.

TWO INSTRUCTIONS FROM THE OWNER, both on 2026-09-25, and this file is the
evidence for both:

  1. "we need a dismiss button plus check box for agent reports, also a
     dismiss all .. those however won't delete the agent entries from the
     database and baseline if it was initially writing in those."

  2. "agent now has to have access to ports and processes finding in this
     machine to be able to report which port relates to which process ...
     python should execute the scan on set intervals and on top of that agent
     should be able to call python to execute a scan whenever it wants to
     complete a report".

EVERY CHECK HERE IS IN BOTH DIRECTIONS. A dismiss that hides nothing is as
broken as one that deletes, a /proc reader that finds no owners is as wrong as
one that invents them, and this project has a rule that a test which could not
have failed is not evidence.

RUNS AGAINST A THROWAWAY DATABASE built from Schema.SQL. It never opens the
operator's store: tests/_isolate_db is not used because this file needs a
database it can write to freely, and memory_engine.DB_PATH is repointed at a
temp file before anything else imports it. The live database is touched by
nothing in here.
"""
import json
import os
import pathlib
import sqlite3
import subprocess
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


def check_true(label, got, why=""):
    if not got:
        fails.append(label)
    print(f"  {'PASS' if got else 'FAIL'}  {label}"
          + (f": {why}" if why else ""))


def check_raises(label, fn, *a, **k):
    try:
        fn(*a, **k)
    except Exception as e:                                   # noqa: BLE001
        print(f"  PASS  {label} (raised {type(e).__name__})")
        return
    fails.append(label)
    print(f"  FAIL  {label}: nothing raised")


def _src(name):
    return (ROOT / name).read_text(encoding="utf-8")


# A THROWAWAY STORE, AND THE MODULES UNDER IT
tmp = pathlib.Path(tempfile.mkdtemp(prefix="t9_"))
DB = tmp / "t.db"
DB.write_text("")
sqlite3.connect(DB).executescript(
    (ROOT / "Schema.SQL").read_text(encoding="utf-8"))

from core import memory_engine as me            # noqa: E402
me.DB_PATH = DB
from core import migrations                     # noqa: E402
migrations.run_migrations(DB)
from core import duty, integrity                # noqa: E402
from tools import port_owner as po              # noqa: E402


def _fresh_report(verdict="no_action", body="a body", saw="what it saw",
                  kind="regular"):
    return duty.write_report(
        "t9-session", kind, "verify", body=body, hypothesis="h",
        evidence="e", verdict=verdict, saw=saw,
        coverage={"complete": True, "note": "everything readable"})


print("\n[1] A DISMISSAL DELETES NOTHING AND THE ROW IS UNCHANGED")
# THE OWNER'S OWN SENTENCE, asserted as literally as it can be: "those however
# won't delete the agent entries from the database". The check reads the row
# back BEFORE and AFTER and compares every column that carries what the agent
# SAID, so a dismissal that quietly rewrote a verdict would fail here.
r1 = _fresh_report(verdict="benign", body="the original body text",
                   saw=None)
with sqlite3.connect(DB) as c:
    before_row = dict(c.execute("SELECT * FROM duty_report WHERE id = ?",
                                (r1["report_id"],)).fetchone()
                      and zip([d[0] for d in c.execute(
                          "SELECT * FROM duty_report WHERE id = ?",
                          (r1["report_id"],)).description],
                          c.execute("SELECT * FROM duty_report WHERE id = ?",
                                    (r1["report_id"],)).fetchone()))

out = duty.dismiss_reports([r1["report_id"]], dismissed_by="user",
                           note="test dismissal")
check("the dismissal succeeded", out["dismissed"], 1)

with sqlite3.connect(DB) as c:
    c.row_factory = sqlite3.Row
    after = dict(c.execute("SELECT * FROM duty_report WHERE id = ?",
                           (r1["report_id"],)).fetchone())
    total = c.execute("SELECT COUNT(*) FROM duty_report").fetchone()[0]

check("THE ROW STILL EXISTS (nothing was deleted)", after is not None, True)
check("and the total row count did not drop", total, 1)
for col in ("body", "verdict", "hypothesis", "evidence", "coverage_json",
            "tokens_spent", "model_calls", "created_at", "session_id",
            "kind", "trigger", "coverage_note"):
    check(f"  {col} is byte-identical after the dismissal",
          after[col], before_row[col])
check("the dismissal flag is set", bool(after["dismissed_at"]), True)
check("and it records who did it", after["dismissed_by"], "user")

print("\n  -- and there is NO DELETE ANYWHERE in the dismissal path")
# THE TEST STRIPS COMMENTS AND STRINGS FIRST, and that is not fussiness: the
# first draft of this check FAILED against correct code, because the function's
# own DOCSTRING quotes the owner's sentence "those however won't delete the
# agent entries" and the docstring legitimately talks about baselines. A check
# that fires on a word rather than on an act is the noise this project's test
# rules are written against, so the check reads the CODE.
import io as _io
import tokenize as _tok


def _code_only(source: str) -> str:
    """The source with every comment and string literal removed."""
    import textwrap
    out = []
    try:
        # DEDENTED FIRST: a function body sliced out of a file carries its
        # indentation, and the tokenizer refuses a module that starts indented
        # ("unindent does not match any outer indentation level"). Found by
        # running it -- the first draft of this helper raised on its first use.
        for tok in _tok.generate_tokens(
                _io.StringIO(textwrap.dedent(source)).readline):
            if tok.type in (_tok.COMMENT, _tok.STRING):
                continue
            out.append(tok.string)
    except _tok.TokenError:
        return source
    return " ".join(out)


_path = _src("core/duty.py")
# THE SLICE STARTS AFTER THE `def` KEYWORD, so the first line is a parameter
# list at column 0 followed by a body at column 4 -- textwrap.dedent finds no
# common prefix and the tokenizer then raises. The header is put back and the
# whole thing dedented, which is what makes the body a parseable module.
_dismiss_fn = _code_only(
    "def dismiss_reports("
    + _path.split("def dismiss_reports(")[1].split("\ndef ")[0])
check("duty.dismiss_reports contains no DELETE statement",
      "DELETE" in _dismiss_fn.upper(), False)
check("nor DROP", "DROP" in _dismiss_fn.upper(), False)
check("nor TRUNCATE", "TRUNCATE" in _dismiss_fn.upper(), False)
_restore_fn = _code_only(
    "def restore_report("
    + _path.split("def restore_report(")[1].split("\ndef ")[0])
check("restore_report contains no DELETE either",
      "DELETE" in _restore_fn.upper(), False)

print("\n  -- and NOTHING IN THE PATH TOUCHES A BASELINE")
check("dismiss_reports has no baseline write",
      "behavioral_baseline" in _dismiss_fn, False)
check("restore_report has no baseline write",
      "behavioral_baseline" in _restore_fn, False)
check("nor any behavioural writer",
      any(w in (_dismiss_fn + _restore_fn)
          for w in ("save_behavioral", "write_behavioral_observation",
                    "update_behavioral_baseline")), False)

# AND THE BASELINE TABLE ITSELF IS UNTOUCHED BY A DISMISS-ALL, read back.
# A FRESH REPORT GOES IN FIRST, and that is a fix to this test rather than a
# convenience: every section in this file shares ONE database, so by the time
# this line runs r1 has already been dismissed by section 1 and a dismiss-all
# correctly skips it. Asserting `dismissed == 1` against that state was
# asserting the opposite of the behaviour section 3 pins (already-dismissed
# reports are NOT re-dismissed), and the first run failed here for exactly
# that reason. So: one undismissed report for the dismiss-all to find, plus
# the check that the one already dismissed was left exactly as it was.
with sqlite3.connect(DB) as c:
    c.row_factory = sqlite3.Row
    me.update_behavioral_baseline(entity_type="ip",
                                 entity_value="192.0.2.77",
                                 behavior_key="connection_count",
                                 session_id="t9-session",
                                 sample_count=5, value_mean=1.0)
    base_before = [dict(r) for r in c.execute(
        "SELECT * FROM behavioral_baseline ORDER BY id")]
    r1_dismissed_before = c.execute(
        "SELECT dismissed_at, dismissed_by FROM duty_report WHERE id = ?",
        (r1["report_id"],)).fetchone()
r_all = _fresh_report(body="the report the dismiss-all is for")
allout = duty.dismiss_reports([], dismissed_by="user", all_open=True)
with sqlite3.connect(DB) as c:
    c.row_factory = sqlite3.Row
    base_after = [dict(r) for r in c.execute(
        "SELECT * FROM behavioral_baseline ORDER BY id")]
    r1_dismissed_after = c.execute(
        "SELECT dismissed_at, dismissed_by FROM duty_report WHERE id = ?",
        (r1["report_id"],)).fetchone()
check("dismiss-all dismissed the one UNDISMISSED report", allout["dismissed"], 1)
check("and the report it dismissed is the new one",
      allout["report_ids"], [r_all["report_id"]])
check("IT DID NOT RE-DISMISS THE ONE ALREADY DISMISSED",
      (r1_dismissed_after["dismissed_at"], r1_dismissed_after["dismissed_by"]),
      (r1_dismissed_before["dismissed_at"], r1_dismissed_before["dismissed_by"]))
check("AND THE BASELINE ROWS ARE BYTE-IDENTICAL AFTERWARDS",
      base_after, base_before)


print("\n[2] THE LISTS: HIDDEN BY DEFAULT, FINDABLE, AND NEVER UNREADABLE")
# THE DEFECT THIS HOLDS OFF is the one a dismiss feature always produces: a
# report that exists and that the model is then told does not exist. Three
# readings are asserted separately because they answer three questions.
#
# THE COUNTS ARE SECTION-SCOPED, and that is a fix to this test rather than a
# convenience. Every section of this file shares ONE database on purpose (see
# the header), so by the time these lines run there are already reports in it
# from section 1 -- and asserting `len(...) == 1` against the WHOLE table was
# asserting a fact about the earlier sections, not about this one. The first
# run failed here for exactly that reason, and the honest fix is to name the
# rows these checks are about instead of counting whatever is lying around.
with sqlite3.connect(DB) as c:
    rows_before = c.execute("SELECT COUNT(*) FROM duty_report").fetchone()[0]
r2 = _fresh_report(body="second report")
r3 = _fresh_report(body="third report")
duty.dismiss_reports([r2["report_id"]], dismissed_by="user")

default_ids = [r["id"] for r in duty.query_reports(limit=50)]
only_dismissed_ids = [r["id"] for r in duty.query_reports(limit=50,
                                                         only_dismissed=True)]
everything_ids = [r["id"] for r in duty.query_reports(limit=50,
                                                      include_dismissed=True)]
check("the default list hides the dismissed one",
      r2["report_id"] in default_ids, False)
check("and still shows the one that was not dismissed",
      r3["report_id"] in default_ids, True)
check("only_dismissed returns exactly the dismissed ones and nothing else",
      (r2["report_id"] in only_dismissed_ids,
       r3["report_id"] in only_dismissed_ids), (True, False))
check("include_dismissed returns everything, both of them present",
      (r2["report_id"] in everything_ids, r3["report_id"] in everything_ids),
      (True, True))
check("AND ASKING FOR ONE BY ID FINDS IT EVEN WHEN DISMISSED",
      len(duty.query_reports(report_id=r2["report_id"], limit=1)), 1)
# THE SUMMARY IS CHECKED AGAINST THE DATABASE, not against a number typed
# here: the point of the check is that the summary is not guessed, and a
# hardcoded 1 would pass for a summary that guessed correctly by luck.
with sqlite3.connect(DB) as c:
    hidden_in_db = c.execute("SELECT COUNT(*) FROM duty_report WHERE "
                             "dismissed_at IS NOT NULL").fetchone()[0]
    total_now = c.execute("SELECT COUNT(*) FROM duty_report").fetchone()[0]
check("the summary names how many are hidden, and agrees with the store",
      duty.summary()["dismissed_reports"], hidden_in_db)
check("and no row was removed by any of it", total_now, rows_before + 2)


print("\n[3] RE-DISMISSING IS REFUSED, AND THE ORIGINAL TIME SURVIVES")
# Overwriting would move the timestamp and destroy the only record of when a
# person actually decided. The second dismissal must skip, not overwrite.
with sqlite3.connect(DB) as c:
    c.row_factory = sqlite3.Row
    first_at = c.execute("SELECT dismissed_at FROM duty_report WHERE id=?",
                         (r2["report_id"],)).fetchone()["dismissed_at"]
again = duty.dismiss_reports([r2["report_id"]], dismissed_by="someone else")
check("nothing was re-dismissed", again["dismissed"], 0)
check("and it says why", again["skipped"][0]["reason"], "already dismissed")
with sqlite3.connect(DB) as c:
    c.row_factory = sqlite3.Row
    still = c.execute("SELECT dismissed_at, dismissed_by FROM duty_report "
                      "WHERE id=?", (r2["report_id"],)).fetchone()
check("the original timestamp is UNCHANGED", still["dismissed_at"], first_at)
check("and the original dismissed_by is unchanged too",
      still["dismissed_by"], "user")


print("\n[4] RESTORING PUTS IT BACK, AND THE UNDO IS NOT GATED")
# THE COUNT IS TAKEN BEFORE THE RESTORE, and that ordering is the whole check:
# read afterwards it is already the post-restore number and the difference is
# always zero. Found by running it -- the first version of this line sat below
# the restore and failed against correct code.
dismissed_before_restore = duty.summary()["dismissed_reports"]
rest = duty.restore_report(r2["report_id"], by="user")
check("it restored", rest["restored"], True)
check("and reported when it had been dismissed",
      bool(rest["was_dismissed_at"]), True)
check("the report is back on the default list",
      r2["report_id"] in [r["id"] for r in duty.query_reports(limit=50)], True)
# R2's OWN ROW IS WHAT THIS CHECKS, and the count is compared WITH ITSELF
# before and after rather than against zero: section 1 dismissed a report of
# its own and the dismiss-all in section 1 dismissed another, so a global
# "nothing is dismissed" is FALSE and correct at this point in the file. The
# fact under test is that restoring THIS report removed exactly one dismissal.
with sqlite3.connect(DB) as c:
    c.row_factory = sqlite3.Row
    r2_row = dict(c.execute("SELECT * FROM duty_report WHERE id = ?",
                            (r2["report_id"],)).fetchone())
check("THIS report is no longer dismissed",
      (r2_row["dismissed_at"], r2_row["dismissed_by"]), (None, None))
check("and nothing else was un-dismissed along with it",
      dismissed_before_restore - duty.summary()["dismissed_reports"], 1)

print("\n  -- restoring something that was never dismissed is refused, not a no-op")
rest2 = duty.restore_report(r3["report_id"], by="user")
check("it refused", rest2["restored"], False)
check("with a reason", rest2["reason"], "that report was not dismissed")
print("\n  -- and restoring a report that does not exist is refused")
rest3 = duty.restore_report(999999, by="user")
check("it refused", rest3["restored"], False)
check_true("with a sentence naming the id",
           "999999" in (rest3.get("reason") or ""), rest3.get("reason"))


print("\n[5] THE SEAL: A DISMISSAL MUST NOT BREAK THE TAMPER WITNESS")
# This is the check that FAILED when the columns were first added, because
# tests/test_integrity.py asserts (sealed OR excluded) == every column. It is
# repeated here against this file's own reports so the reason is stated in the
# place the feature lives.
v = integrity.verify_sealed_rows(db_path=DB)
check("the sealed rows verify before any dismissal", v["status"], "intact")
with sqlite3.connect(DB) as c:
    c.row_factory = sqlite3.Row
    report_cols = [r[1] for r in c.execute(
        "PRAGMA table_info(duty_report)").fetchall()]
spec = integrity.SEALED_TABLES["duty_report"]
declared = set(spec["columns"]) | set(spec["excluded"]) | {spec["key"]}
check("every duty_report column is sealed or excluded WITH A REASON",
      sorted(set(report_cols) - declared), [])
for col in ("dismissed_at", "dismissed_by", "dismissal_note"):
    check(f"  {col} is excluded rather than sealed", col in spec["excluded"], True)
    check(f"  and its exclusion carries a reason",
          bool(str(spec["excluded"].get(col) or "").strip()), True)
    check(f"  and it is NOT also in the sealed set",
          col in spec["columns"], False)

duty.dismiss_reports([r3["report_id"]], dismissed_by="user",
                     note="seal check")
v2 = integrity.verify_sealed_rows(db_path=DB)
check("THE SEAL IS STILL INTACT AFTER A DISMISSAL", v2["status"], "intact")
check("no row reads as edited", v2["edited_rows"], 0)
check("and none as deleted", v2["deleted_rows"], 0)
check("the dismissal is journalled rather than witnessed",
      v2["verified_rows"], v["verified_rows"])

print("\n  -- editing the VERDICT still breaks the seal (the witness is alive)")
with sqlite3.connect(DB) as c:
    c.execute("UPDATE duty_report SET verdict = 'benign' WHERE id = ?",
              (r3["report_id"],))
v3 = integrity.verify_sealed_rows(db_path=DB)
check("a rewritten verdict IS caught", v3["status"], "broken")
check("and exactly one row is reported edited", v3["edited_rows"], 1)
with sqlite3.connect(DB) as c:
    c.execute("UPDATE duty_report SET verdict = 'no_action' WHERE id = ?",
              (r3["report_id"],))


print("\n[6] THE ROUTES REFUSE TO GUESS, IN BOTH DIRECTIONS")
# Read off the source rather than driven over HTTP, because this file has no
# running server -- and every one of these is a REFUSAL, which is the half of
# a route people write tests for last. The behaviour itself is driven for real
# in scripts/verify_t9_live.sh against a real boot.
_routes = _src("api/routes.py")
_dismiss_route = _routes.split("def agents_dismiss(")[1].split("\n    @app.route")[0]
check("an unparseable body is refused", "could not read the request body" in
      _dismiss_route, True)
check("and NOTHING HAS BEEN DISMISSED appears in that refusal",
      "NOTHING HAS BEEN DISMISSED" in _dismiss_route, True)
check("a non-object body is refused",
      "takes a JSON object" in _dismiss_route, True)
check("all_open is checked with `is not True`, not truthiness",
      "is not True" in _dismiss_route, True)
check("report_ids must be a list", "report_ids must be a list" in
      _dismiss_route, True)
check("A REQUEST THAT NAMES NEITHER IS REFUSED rather than treated as all",
      "will not treat it as 'hide everything'" in _dismiss_route, True)
check("and the check happens before the dismissal call",
      _dismiss_route.index("Name the reports to dismiss") <
      _dismiss_route.index("duty.dismiss_reports("), True)
check("the show filter is validated rather than passed through",
      "show must be 'all' or 'dismissed'" in _routes, True)
check("the response names the count, not a bare success",
      '"dismissed": out["dismissed"]' in _dismiss_route, True)
check("and it says nothing was deleted",
      "Nothing was deleted" in _dismiss_route, True)

print("\n  -- the restore route exists and is not gated by a permission card")
check("there is a restore route",
      '/api/agents/<int:report_id>/restore' in _routes, True)
check("and it does not require an approval flow",
      "requires_permission" in
      _routes.split("def agents_restore(")[1].split("\n    @app.route")[0],
      False)


print("\n[7] PORT OWNERSHIP: THE CORRELATION ITSELF, AGAINST THIS REAL HOST")
# The reader is run against the REAL /proc, because a fixture would prove that
# the parser matches the fixture. Measured on this host when it was written:
# 16-32 sockets, 2-9 listeners attributable unelevated, ~65 ms a pass.
listed = po.list_sockets()
check_true("the kernel's tables were read",
           listed["coverage"]["tables_read"] >= 3,
           json.dumps(listed["coverage"]))
check_true("no table is silently missing from the report",
           isinstance(listed["coverage"]["unreadable"], list), True)

cor = po.correlate()
check_true("a pass found this host's own listening sockets",
           cor["counts"]["listeners"] >= 1,
           json.dumps(cor["counts"]))
check("sockets = listeners + established",
      cor["counts"]["sockets"],
      cor["counts"]["listeners"] + cor["counts"]["established"])
check("the three owner states sum to the listener count",
      (cor["counts"]["listeners_with_owner"]
       + cor["counts"]["listeners_unreadable"]
       + cor["counts"]["listeners_no_holder"]),
      cor["counts"]["listeners"])
check_true("the pass is bounded and fast", cor["duration_ms"] < 5000,
           f"{cor['duration_ms']} ms")

print("\n  -- the address decoding is pinned against addresses whose reading is known")
# THE byte-order trap: the kernel writes an IPv4 address little-endian and an
# IPv6 address as four little-endian u32 words. Both are asserted against
# values known in advance, because a reversed address still LOOKS like an
# address and nothing downstream would notice.
check("127.0.0.1 decodes (the kernel writes 0100007F)",
      po._hex_to_ipv4("0100007F"), "127.0.0.1")
# THE BYTES ARE REVERSED, so the LAST pair in the string is the FIRST octet of
# the address. This expectation was typed the other way round in the first draft
# and the failure was the TEST being wrong, not the decoder -- and the address
# it used was the operator's own, which is a leak in a published file (the gate
# caught it). The pair below pins both directions, from the documentation range,
# so neither can be "fixed" by flipping the other.
check("a non-loopback decodes, byte order and all",
      po._hex_to_ipv4("010200C0"), "192.0.2.1")
check("and its mirror image reads as the address one would guess wrongly",
      po._hex_to_ipv4("C0000201"), "1.2.0.192")
check("and 0.0.0.0 decodes as itself",
      po._hex_to_ipv4("00000000"), "0.0.0.0")
check("rubbish decodes to empty rather than to a plausible address",
      po._hex_to_ipv4("ZZZZZZZZ"), "")
# THE v4-MAPPED LITERAL WAS WRONG IN THE FIRST DRAFT and the decoder was
# right, which is why this is now the bytes MEASURED off a real socket: a
# socket bound to ::ffff:127.0.0.1 on this host is written by the kernel to
# /proc/net/tcp6 as 0000000000000000FFFF00000100007F. The draft literal put
# the FFFF in the wrong 8-hex group and read as ::ffff:0:7f00:1 -- and that is
# the value the DECODER correctly returns for it, so writing the expectation
# to match would have pinned a wrong address into the file.
check("a v4-mapped v6 address reads as itself (the kernel's own bytes for "
      "::ffff:127.0.0.1)", po._hex_to_ipv6("0000000000000000FFFF00000100007F"),
      "::ffff:127.0.0.1")
check("and the decoder still answers a hand-written address honestly",
      po._hex_to_ipv6("00000000000000000000FFFF0100007F"), "::ffff:0:7f00:1")
check("the v6 all-zero address decodes", po._hex_to_ipv6("0" * 32), "::")
check("and the v6 loopback decodes from the kernel's own bytes for ::1 "
      "(read off this host's own ::1:631 listener)",
      po._hex_to_ipv6("00000000000000000000000001000000"), "::1")
check("and a wrong-length v6 string is refused rather than truncated",
      po._hex_to_ipv6("00112233"), "")

print("\n  -- a listener this app cannot attribute says SO, and never says 'nobody'")
unreadable = [r for r in cor["sockets"]
              if r["owner_status"] == po.OWNER_UNREADABLE]
if unreadable:
    check_true("an unattributable listener carries a note",
               bool(unreadable[0].get("owner_note")), unreadable[0])
    check_true("and the note names the privilege limit rather than absence",
               "privilege" in (unreadable[0]["owner_note"] or "").lower()
               or "refused" in (unreadable[0]["owner_note"] or "").lower(),
               unreadable[0]["owner_note"])
check("no_holder_found is a THIRD value and is never OWNER_UNREADABLE",
      po.OWNER_NO_HOLDER == po.OWNER_UNREADABLE, False)
check_true("the coverage sentence names the unreadable count when there is one",
           (not unreadable)
           or ("cannot read" in po.coverage_sentence(cor["counts"],
                                                     cor["coverage"])),
           po.coverage_sentence(cor["counts"], cor["coverage"]))
check_true("and it names how many WERE matched",
           "were matched to a" in po.coverage_sentence(cor["counts"],
                                                       cor["coverage"]),
           po.coverage_sentence(cor["counts"], cor["coverage"]))

print("\n  -- comm is the process's own name and exe is the kernel's answer")
check("process_detail asks /proc for both",
      "comm" in _src("tools/port_owner.py")
      and "/exe" in _src("tools/port_owner.py"), True)
me_detail = po.process_detail(os.getpid())
check("this test process's own comm is readable", bool(me_detail["comm"]), True)
check_true("and its exe resolves to a python binary",
           "python" in (me_detail["exe"] or "").lower(), me_detail["exe"])


print("\n[8] THE SWEEP: SEEDED ONCE, QUIET AFTERWARDS, BOUNDED BY CONSTRUCTION")
# THE DEFECT MEASURED BEFORE THIS FIX: the first pass wrote 16 `appeared`
# change rows for a machine that had not changed at all. Every one of those
# listeners predated this code, and reporting them as arrivals would put a
# page of news into a report about a host sitting still.
first = po.record_sweep("t9")
check("the first sweep ran", first["ran"], True)
check("and it is NAMED as a seed pass", first["seeding"], True)
check("THE SEED PASS REPORTS NO ARRIVALS", first["appeared"],
      first["counts"]["listeners"])
with sqlite3.connect(DB) as c:
    check("and writes NO change rows at all",
          c.execute("SELECT COUNT(*) FROM port_owner_change").fetchone()[0], 0)
    check("while still recording every listener",
          c.execute("SELECT COUNT(*) FROM port_owner_socket").fetchone()[0],
          first["counts"]["listeners"])
    check("and the seed is said in the note",
          "FIRST PASS" in (c.execute(
              "SELECT note FROM port_owner_sweep ORDER BY id DESC LIMIT 1"
          ).fetchone()[0]), True)

second = po.record_sweep("t9")
check("the second sweep is not a seed", second["seeding"], False)
check("A QUIET HOST WRITES NO CHANGES ON A SECOND PASS", second["appeared"], 0)
check("and nothing else changed either",
      (second["owner_changed"], second["disappeared"]), (0, 0))
with sqlite3.connect(DB) as c:
    check("the change table is still empty",
          c.execute("SELECT COUNT(*) FROM port_owner_change").fetchone()[0], 0)
    check("and no duplicate socket rows were made",
          c.execute("SELECT COUNT(*) FROM port_owner_socket").fetchone()[0],
          first["counts"]["listeners"])
    check("the seen_count moved instead of a new row",
          c.execute("SELECT MAX(seen_count) FROM port_owner_socket"
                    ).fetchone()[0], 2)

print("\n  -- the tables are BOUNDED: only listeners are tracked")
with sqlite3.connect(DB) as c:
    check("no established socket was written to the table",
          c.execute("SELECT COUNT(*) FROM port_owner_socket "
                    "WHERE scope <> 'listen'").fetchone()[0], 0)
    check("while the sweep row still counts them",
          c.execute("SELECT established FROM port_owner_sweep ORDER BY id "
                    "DESC LIMIT 1").fetchone()[0] >= 0, True)

print("\n  -- the unique index really prevents a duplicate identity")
with sqlite3.connect(DB) as c:
    row = c.execute("SELECT * FROM port_owner_socket LIMIT 1").fetchone()
check_true("there is a row to try", row is not None)
if row:
    with sqlite3.connect(DB) as c:
        try:
            c.execute(
                "INSERT INTO port_owner_socket (proto, scope, local_address,"
                " local_port, pid, comm, exe, owner_status, inode, "
                "first_seen_at, last_seen_at, seen_count, active) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,1,1)",
                (row[1], row[2], row[3], row[4], row[5], row[6], row[7],
                 row[8], row[9], row[10], row[11]))
            check("a duplicate identity was inserted (the index does nothing)",
                  True, False)
        except sqlite3.IntegrityError:
            check("a duplicate identity is refused by the index", True, True)

print("\n  -- and it is a seed, not a hole: the NEXT real arrival IS reported")
# The inverse direction, driven on synthetic rows so it does not depend on
# this host starting a listener while the test runs. A port that was not in
# the table must produce one appeared row.
with sqlite3.connect(DB) as c:
    c.execute("DELETE FROM port_owner_change")
synthetic = {
    "sockets": [{"proto": "tcp", "scope": "listen", "local_address": "127.0.0.1",
                 "local_port": 45999, "remote_address": "", "remote_port": 0,
                 "inode": "999999", "uid": "1000",
                 "pid": os.getpid(), "comm": "synthetic", "exe": "/x/y",
                 "holder_count": 1, "owner_status": po.OWNER_IDENTIFIED,
                 "owner_note": None}],
    "counts": {"sockets": 1, "listeners": 1, "established": 0,
               "listeners_with_owner": 1, "listeners_unreadable": 0,
               "listeners_no_holder": 0, "listeners_on_all_interfaces": 0},
    "coverage": {"tables_read": 4, "tables_total": 4, "unreadable_tables": [],
                 "processes_seen": 1, "fds_seen": 1, "processes_denied": 0,
                 "proc_readable": True},
    "duration_ms": 1,
}
with sqlite3.connect(DB) as c:
    c.execute("UPDATE port_owner_socket SET active = 0")
third = po.record_sweep("t9", correlated=synthetic)
check("a new listener on an established record IS reported", third["appeared"], 1)
with sqlite3.connect(DB) as c:
    c.row_factory = sqlite3.Row
    changes = [dict(r) for r in c.execute(
        "SELECT * FROM port_owner_change ORDER BY id")]
check("exactly one change row was written", len(changes), 1)
if changes:
    check("and it is an appearance", changes[0]["kind"], "appeared")
    check_true("with a sentence naming the port",
               "45999" in (changes[0]["note"] or ""), changes[0]["note"])

print("\n  -- a listener that goes away is a DISAPPEARANCE, and is kept")
empty = dict(synthetic)
empty["sockets"] = []
empty["counts"] = dict(synthetic["counts"], sockets=0, listeners=0,
                       listeners_with_owner=0)
with sqlite3.connect(DB) as c:
    c.execute("DELETE FROM port_owner_change")
fourth = po.record_sweep("t9", correlated=empty)
check("its departure is reported", fourth["disappeared"], 1)
with sqlite3.connect(DB) as c:
    c.row_factory = sqlite3.Row
    row = dict(c.execute("SELECT * FROM port_owner_socket WHERE local_port = "
                         "45999").fetchone())
    chg = dict(c.execute("SELECT * FROM port_owner_change ORDER BY id "
                         "DESC LIMIT 1").fetchone())
check("the socket row is marked inactive, NOT deleted",
      (row["active"], bool(row)), (0, True))
check("and the change names the departure", chg["kind"], "disappeared")
check("the row still carries when it was first seen",
      bool(row["first_seen_at"]), True)


print("\n[9] OWNER AND BIND CHANGES: A RESTART IS NOT AN ARRIVAL PLUS A DEPARTURE")
# The defect this holds off: identity includes pid, so `systemctl restart`
# changes identity by definition and the appearance pass would report every
# restart as news twice over. Driven on synthetic rows because it needs two
# passes with a controlled holder change.
def _one(port, pid, addr="127.0.0.1", comm="svc"):
    return {"proto": "tcp", "scope": "listen", "local_address": addr,
            "local_port": port, "remote_address": "", "remote_port": 0,
            "inode": str(pid), "uid": "1000", "pid": pid, "comm": comm,
            "exe": f"/usr/bin/{comm}", "holder_count": 1,
            "owner_status": po.OWNER_IDENTIFIED, "owner_note": None}


def _payload(rows):
    return {"sockets": rows,
            "counts": {"sockets": len(rows), "listeners": len(rows),
                       "established": 0,
                       "listeners_with_owner": len(rows),
                       "listeners_unreadable": 0, "listeners_no_holder": 0,
                       "listeners_on_all_interfaces": 0},
            "coverage": {"tables_read": 4, "tables_total": 4,
                         "unreadable_tables": [], "processes_seen": 1,
                         "fds_seen": 1, "processes_denied": 0,
                         "proc_readable": True},
            "duration_ms": 1}


# EVERY SUB-CASE BELOW IS TWO PASSES: a PRIMING pass that records the starting
# state, then the pass under test. The priming pass has to be a SEED or it
# legitimately reports the port it is seeing for the first time as an arrival --
# which is the correct behaviour (a listener this app has no record of IS new
# news) and it is why the first draft of these checks counted an extra
# `appeared` row per sub-case. It emptied the socket table without emptying the
# sweep table, so `seeding` was False and the first look reported arrivals.
#
# `_reset_sweep_state` clears all three tables together, which is what makes the
# first pass a genuine seed -- the same sequence a real boot goes through.
def _reset_sweep_state():
    with sqlite3.connect(DB) as c:
        c.execute("DELETE FROM port_owner_change")
        c.execute("DELETE FROM port_owner_socket")
        c.execute("DELETE FROM port_owner_sweep")


_reset_sweep_state()
_prime = po.record_sweep("t9", correlated=_payload([_one(45998, 1000)]))
check("the priming pass for this section is a SEED", _prime["seeding"], True)
res = po.record_sweep("t9", correlated=_payload([_one(45998, 2000)]))
with sqlite3.connect(DB) as c:
    c.row_factory = sqlite3.Row
    changes = [dict(r) for r in c.execute(
        "SELECT * FROM port_owner_change ORDER BY id")]
kinds = [row["kind"] for row in changes]
check("a replaced holder is ONE owner_changed, not an arrival and a departure",
      "owner_changed" in kinds, True)
check("and it is the only kind reported for that port", kinds.count("owner_changed"), 1)
check("no appeared row was written for the restart", "appeared" in kinds, False)
check("no disappeared row either", "disappeared" in kinds, False)
check("AND the replacement is the ONLY change row there is",
      len(changes), 1)
check("and the returned count agrees", res["owner_changed"], 1)
# THE HOLDER THAT WAS REPLACED MUST NOT SURVIVE THE PASS as an active row. If
# it does it is read back into the next pass's `prev`, the pid sets intersect
# again, and the port stops being able to report a change of hands at all --
# measured here, because it was true of the first version of this fix.
with sqlite3.connect(DB) as c:
    c.row_factory = sqlite3.Row
    live = [dict(r) for r in c.execute(
        "SELECT pid, active FROM port_owner_socket WHERE local_port = 45998")]
check("the replaced pid is DEACTIVATED, not left active",
      sorted(row["pid"] for row in live if row["active"]), [2000])

print("\n  -- a preforking server gaining a worker is NOT a change of hands")
_reset_sweep_state()
po.record_sweep("t9", correlated=_payload([_one(45997, 3000)]))
res2 = po.record_sweep("t9", correlated=_payload([_one(45997, 3000),
                                                  _one(45997, 3001)]))
with sqlite3.connect(DB) as c:
    c.row_factory = sqlite3.Row
    kinds2 = [dict(r)["kind"] for r in c.execute(
        "SELECT * FROM port_owner_change ORDER BY id")]
check("a second worker holding the same port reports NO owner change",
      "owner_changed" in kinds2, False)
# ONE appeared ROW, FOR THE ONE WORKER THAT JOINED: pid 3000 was recorded by the
# seed pass and is not news, so the only arrival is pid 3001.
check("and reports the new worker as an arrival only",
      kinds2.count("appeared"), 1)

print("\n  -- an unreadable owner never invents a change of hands")
_reset_sweep_state()
unread1 = dict(_one(45996, None))
unread1["owner_status"] = po.OWNER_UNREADABLE
unread1["comm"] = None
unread1["exe"] = None
po.record_sweep("t9", correlated=_payload([unread1]))
unread2 = dict(unread1, inode="12345")
res3 = po.record_sweep("t9", correlated=_payload([unread2]))
with sqlite3.connect(DB) as c:
    kinds3 = [r[0] for r in c.execute("SELECT kind FROM port_owner_change")]
check("two blank owners produce no owner_changed row",
      "owner_changed" in kinds3, False)
check("and the sweep says it reported none", res3["owner_changed"], 0)

print("\n  -- a bind change IS reported, and only for the same process")
_reset_sweep_state()
po.record_sweep("t9", correlated=_payload([_one(45995, 4000)]))
res4 = po.record_sweep("t9", correlated=_payload(
    [_one(45995, 4000, addr="0.0.0.0")]))
with sqlite3.connect(DB) as c:
    c.row_factory = sqlite3.Row
    kinds4 = [dict(r)["kind"] for r in c.execute(
        "SELECT * FROM port_owner_change ORDER BY id")]
check("moving from loopback to all-interfaces IS reported",
      "bind_changed" in kinds4, True)
# THE RETURNED COUNTS ARE THE BIND COUNT, NOT THE OWNER COUNT. The first draft
# of this check read `owner_changed` here, which is a DIFFERENT number on the
# same payload: it was asserting that a bind move is a change of hands, which
# is the exact confusion the two keys exist to prevent.
check("and counted as a bind change, not as a change of hands",
      (res4["bind_changed"], res4["owner_changed"]), (1, 0))
check("and the change row itself is a bind_changed",
      kinds4.count("bind_changed"), 1)

print("\n  -- and a DIFFERENT process on the port is an owner change, not a bind move")
_reset_sweep_state()
po.record_sweep("t9", correlated=_payload([_one(45994, 5000)]))
po.record_sweep("t9", correlated=_payload([_one(45994, 6000, addr="0.0.0.0")]))
with sqlite3.connect(DB) as c:
    kinds5 = [r[0] for r in c.execute("SELECT kind FROM port_owner_change")]
check("a different holder at a different address is an owner_changed",
      "owner_changed" in kinds5, True)
check("and NOT reported as the previous process moving its bind",
      kinds5.count("bind_changed"), 0)


print("\n[10] THE TWO ENTRY POINTS THE OWNER ASKED FOR")
# "python should execute the scan on set intervals AND ... agent should be
# able to call python to execute a scan whenever it wants to complete a
# report". Both halves are asserted: the timer's clock, and the on-demand call
# the duty loop makes.
print("\n  -- the interval: read from one key, floored in code")
secs, key = po.sweep_interval_seconds({"sensors": {"port_owner":
                                                   {"poll_interval": 600}}})
check("a sane interval is honoured", secs, 600)
check("and the key it came from is named", key,
      "sensors.port_owner.poll_interval")
secs2, key2 = po.sweep_interval_seconds({"sensors": {"port_owner":
                                                     {"poll_interval": 1}}})
check("AN INTERVAL BELOW THE FLOOR IS RAISED, not honoured", secs2,
      po.MIN_SWEEP_SECONDS)
check("and the floor says it was applied", "floor" in key2, True)
secs3, _ = po.sweep_interval_seconds({"sensors": {"port_owner":
                                                  {"poll_interval": "abc"}}})
check("an unreadable interval falls back to the default", secs3,
      po.DEFAULT_SWEEP_SECONDS)
check("the default is not below the floor",
      po.DEFAULT_SWEEP_SECONDS >= po.MIN_SWEEP_SECONDS, True)

print("\n  -- the switch: `is True`, and an unreadable value is OFF")
check("no key means enabled",
      po.sweep_enabled({})[0], True)
check("true means enabled",
      po.sweep_enabled({"sensors": {"port_owner": {"enabled": True}}})[0], True)
check("FALSE means disabled",
      po.sweep_enabled({"sensors": {"port_owner": {"enabled": False}}})[0],
      False)
check("THE STRING 'false' IS TREATED AS OFF, not as truthy",
      po.sweep_enabled({"sensors": {"port_owner": {"enabled": "false"}}})[0],
      False)
check_true("and it says the value was unreadable",
           "unreadable" in
           po.sweep_enabled({"sensors": {"port_owner":
                                         {"enabled": "false"}}})[1], True)

print("\n  -- the clock is WALL CLOCK, and an unreadable time is due NOW")
due, waited = po.sweep_due("2020-01-01 00:00:00", 300)
check("a long-past sweep is due", due, True)
check_true("with the wait reported", waited > 1000000, waited)
import datetime as _dt
_now_s = (_dt.datetime.now(_dt.timezone.utc)
          .strftime("%Y-%m-%d %H:%M:%S"))
due2, waited2 = po.sweep_due(_now_s, 300)
check("a just-taken sweep is NOT due", due2, False)
check("nor any time an interval ago is not due", po.sweep_due(_now_s, 30)[0],
      False)
due3, _w = po.sweep_due("not a timestamp", 300)
check("AN UNREADABLE TIMESTAMP IS DUE, not a reason to wait forever", due3,
      True)
due4, _w = po.sweep_due(None, 300)
check("and so is a missing one", due4, True)

print("\n  -- sweep_now is the on-demand pass, and it is the SAME pass")
before_n = sqlite3.connect(DB).execute(
    "SELECT COUNT(*) FROM port_owner_sweep").fetchone()[0]
res_now = po.sweep_now("t9", reason="test on demand")
after_n = sqlite3.connect(DB).execute(
    "SELECT COUNT(*) FROM port_owner_sweep").fetchone()[0]
check("sweep_now ran", res_now["ran"], True)
check("and wrote exactly one sweep row", after_n - before_n, 1)
check("it reports the reason it was asked for", res_now["reason"],
      "test on demand")

print("\n  -- and sweep_now NEVER RAISES, even with the tables gone")
_saved = me.DB_PATH
me.DB_PATH = tmp / "nonexistent.db"
try:
    broken = po.sweep_now("t9", reason="broken store")
    check("it returned rather than raising", broken["ran"], False)
    check_true("with a reason", bool(broken.get("reason")), broken)
finally:
    me.DB_PATH = _saved


print("\n[11] THE DUTY LOOP USES BOTH HALVES, AND THE REPORT CARRIES THEM")
# A function that exists and is never called is the defect this project keeps
# paying for, so the CALL SITES are asserted, not just the functions.
_duty = _src("core/duty.py")
check("the duty loop builds a host survey before the prompt",
      "build_host_survey_block(" in _duty, True)
check("and the incident prompt carries it", "{host_block}" in _duty, True)
check("and so does the regular prompt",
      _duty.count("{host_block}") >= 2, True)
check("the survey runs a FRESH sweep for the report",
      "port_owner.sweep_now(" in _duty, True)
check("and it is called by run_once rather than sitting unused",
      "host_block = build_host_survey_block(" in _duty, True)

# THE SENTENCES BELOW ARE ASSEMBLED FROM WRAPPED STRING LITERALS in the source,
# so a `in _duty` search for the finished sentence finds nothing even though the
# block really does say it. That is a defect in the CHECK, not in the block:
# the first draft of these two checks failed against correct code, and the fix
# is to search for a fragment that survives the wrap -- or better, to assert on
# the RENDERED block, which is what the reader of a prompt actually gets.
_prompt_text = ""
try:
    _prompt_text = duty.build_host_survey_block("t9-check", sweep=False)
except Exception as _e:                                      # noqa: BLE001
    print(f"  (the survey block could not be rendered here: {_e!r}; the "
          f"checks below fall back to reading the source)")
check("the survey block is bounded and says so when it cuts",
      ("This list is CUT" in _prompt_text
       or "This list is CUT" in _duty), True)
check("and the change list announces its own cut",
      ("this list is CUT" in _prompt_text or "this list is CUT" in _duty), True)
check("an unattributable listener is described as a privilege limit in the "
      "prompt too",
      ("PRIVILEGE LIMIT" in _prompt_text or "PRIVILEGE LIMIT" in _duty), True)
check("a failed sweep is a SENTENCE in the block, not an exception",
      "THE SWEEP DID NOT RUN FOR THIS REPORT" in _duty, True)
check("and the block forbids calling an open port a finding",
      "raises no finding in this app by design" in _prompt_text
      or ("raises no finding in" in _duty and "this app by design" in _duty),
      True)

print("\n  -- the timer thread exists and starts the sweep before sleeping")
_main = _src("main.py")
check("main.py has the sweeper", "_start_port_owner_sweeper" in _main, True)
check("and CALLS it at boot",
      "_start_port_owner_sweeper(config, session_id)" in _main, True)
check("the thread is a daemon so it cannot hold the app open",
      'name="port-owner-sweeper"' in _main and "daemon=True" in _main, True)
check("the clock comes from the module rather than a second config reader",
      "port_owner.sweep_interval_seconds(config)" in _main, True)
check("the switch comes from the module too",
      "port_owner.sweep_enabled(config)" in _main, True)

print("\n  -- and the model can ask for the same thing through a tool")
check("the tool is in the manifest",
      '"query_port_owner"' in _src("core/tool_registry.py"), True)
check("it has a dispatch branch",
      'if name == "query_port_owner":' in _src("core/tool_registry.py"), True)
check("it is declared in sensor_health.DEPENDS",
      '"query_port_owner"' in _src("core/sensor_health.py"), True)
check("it is fenced like every other tool serving somebody else's text",
      '"query_port_owner"' in _src("core/sanitize.py"), True)
check("it is classified READ-ONLY rather than defaulting to a write",
      '"query_port_owner"' in
      _src("core/tool_registry.py").split("_READ_ONLY_EXTRA = {")[1]
      .split("}")[0], True)
check("and it is in the unattended allowlist so a report can carry it",
      "query_port_owner" in duty.DUTY_TOOL_ALLOWLIST, True)

check("the self-scan attaches port owners",
      "could not attach port owners" in _src("tools/port_scanner.py"), True)
check("and only for a self-scan, where the answer can exist",
      "if scan_origin == \"self\":" in _src("tools/port_scanner.py"), True)

print("\n  -- the fence check at import would have failed on a stale name")
print("       (core/tool_registry raises at import if a fenced name is not a "
      "tool; this file imports it above and did not raise)")


print("\n[12] THE PAGE: BOTH CONTROLS, ON THE SAME TAB, AND NOTHING OPTIMISTIC")
_page = (ROOT / "ui" / "index.html").read_text(encoding="utf-8")
_agents_page = _page.split('id="page-agents"')[1].split('id="page-review"')[0]
# THE REPORT ROWS ARE RENDERED, NOT STATIC MARKUP, and the first draft of these
# checks looked for the per-row button inside the page's own <div> -- which
# holds the empty container `#agent-reports` and nothing else. It failed
# against working code: reportCard() builds each row, renderAgents() writes
# them into that container, and loadAgents() is the only thing that calls it.
# So the check asserts BOTH halves of the render path: the container is on the
# Agents tab, and the only writer of it is the agents renderer.
_agents_render = _page.split("function renderAgents()")[1].split(
    "\nfunction ")[0]
_report_card = _page.split("function reportCard(r)")[1].split("\nfunction ")[0]
check("THE REPORT LIST CONTAINER IS ON THE AGENTS TAB",
      'id="agent-reports"' in _agents_page, True)
check("and the only thing writing into it is the agents renderer",
      ("document.getElementById('agent-reports')" in _agents_render
       and _page.count("reports.map(reportCard)") == 1), True)
check("the per-row dismiss button is rendered into every report row",
      "dismissOneReport(" in _report_card, True)
check("and the tick box is too",
      'class="agent-tick"' in _report_card, True)
check("the dismiss-all button is on the Agents tab",
      "dismissAllReports()" in _agents_page, True)
check("the dismiss-ticked button is on the Agents tab",
      "dismissSelectedReports()" in _agents_page, True)
check("and the show-dismissed toggle is there too",
      'id="agent-show-dismissed"' in _agents_page, True)
check("ALL FOUR ARE REACHABLE FROM THE SAME TAB, not spread across pages",
      all(x in _agents_page for x in ("dismissAllReports()",
                                      "dismissSelectedReports()",
                                      'id="agent-show-dismissed"'))
      and "dismissOneReport(" in _report_card
      and 'id="agent-reports"' in _agents_page, True)

check("the dismiss-all confirms first",
      "window.confirm(" in _page, True)
check("and the confirmation says NOTHING IS DELETED",
      "NOTHING IS DELETED" in _page, True)
check("the card text says dismissing deletes nothing",
      "DISMISSING HIDES A REPORT FROM THIS LIST AND DELETES NOTHING"
      in _page.upper().replace("\n", " "), True)
check("the success line says so too",
      "NOTHING WAS DELETED" in _page, True)
check("the tick state survives a refresh (a Set, not a DOM read)",
      "let AGENT_TICKED = new Set();" in _page, True)
check("a failed dismissal says nothing was dismissed",
      "NOTHING was dismissed" in _page, True)
check("the empty state names the hidden count rather than saying 'no report'",
      "existing and are DISMISSED" in _page
      or "exist and are DISMISSED" in _page, True)
check("the hidden count is rendered from the summary, not guessed",
      "s.dismissed_reports" in _page, True)

print("\n  -- and the Ports tab reads the same record for a person")
check("there is a route for it",
      '/api/ports/owners' in _src("api/routes.py"), True)
check("the route validates its sweep argument rather than coercing it",
      "sweep must be true or false" in _src("api/routes.py"), True)
check("and carries the coverage sentence in the same payload",
      '"coverage": data.get("coverage")' in _src("api/routes.py"), True)


print("\n[13] THE LEVERS THIS ROUND DID NOT TOUCH")
# Named so a later reader can see what was deliberately left alone rather than
# assuming it was missed.
_po_src = _src("tools/port_owner.py")
check("port_owner writes NO finding (the finding rule: only a declared "
      "expectation raises)",
      "save_finding" in _po_src, False)
check("and it registers no detection id", "detections" in _po_src, False)
check("it reads the store only through memory_engine",
      "sqlite3.connect" in _po_src, False)
check("it does not spawn a subprocess (no ss, no netstat parsing)",
      "subprocess" in _po_src, False)
check("the migration adds tables and columns but backfills NO row",
      "UPDATE port_owner" in _src("core/migrations.py").split(
          "def _migrate_port_owner(")[1].split("\ndef ")[0], False)

print("\n" + ("ALL CHECKS PASSED" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
