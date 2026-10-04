"""
tests/test_question_truth.py, the round the owner opened with "fix this".

THE ASK, and the thing the owner pasted, was a confirm_change question about
example-app. Three separate defects came out of reading it against the machine
rather than against the question. Each is asserted here in both directions --
the defect must fail and the fix must pass -- per the register's rule 7.

  1. THE SENTENCE ABOUT THE FILE WAS FALSE. The question said the md5sums
     control file was "truncated", and the why_stuck said the sensor "only
     detects that the md5sums control file is truncated". The file is
     COMPLETE: 846 lines, newline-terminated, every line a valid digest, and
     byte-identical to the copy inside the vendor's own downloaded .deb. The
     reason string cut the line at 60 characters with no marker, and the
     truncated-LOOKING display was written into the question as a claim about
     the FILE. Sections [1] and [2].

  2. THE ADVICE COULD NOT WORK. The finding, and the question copied from it,
     said a reinstall would fix it. It cannot: the installer wrote the file
     correctly from a correctly-built package, so a reinstall writes the same
     bytes back. Measured by rebuilding the control archive under a scratch
     admindir: dpkg's separator is TWO OR MORE SPACES; one space is refused,
     a TAB is refused, two spaces verify and exit 0. Section [3].

  3. THE HINTS WERE FOR THE WRONG KIND OF THING. A package name was given
     Shodan, Censys and VirusTotal IP links with the package name pasted into
     an IP address URL, plus three IP reputation sources named as "not asked".
     classify() answered None and the code defaulted to "ip". Section [4].

  And the fourth finding, which is about the QUEUE rather than the question:
  the owner ANSWERED this one, in chat, and the answer was filed as an observation
  while the question stayed open. Sections [5] and [6].

Run it directly: python tests/test_question_truth.py
"""
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import _isolate_db                                    # noqa: E402
_isolate_db.isolate()

from core import memory_engine as me                  # noqa: E402
from core import questions as q                       # noqa: E402

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}"
          + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


def check_true(label, got):
    check(label, bool(got), True)


SID = "test-session"
CONTROL = "/var/lib/dpkg/info/example-app.md5sums"


print("\n[1] THE FILE IS NOT TRUNCATED, and the reason says what is wrong with it")

import tools.local_integrity as li                    # noqa: E402

# The real control file, if this host has it. The whole defect was a claim
# about THIS file, so a synthetic fixture would prove the parser and not the
# finding. SKIP IN WORDS when it is absent, per the house rule -- a green
# check that never looked is worse than a skip.
if pathlib.Path(CONTROL).exists():
    _ok, _why = li._md5sums_ok(CONTROL)
    check("dpkg still refuses this package", _ok, False)
    check_true("and the reason no longer reads as a truncated file",
               "truncat" not in _why.lower())
    check_true("it names the separator as the defect",
               "ONE space" in _why or "TAB" in _why)
    check_true("and it says how many lines the file HAS, so the reader can "
               "tell completeness from a slice", "of 846" in _why)
    # THE MARKER IS ASSERTED ON ITS OWN, with no disjunction. This check's
    # first draft was `"...[" in _why or len(_why) < 400`, and the round's own
    # negative control caught it: the OR's weaker half is satisfied by the
    # REVERTED unmarked slice, so the check stayed green against the defect it
    # was written for. Measured, not theorised -- C2 in
    # scripts/control_question_truth.py.
    _longest = max((len(l) for l in open(CONTROL, encoding="utf-8")), default=0)
    check_true(f"the file's longest line is longer than the 60-char display "
               f"limit, so a cut is exercised ({_longest} chars)",
               _longest > 60)
    check_true("and the evidence is MARKED as cut, so a complete file cannot "
               "be read as a truncated one", "...[" in _why)

    # THE FILE'S OWN BYTES, measured independently of the parser.
    _raw = pathlib.Path(CONTROL).read_bytes()
    check("the control file ends with a newline -- it is not cut off",
          _raw.endswith(b"\n"), True)
    check("and it holds all 846 lines",
          len([l for l in _raw.decode("utf-8", "replace").split("\n")
               if l.strip()]), 846)
else:
    print("  SKIP  this host has no example-app control file, so the claims "
          "about it cannot be re-measured here")


print("\n[2] the parser accepts dpkg's grammar and refuses what dpkg refuses")

import tempfile, os, shutil                           # noqa: E402

_tmp = tempfile.mkdtemp(prefix="qt_md5_")
try:
    def _wrote(name, body):
        p = os.path.join(_tmp, name)
        with open(p, "w") as fh:
            fh.write(body)
        return p

    ONE = "87ccd9ca305586f516317bb405ab30d4 usr/share/x/a\n"
    TWO = "87ccd9ca305586f516317bb405ab30d4  usr/share/x/a\n"
    THREE = "87ccd9ca305586f516317bb405ab30d4   usr/share/x/a\n"
    TAB = "87ccd9ca305586f516317bb405ab30d4\tusr/share/x/a\n"

    # MEASURED against the real dpkg on 2026-09-26, one variant per run:
    # 1 space rc 2, 2 spaces rc 0, 3 spaces rc 0, TAB rc 2.
    check("ONE space is refused (dpkg rc 2)",
          li._md5sums_ok(_wrote("one.md5sums", ONE))[0], False)
    check("TWO spaces are accepted (dpkg rc 0)",
          li._md5sums_ok(_wrote("two.md5sums", TWO))[0], True)
    check("THREE spaces are accepted too (dpkg rc 0) -- the old check "
          "refused this, which is dpkg's rule being paraphrase",
          li._md5sums_ok(_wrote("three.md5sums", THREE))[0], True)
    check("a TAB is refused (dpkg rc 2)",
          li._md5sums_ok(_wrote("tab.md5sums", TAB))[0], False)
    check_true("and the TAB refusal says TAB rather than 'unparseable'",
               "TAB" in li._md5sums_ok(_wrote("tab.md5sums", TAB))[1])

    _p = li._md5sums_line_problem("not-a-digest path")
    check_true("a line with no digest says so",
               "32-character md5" in _p)
    check("a well-formed line has no problem", li._md5sums_line_problem(
        TWO.rstrip("\n")), "")
    check("and an empty line has none either",
          li._md5sums_line_problem(""), "")

    # THE LINE COUNT IS IN THE REASON, which is what lets a reader tell a
    # complete file from a display slice.
    _r = li._md5sums_ok(_wrote("many.md5sums", ONE * 5))[1]
    check_true("the reason carries 'line 1 of 5'", "line 1 of 5" in _r)
finally:
    shutil.rmtree(_tmp, ignore_errors=True)


print("\n[3] the finding no longer tells the owner a reinstall will fix it")

_text = li._dpkg_refused_text("example-app", "line 1 of 846: ONE space", 1)
check_true("the false instruction is GONE",
           "Reinstalling the package" not in _text)
check_true("and the sentence says so explicitly, so a reader who saw the old "
           "version can tell which is which",
           "reinstall" in _text.lower() and "NOT the fix" in _text)
check_true("it names the separator as the actual repair",
           "two or more spaces" in _text)
check_true("and it names who owns the decision, because the file is root's",
           "operator" in _text or "root-owned" in _text)
check_true("the abort consequence is still stated",
           "aborts on the first" in _text)
check_true("the FALSE 'two files' claim is gone",
           "reports two files" not in _text)
check_true("and what replaces it is true -- dpkg stops at the bad file",
           "never reaches" in _text)

# The same claim lived in four places, and one round in this tree already
# fixed only the file in front of it. Assert the RUNNING TEXT, not the file:
# a whole-file substring check here reads the CORRECTION PROSE that quotes the
# old sentence -- the absence-check-satisfied-by-its-own-comment trap this
# project has recorded, hit again while writing this test.
_src = (ROOT / "tools" / "local_integrity.py").read_text(encoding="utf-8")
_live = "\n".join(l for l in _src.splitlines()
                  if not l.lstrip().startswith("#"))
check_true("the module header no longer says 'two files reported'",
           "and two files reported" not in _live)
check_true("nor calls the file malformed in the cost note",
           "one malformed control file" not in _src)
check_true("the consequence field is corrected in place",
           "CORRECTED 2026-09-26" in _src)

# And the correction prose is really there, so the check above is not passing
# because somebody deleted the explanation instead of the claim.
check_true("the correction NAMES the old wording it replaced",
           "and two files reported" in _src)


print("\n[4] hints match the KIND of thing, and never guess one")

_h = q._research_hints("example-app")
check("a package name gets no IP lookups", len(
    [x for x in _h if "shodan.io" in (x.get("url") or "")
     or "censys.io" in (x.get("url") or "")]), 0)
check_true("and it says the app could not classify it, rather than leaving "
           "an empty list to read as 'nowhere to look'",
           any("no kind was established" in x["label"] for x in _h))
check_true("the sentence blames the app and not the thing",
           any("NOT evidence about the thing itself" in x["why"] for x in _h))
check_true("no IP reputation source is named as 'not asked' for a package",
           not any(x["label"].startswith(("abuseipdb", "greynoise"))
                   for x in _h))

# The other direction: a real address still gets its real hints.
_hi = q._research_hints("203.0.113.7")
check_true("an address still gets Shodan",
           any("shodan.io" in (x.get("url") or "") for x in _hi))
check_true("and still gets the keyed-source notes",
           any(x["label"].endswith("was not asked") for x in _hi))
check_true("and the generic search is NOT padded onto a classified kind",
           not any("duckduckgo" in (x.get("url") or "") for x in _hi))

# A domain gets domain lookups, not IP ones. The old default would have got
# this right by accident; assert it so a future change to the fallback cannot
# silently move it.
_hd = q._research_hints("example.com")
check_true("a domain gets VirusTotal's DOMAIN page",
           any("/domain/" in (x.get("url") or "") for x in _hd))
check_true("and not the IP-address page",
           not any("/ip-address/" in (x.get("url") or "") for x in _hd))


print("\n[4b] 'nothing has been looked up' is not one silence but two")

# MEASURED: enrichment.enqueue REFUSES an indicator it cannot classify. So for
# a package name there is no lookup to run and never will be, and the card
# said "nothing has been looked up for this yet" -- which reads as "a lookup
# is pending or possible". Same family as the hints defect: an absence dressed
# as a gap somebody might still fill.
_tried_pkg, _ = q._what_was_tried("example-app")
check_true("an unclassifiable thing says the worker REFUSED it",
           "REFUSED" in _tried_pkg[0]["said"])
check_true("and says it is not a lookup waiting to happen",
           "not a lookup waiting to happen" in _tried_pkg[0]["said"])

_tried_ip, _ = q._what_was_tried("203.0.113.7")
check_true("a real address still says only that it has not been looked up yet",
           "REFUSED" not in _tried_ip[0]["said"])

# And the app's own refusal is what the sentence is based on, so drive it.
from core import enrichment as enr                      # noqa: E402
check("the classifier really does refuse a package name",
      enr.classify("example-app"), None)
check("and really does place an address",
      enr.classify("203.0.113.7"), "ip")


print("\n[5] a refused repeat hands back WHAT was asked and HOW LONG it waited")
_r = q.file_question(SID, "expected_behaviour", "process", "sleeper",
                     "is this normal for you")
check("the first ask lands", _r["success"], True)
_again = q.file_question(SID, "expected_behaviour", "process", "sleeper",
                         "same topic, rephrased completely")
check("the repeat is still refused -- rule 2 is not weakened",
      _again["success"], False)
check("and it is the SAME question id", _again["question_id"],
      _r["question_id"])
check_true("the refusal now carries the question that is filed",
           _again.get("already_asked_text")
           == "is this normal for you")
check_true("and when it was asked", _again.get("asked_at"))
check_true("and how long it has been waiting, in words",
           "day" in (_again.get("waiting_for") or ""))
check("an unshown question says the owner has not been shown it",
      _again["first_shown_at"], None)
check_true("and the note says it was NOT re-asked and NOT reopened",
           "NOT reopened" in _again["note"])


print("\n[6] the row the owner answered in chat is NAMED, not left looking unanswered")

# THE MEASURED SHAPE, reproduced: a question asked, an answer filed as
# operator_stated, and the question row still open -- exactly this host's
# state on 2026-09-26.
with me._get_conn() as c:
    c.execute("DELETE FROM operator_question WHERE entity_value=?",
              ("example-app",))
_seed = q.file_question(SID, "confirm_change", "process", "example-app",
                        "did you install this package")
check("the question is filed", _seed["success"], True)

me.write_behavioral_observation(
    entity_type="process", entity_value="example-app",
    behavior_key="operator_answer",
    behavior_value="user confirmed intentional install",
    session_id="operator-answer-999", basis="operator_stated")

_rows = q.query_questions(state="open")
_mine = [r for r in _rows if r["entity_value"] == "example-app"]
check("the row is still open -- nothing auto-closes it", len(_mine), 1)
check_true("but it is FLAGGED as having a filed answer",
           _mine[0].get("unheard_answer"))
check_true("and the flag carries what was filed, not just a boolean",
           "intentional install" in
           (_mine[0].get("unheard_answer_detail") or {}).get("behavior_value", ""))
check_true("with a note saying what the flag does and does not prove",
           "not proof" in
           (_mine[0].get("unheard_answer_detail") or {}).get("note", ""))

_s = q.summary()
check_true("the summary names the open question with a filed answer",
           any(e["question_id"] == _seed["question_id"]
               for e in (_s.get("open_with_a_filed_answer") or [])))
check("and the four counts still add up to the rows -- no fifth state",
      sum(_s[k] for k in ("open", "answered", "do_not_know", "expired")),
      len(q.query_questions(limit=500)))

# The other direction: an open question with NO filed answer must not be
# flagged, or the flag is decoration.
_r2 = q.file_question(SID, "identify_process", "process", "quiet-thing",
                      "do you recognise this")
check("a second question is filed", _r2["success"], True)
_quiet = [r for r in q.query_questions(state="open")
          if r["entity_value"] == "quiet-thing"]
check("and it is NOT flagged, because nothing was filed for it",
      _quiet[0].get("unheard_answer"), False)
check("nor carries a detail block",
      "unheard_answer_detail" in _quiet[0], False)

# And an ANSWERED question is not 'unheard' -- the flag is for open rows only.
q.answer(_seed["question_id"], do_not_know=True)
_after = [r for r in q.query_questions()
          if r["entity_value"] == "example-app" and r["state"] != "open"]
check_true("once the owner answers it, the row moves state",
           bool(_after) and _after[0]["state"] == "do_not_know")
check("and is no longer flagged as unheard", _after[0].get("unheard_answer"),
      False)


print("\n[7] the question's own text is WITNESSED, and its seal does not "
      "break when the owner answers")

from core import integrity as ig                      # noqa: E402

check_true("operator_question is a sealed table",
           "operator_question" in ig.SEALED_TABLES)

_demo = q.file_question(SID, "identify_device", "ip", "203.0.113.99",
                        "is this one of yours")
check("a newly filed question lands", _demo["success"], True)
check("and the OPERATION is accepted by the journal's allow-list, so a row "
      "that was sealed says so",
      isinstance(ig.record("operator_question_filed", "operator_question",
                           _demo["question_id"], {}), dict), True)

# ANSWERING must not break the witness: state/answered_at/answer_text are
# excluded columns, exactly like action_request's decided half.
#
# row_ref IS TEXT IN THE JOURNAL and an int here -- the comparison is done as
# strings, and this check's first draft compared an int against a set of TEXT
# and reported a working seal as broken. That is the same cast trap the
# module's own _trim_consistent carries a comment about.
def _edited_rows():
    v = ig.verify_sealed_rows()
    return {str(p["row_ref"]) for p in (v.get("problems") or [])
            if p.get("kind") == "edited" and p.get("table") == "operator_question"}

_before = _edited_rows()
with me._get_conn() as c:
    c.execute("UPDATE operator_question SET state='answered', answer_text='x' "
              "WHERE id=?", (_demo["question_id"],))
check("answering it does NOT break its witness (state is excluded)",
      _edited_rows() == _before, True)

with me._get_conn() as c:
    c.execute("UPDATE operator_question SET question='something else entirely' "
              "WHERE id=?", (_demo["question_id"],))
check_true("but REWRITING the question IS detected",
           str(_demo["question_id"]) in _edited_rows())


print("\n" + ("ALL PASS" if not fails else f"{len(fails)} FAILED: {fails}"))
sys.exit(1 if fails else 0)
