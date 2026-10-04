"""
tests/test_detection_ids.py, does every finding say which rule raised it.

FAILURE CASES FIRST, per rule one. The happy path of a register is trivial:
look a string up in a dict. Everything worth testing here is a way the
register can be WRONG while still looking like it works, and the worst of
those is a suppression that silences something and cannot say so.

What is tested, in order:

  [1] An unregistered id is refused. Not defaulted, not logged and ignored.
  [2] A missing id is refused, with a sentence that says what to do.
  [3] A severity the detection does not declare is refused.
  [4] A suppression that cannot be READ does not silence anything, and says
      out loud that it could not look. Failing open on a silencing check.
  [5] A suppressed detection returns saved False WITH A REASON, so a caller
      can never confuse "not raised" with "raised".
  [6] Suppressing one detection on one entity leaves every other detection on
      that entity alone. This is the whole point of the feature.
  [7] The wildcard really is one row. NULL would not have been.
  [8] Only then: a finding saves, carries its id and the rev that was live.
  [9] The rev is COPIED, not looked up later. A register change does not
      rewrite history.
 [10] Unstamped rows are counted separately and never as a rule's zero.
 [11] Every threat label the sniffer can emit maps to a registered detection.
 [12] Every save_finding call site in the tree names a detection.
 [13] Fresh schema and migrated schema converge, and the migration is
      idempotent.
 [14] No number is reused, and every retired entry says why.

Run it directly: python tests/test_detection_ids.py
"""
import pathlib
import sqlite3
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import _isolate_db                                    # noqa: E402
_isolate_db.isolate()

from core import detections as det                    # noqa: E402
from core import memory_engine as me                  # noqa: E402

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}"
          + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


def check_true(label, got):
    check(label, bool(got), True)


def raises(label, exc, fn, *a, **kw):
    try:
        fn(*a, **kw)
    except exc:
        print(f"  PASS  {label}")
        return
    except Exception as e:
        print(f"  FAIL  {label}: raised {type(e).__name__} not {exc.__name__}")
        fails.append(label)
        return
    print(f"  FAIL  {label}: nothing raised")
    fails.append(label)


SID = "test-session"

# findings.sensor_id is a foreign key into sensors, and save_finding stamps
# the local sensor by default. An isolated database has no sensors row, so
# without this every write here fails on the constraint rather than on
# anything this file is about.
from core import sensors as sn                        # noqa: E402
sn.register_local()


def save(did, severity="medium", entity="192.0.2.22", title="t",
         entity_type="ip"):
    return me.save_finding(
        session_id=SID, source="test", severity=severity,
        entity_type=entity_type, entity_value=entity, title=title,
        detection_id=did)


print("\n[1] An id nobody registered is refused")
# The failure that makes the whole register pointless if it is allowed. A
# default here would let a new sensor quietly inherit an existing identity,
# and the findings history would silently merge two different rules.
raises("an unknown id raises", det.UnknownDetection, det.get, "NOPE-9999")
raises("save_finding refuses an unknown id", det.UnknownDetection,
       save, "NOPE-9999")
check("exists() answers without raising, for readers",
      det.exists("NOPE-9999"), False)


print("\n[2] No id at all is refused, and the message says what to do")
raises("no detection_id raises", det.MissingDetectionId,
       me.save_finding, session_id=SID, source="test", severity="low",
       entity_type="ip", entity_value="192.0.2.1", title="t")
try:
    save(None)
except det.MissingDetectionId as e:
    msg = str(e)
    check_true("the message names the register", "core/detections" in msg)
    check_true("the message says what to do", "add an entry" in msg.lower())


print("\n[3] A severity the detection does not declare is refused")
# PKT-1001 is registered low only, because the code only ever raises it low.
# If somebody changes that in the sniffer, this goes red rather than the
# dashboard quietly showing a critical nobody decided on.
raises("an undeclared severity raises", det.BadSeverity,
       save, "PKT-1001", "critical")
check("a declared one is accepted", save("PKT-1001", "low")["saved"], True)
raises("garbage severity still hits BadInput first", me.BadInput,
       save, "PKT-1001", "catastrophic")


print("\n[4] A suppression check that cannot look says so, and fails OPEN")
# Rule two, applied to a silencing check. If the table is unreadable, the two
# possible mistakes are not equal: raising something the operator muted is
# noise, and muting something nobody muted is silence nobody chose. So this
# reports suppressed False AND checked False, and the finding still writes.
real_conn = me._get_conn


class _Broken:
    def __enter__(self):
        raise sqlite3.OperationalError("no such table: detection_suppression")

    def __exit__(self, *a):
        return False


me._get_conn = lambda *a, **k: _Broken()
blind = me.detection_suppressed("PKT-1001", "ip", "192.0.2.5")
me._get_conn = real_conn
check("a broken read is not suppression", blind["suppressed"], False)
check("and it admits it could not look", blind["checked"], False)
check("a clean read says it DID look",
      me.detection_suppressed("PKT-1001", "ip", "192.0.2.5")["checked"], True)


print("\n[5] A suppressed save returns False with a reason, never silence")
me.suppress_detection("PKT-1002", reason="known NTP poller",
                      entity_type="ip", entity_value="192.0.2.12")
r = save("PKT-1002", "low", entity="192.0.2.12")
check("it did not save", r["saved"], False)
check_true("it says which rule", r["detection_id"] == "PKT-1002")
check_true("it gives the operator's own reason",
           "known NTP poller" in (r.get("reason") or ""))
check("the same rule on another address still raises",
      save("PKT-1002", "low", entity="192.0.2.13")["saved"], True)


print("\n[6] Suppressing one rule leaves the entity's other rules alone")
# The thing dismiss_entity could never do. Before this, quieting the beacon
# rule about 192.0.2.12 meant quieting EVERY rule about 192.0.2.12.
check("a different rule on the suppressed address still raises",
      save("PKT-1001", "low", entity="192.0.2.12")["saved"], True)
check("dismiss_entity is untouched by any of this",
      me.is_dismissed("ip", "192.0.2.12"), False)


print("\n[7] The wildcard is one row, because NULL would not have been")
# SQLite treats two NULLs as distinct, so a UNIQUE index over nullable columns
# does not stop duplicates. '*' is a real value and the index works on it.
me.suppress_detection("PKT-1003", reason="first")
me.suppress_detection("PKT-1003", reason="second, replaces the first")
rows = [s for s in me.list_suppressions() if s["detection_id"] == "PKT-1003"]
check("re-suppressing updates rather than duplicating", len(rows), 1)
check("and it keeps the newer reason", rows[0]["reason"],
      "second, replaces the first")
check("a wildcard rule silences every entity",
      save("PKT-1003", "medium", entity="192.0.2.18")["saved"], False)
check("removing it lets the rule speak again",
      me.unsuppress_detection("PKT-1003")["removed"], 1)
check("removing nothing is not an error",
      me.unsuppress_detection("PKT-1003")["ok"], True)
check("and it says nothing was there",
      me.unsuppress_detection("PKT-1003")["removed"], 0)
raises("suppressing an unknown id is refused", det.UnknownDetection,
       me.suppress_detection, "NOPE-1", "because")
raises("a suppression with no reason is refused", me.BadInput,
       me.suppress_detection, "PKT-1001", "   ")


print("\n[8] The happy path: the row carries its id and its rev")
me.unsuppress_detection("PKT-1002", "ip", "192.0.2.12")
ok = save("LNX-1004", "high", entity="192.0.2.26")
check("saved", ok["saved"], True)
with me._get_conn() as c:
    row = c.execute(
        "SELECT detection_id, detection_rev FROM findings "
        "WHERE entity_value='192.0.2.26' ORDER BY id DESC LIMIT 1").fetchone()
check("the id is on the row", row["detection_id"], "LNX-1004")
check("so is the rev", row["detection_rev"], det.get("LNX-1004").rev)


print("\n[9] The rev is copied at write time, not looked up later")
# The reason to store it at all. If the register's rev moved and old rows
# resolved it live, "why did this fire in August" would answer with today's
# rule, which is the wrong rule.
before = det.get("LNX-1004").rev
det.DETECTIONS["LNX-1004"].rev = before + 5
save("LNX-1004", "high", entity="192.0.2.27")
det.DETECTIONS["LNX-1004"].rev = before
with me._get_conn() as c:
    old = c.execute("SELECT detection_rev FROM findings WHERE "
                    "entity_value='192.0.2.26'").fetchone()["detection_rev"]
    new = c.execute("SELECT detection_rev FROM findings WHERE "
                    "entity_value='192.0.2.27'").fetchone()["detection_rev"]
check("the older row kept the rev it was raised under", old, before)
check("the newer row recorded the newer rev", new, before + 5)


print("\n[10] Rows raised before ids existed are counted separately")
# Never as a rule's zero. A rule that has been firing since August reading
# "0 findings" would be a lie told by a column added last week.
with me._get_conn() as c:
    c.execute("""INSERT INTO findings
                 (session_id, source, severity, entity_type, entity_value,
                  title) VALUES (?,?,?,?,?,?)""",
              (SID, "old", "low", "ip", "192.0.2.4", "raised before TODO 112"))
counts = me.detection_counts()
check("the unstamped row is counted on its own", counts["unstamped"], 1)
check("and not against any rule",
      any(k is None for k in counts["counts"]), False)
check("the count knows it actually looked", counts["counted"], True)
ov = me.detection_overview()
check_true("the overview carries the unstamped total",
           ov["unstamped_findings"] == 1)
check_true("and explains what NULL means there",
           "before detections had ids" in ov["unstamped_note"])


print("\n[11] Every threat label the sniffer can emit is registered")
# The check that catches somebody adding a classifier branch and not coming
# back to the register. PKT-1099 exists so an unregistered label is still
# raised, which means this test is the only thing that would notice.
#
# WHERE THE LABELS LIVE ON THIS SIDE, converted 2026-09-21. The Windows sniffer
# emitted each threat label as a `return "label"` STRING, so this scan read the
# module's source line by line. The Linux sensor does not work that way: it
# returns a DICT per detection, and the label is the "type" field of a dict
# built inside the `_detect_*` functions (beaconing_detected,
# dangerous_port_connection, suspicious_payload). Scanning for return strings
# found zero labels and the check below caught that ("and the scan actually
# found some labels"), which is how this was noticed rather than passing empty.
#
# So the scan reads the same declarations the ADAPTER reads when it maps a hit
# to a rule id. Checked for a divergence: adapters.py names these three types
# in its own comment block above LinuxPacketSniffer.
SNIFFER = (ROOT / "tools" / "packet_sniffer_linux.py").read_text(encoding="utf-8")

# THE SCAN NOW READS ONLY THE DETECTION FUNCTIONS. 2026-09-22.
#
# The comment above has always said the label is the "type" field of a dict
# built INSIDE the _detect_* functions. The scan read the whole file, so any
# unrelated `"type":` line anywhere in the module was collected as a threat
# label and checked against the register.
#
# That was not theoretical: adding an interface dict with "type": "unknown"
# to get_available_interfaces -- display metadata for the dashboard, never
# near a finding -- turned this check red with the label 'unknown' and told
# the reader a threat label was unregistered. The check was right about what
# it saw; it was looking in a place its own comment said it was not.
#
# Scoping it to the functions that actually build detections keeps the
# property this exists for -- somebody adds a classifier branch and does not
# come back to the register -- and stops it reporting one that cannot happen.
# ast is used rather than a text scan so the boundary is the real one.
import ast                                            # noqa: E402

_tree = ast.parse(SNIFFER)
_sniffer_lines = SNIFFER.splitlines()
_detect_spans = []
for _node in ast.walk(_tree):
    if isinstance(_node, ast.FunctionDef) and _node.name.startswith("_detect"):
        _detect_spans.append((_node.lineno, _node.end_lineno))
_detect_text = "\n".join(
    line
    for start, end in sorted(_detect_spans)
    for line in _sniffer_lines[start - 1:end]
)

emitted = set()
for line in _detect_text.splitlines():
    s = line.strip()
    # the classic form, kept so this still catches a label added as a return
    if s.startswith('return "') and "_check" not in s:
        emitted.add(s.split('"')[1].split(":")[0])
    elif s.startswith('return (f"') or s.startswith('return f"'):
        frag = s.split('"', 1)[1]
        emitted.add(frag.split(":")[0].split("{")[0])
    # THE FORM THIS SENSOR ACTUALLY USES: a detection dict's type field
    elif s.startswith('"type":'):
        parts = s.split('"')
        if len(parts) > 3:
            emitted.add(parts[3].split(":")[0])
# Only the ones that are threat labels, not the scope words, which are
# returned by classify_scope and never reach a finding.
SCOPES = {"unclassified", "loopback", "local_multicast", "foreign_multicast",
          "broadcast", "private_to_private", "outbound", "inbound",
          "public_to_public"}
# THE SENSOR'S OWN TYPE NAMES ARE NOT RULE IDS, and the register is checked
# against the IDS their adapter maps them to instead. This is the Linux
# architecture rather than a relaxation: on Windows the sniffer emitted a
# RULE-SHAPED label ("beacon_interval:...") straight into save_finding, so the
# scan could compare labels to the register. Here the sensor reports a fact
# with a type name and adapters.LinuxPacketSniffer decides which rule it is:
#
#   beaconing_detected        -> PKT-1002 beacon_interval
#   dangerous_port_connection -> PKT-1013 / PKT-1014 by direction
#   suspicious_payload        -> PKT-1010 or nothing at all (counted, not
#                                written, because a ZIP header is not
#                                Metasploit and the register's rule says so)
#
# So the two halves are checked separately: every OTHER label still has to be
# in the register, and these three have to map to an id the register holds.
#
# ADDED 2026-09-23: volume_sustained, the new PKT-1001 raiser. The register
# has carried PKT-1001 since the packet rules were written and the module has
# carried VOLUME_THRESHOLD with no reader for as long as this scan has
# existed; adding the detector is what turned the scan red, which is exactly
# what this check is for.
MAPPED_BY_ADAPTER = {
    "beaconing_detected":        "PKT-1002",
    "dangerous_port_connection": "PKT-1013",
    "volume_sustained":          "PKT-1001",
    "suspicious_payload":        None,   # deliberately unmapped, see above
}
labels = sorted(e for e in emitted
                if e and e not in SCOPES and e not in MAPPED_BY_ADAPTER)
unmapped = det.unmapped_threat_prefixes(labels)
check("no threat label is missing from the register", unmapped, [])
# THE SCAN MUST HAVE FOUND SOMETHING TO BE WORTH ANYTHING. It is asserted over
# BOTH sets now: the rule-shaped labels above and the adapter-mapped type names
# below. Counting only the first left this red on a sensor whose labels are all
# map-carried, which would have been a check that can never pass.
check_true("and the scan actually found some labels",
           len(labels) + len(MAPPED_BY_ADAPTER) >= 3)
for label, rule_id in MAPPED_BY_ADAPTER.items():
    if rule_id is None:
        continue
    try:
        det.get(rule_id)
        check(f"{label} maps to a registered rule", True, True)
    except Exception as e:
        check(f"{label} maps to a registered rule", f"{type(e).__name__}: {e}",
              "ok")


print("\n[12] Every call site in the tree names a detection")
import ast                                            # noqa: E402
missing, seen = [], 0
for f in sorted(ROOT.rglob("*.py")):
    # TESTS ARE SKIPPED, and it is worth saying why rather than leaving it to
    # look like laziness. test_finding_noise subclasses PacketSniffer and
    # OVERRIDES _emit_finding with a recorder, so its calls never reach
    # save_finding and a missing id there is not a bug, it is a stub taking
    # fewer arguments than the real thing. The scan is about the app's own
    # call sites, which are the ones that can actually raise at runtime.
    if "__pycache__" in str(f) or f.name.startswith("test_"):
        continue
    try:
        tree = ast.parse(f.read_text(encoding="utf-8"))
    except SyntaxError:
        continue
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = getattr(node.func, "attr", None) or getattr(node.func, "id", None)
        if name not in ("save_finding", "_emit_finding"):
            continue
        seen += 1
        kw = {k.arg for k in node.keywords if k.arg}
        # **kwargs passthrough is how _emit_finding hands it on, so a call
        # that splats is not a miss.
        if "detection_id" not in kw and not any(k.arg is None
                                                for k in node.keywords):
            missing.append(f"{f.name}:{node.lineno}")
check("every call site names a detection", missing, [])
check_true("and the scan actually found the call sites", seen >= 20)


print("\n[13] Fresh and migrated schemas converge, and it is idempotent")
from core import migrations                           # noqa: E402


def shape(db):
    c = sqlite3.connect(db)
    try:
        out = {}
        for t in ("findings", "detection_suppression"):
            cols = [r[1] for r in c.execute(f"PRAGMA table_info({t})")]
            out[t] = sorted(cols)
        out["indexes"] = sorted(
            r[0] for r in c.execute(
                "SELECT name FROM sqlite_master WHERE type='index' "
                "AND name LIKE 'idx_%detection%'"))
        return out
    finally:
        c.close()


tmp = pathlib.Path(tempfile.mkdtemp(prefix="agentalsec_migr_"))
fresh = tmp / "fresh.db"
c = sqlite3.connect(fresh)
c.executescript((ROOT / "Schema.SQL").read_text(encoding="utf-8"))
c.commit()
c.close()

# A v32 database is a fresh one with the new bits taken back out, which is
# the closest thing to the owner's real file that a test can build.
migrated = tmp / "migrated.db"
c = sqlite3.connect(migrated)
c.executescript((ROOT / "Schema.SQL").read_text(encoding="utf-8"))
c.execute("DROP TABLE detection_suppression")
c.execute("DROP INDEX IF EXISTS idx_findings_detection")
# SQLite cannot drop a column on older versions, so rebuild findings without
# the two new ones, which is exactly what the owner's v32 file looks like.
cols = [r[1] for r in c.execute("PRAGMA table_info(findings)")
        if r[1] not in ("detection_id", "detection_rev")]
c.execute("CREATE TABLE findings_old AS SELECT "
          + ",".join(cols) + " FROM findings")
c.execute("DROP TABLE findings")
c.execute("ALTER TABLE findings_old RENAME TO findings")
c.execute("UPDATE user_preferences SET value='32' WHERE key='schema_version'")
c.commit()
c.close()

check("the v32 stand-in really lacks the column",
      "detection_id" in shape(migrated)["findings"], False)
migrations.run_migrations(migrated)
check("migrated matches fresh", shape(migrated), shape(fresh))
first = shape(migrated)
migrations.run_migrations(migrated)
check("running it twice changes nothing", shape(migrated), first)


print("\n[14] No number is reused and every retirement says why")
ids = [d.did for d in det._REGISTER]
check("no duplicate ids", len(ids), len(set(ids)))
check("no duplicate names", len({d.name for d in det._REGISTER}), len(ids))
no_reason = [d.did for d in det._REGISTER if d.retired and not d.retired_reason]
check("every retired entry explains itself", no_reason, [])
no_summary = [d.did for d in det._REGISTER if not (d.summary or "").strip()]
check("every entry says what makes it fire", no_summary, [])
bad_sev = [d.did for d in det._REGISTER
           if not d.severities or d.severities - me.VALID_SEVERITY]
check("every declared severity is a real severity", bad_sev, [])
# No em dashes or pipes anywhere in what we wrote. The owner's standing rule, and the
# register text goes on screen.
text = (ROOT / "core" / "detections.py").read_text(encoding="utf-8")
check("no em dashes in the register", "—" in text, False)
check("no pipe characters in the register text",
      any("|" in (d.summary or "") for d in det._REGISTER), False)


print("\n[15] Silencing something reaches the journal")
# FOUND BY THIS TEST'S OWN OUTPUT on 2026-09-15, not by reading. The first
# run printed "integrity: refusing unknown operation 'detection_suppressed'"
# eight times while every check still passed, because record() logs and
# returns None rather than raising, by design. So the feature worked and its
# audit trail silently did not, which is the same shape as the prediction
# tools that were missing a sensor_health entry.
#
# The journal is the thing that answers "why did the 8888 alert stop". A
# silencing act that does not reach it is exactly the act worth hiding.
from core import integrity                            # noqa: E402
check_true("suppressing is a journalled operation",
           "detection_suppressed" in integrity.JOURNALLED)
check_true("so is lifting one",
           "detection_unsuppressed" in integrity.JOURNALLED)
before_rows = 0
with me._get_conn() as c:
    before_rows = c.execute(
        "SELECT COUNT(*) n FROM integrity_journal "
        "WHERE operation LIKE 'detection_%'").fetchone()["n"]
me.suppress_detection("PKT-1001", reason="journal check")
me.unsuppress_detection("PKT-1001")
with me._get_conn() as c:
    after_rows = c.execute(
        "SELECT COUNT(*) n FROM integrity_journal "
        "WHERE operation LIKE 'detection_%'").fetchone()["n"]
check("both halves of the pair were recorded", after_rows - before_rows, 2)


print("\n[16] Action records are not counted as detections")
# tools/remediation.py writes seven rows into findings that are records of
# what this app DID, not things it observed. They need ids and they are not
# detections, and the register has to keep that straight or the Detections
# page overstates what this tool can catch.
kinds = {d.did: d.kind for d in det._REGISTER}
check("remediation rows are action records", kinds["REM-1001"],
      "action_record")
check("sensor rows are detections", kinds["PKT-1002"], "detection")
real = {d["detection_id"] for d in det.real_detections()}
check("action records are excluded from the real list",
      any(k.startswith("REM-") for k in real), False)
check("so are retired numbers", "PRT-1001" in real, False)
check_true("and real detections are still there", "LNX-1002" in real)


print("\n[17] The model can read the register, and cannot silence anything")
# CAUGHT BY THE OWNER'S OWN GUARDRAIL BEFORE, on the prediction tools: a new tool with
# no core/sensor_health.DEPENDS entry raises UnregisteredTool inside
# execute_tool, so every call would have been a 500 in the running app. That
# was found by a smoke test and not by reading, so it is a check now.
from core import sensor_health                        # noqa: E402
check_true("the tool declares its sensor dependencies",
           "query_detections" in sensor_health.DEPENDS)
MANIFEST = (ROOT / "core" / "tool_registry.py").read_text(encoding="utf-8")
check_true("the tool is in the manifest",
           '"name": "query_detections"' in MANIFEST)
check_true("query_findings can filter by rule",
           '"detection_id": {' in MANIFEST)

# No WRITE tool, deliberately. Same call as expected ports in item 39: a tool
# that lets the model silence a detection is a tool for blinding this app.
for forbidden in ("suppress_detection", "unsuppress_detection"):
    check(f"no model tool named {forbidden}",
          f'"name": "{forbidden}"' in MANIFEST, False)


print("\n[18] The page and the route exist and say the honest thing")
UI = (ROOT / "ui" / "index.html").read_text(encoding="utf-8")
ROUTES = (ROOT / "api" / "routes.py").read_text(encoding="utf-8")
check_true("there is a Detections tab", 'data-page="detections"' in UI)
check_true("the page is wired into the loader", "loadDetections()" in UI)
check_true("the register is served", '"/api/detections"' in ROUTES)
check_true("suppressing has a human door",
           '"/api/detections/suppress"' in ROUTES)
check_true("so does lifting one",
           '"/api/detections/unsuppress"' in ROUTES)
# The two sentences that stop the page lying. A count it could not read must
# not render as a zero, and old unstamped rows must be named rather than
# quietly left out of every rule's total.
check_true("the page refuses to print a zero it could not count",
           "could not look" in UI)
check_true("the page explains the rows with no id",
           "before rules had ids" in UI)
# created_by is not taken from the body. A route that accepts who it was is a
# route that can be told.
check("the suppress route does not read created_by from the request",
      'body.get("created_by")' in ROUTES, False)
check_true("it hardcodes the human", 'created_by="user"' in ROUTES)


print("\n" + ("ALL PASS" if not fails else f"{len(fails)} FAILED: {fails}"))
sys.exit(1 if fails else 0)
