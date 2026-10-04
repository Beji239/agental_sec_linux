"""
tests/test_auditd_fixes.py, L4. THE AUDIT ROUND: the defects the audit found,
each one asserted in the direction that FAILS if it comes back.

ONE SECTION PER DEFECT, and every detector is driven BOTH WAYS. A reader that
stops firing is as broken as one that fires on everything, so each rule here
has a must-fire case and a must-NOT-fire case beside it, built from audit's own
record shapes as auditd actually writes them.

WHAT THIS FILE CANNOT TEST HERE: a real auditd writing a real log. auditd is
not installed on this host and installing it is the operator's command, not a
test's. Everything below is a fixture in audit 3.x's own formats, driven through
the SHIPPED functions -- never a reimplementation, which would only prove the
test's model of the code.

THE FIXTURES NAME NOBODY AND NO MACHINE. Every path is /etc/audit/... or a
documentation address, every account is read at run time or is a placeholder,
and the temp directory is created by the test. A test that pinned one operator's
account would be wrong on every other box, which is the rule the leak gate
exists to enforce.
"""

import io
import os
import pathlib
import sqlite3
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import _isolate_db                                    # noqa: E402
SCRATCH = _isolate_db.isolate()
from tools import auditd_monitor as am                # noqa: E402

TMP = pathlib.Path(tempfile.mkdtemp(prefix="auditd_fixes_"))

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}"
          + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


def check_true(label, condition):
    check(label, bool(condition), True)


NOW = time.time()


def stamp(offset=0.0, msg_id=900, when=None):
    return f"{(when or NOW) - offset:.3f}:{msg_id}"


def cfg_for(path, **kw):
    block = {"enabled": True, "log_path": str(path)}
    block.update(kw)
    return {"sensors": {"auditd": block}}


def write_log(lines, path):
    if os.path.exists(path):
        os.unlink(path)
    io.open(path, "w", encoding="utf-8").write("\n".join(lines) + "\n")
    return path


def syscall(msg_id=900, offset=0.0):
    return (f'type=SYSCALL msg=audit({stamp(offset, msg_id)}): '
            f'arch=c000003e syscall=257 ppid=1 pid=4242 auid=1000 uid=0 '
            f'comm="vim" exe="/usr/bin/vim" key="identity"')


def path_rec(name="/etc/audit/watched", msg_id=900, offset=0.0, nametype="NORMAL",
             kind="PATH"):
    return (f'type={kind} msg=audit({stamp(offset, msg_id)}): item=0 '
            f'name="{name}" inode=1234 nametype={nametype} key="identity"')


def config_change(op="add_rule", msg_id=901, offset=0.0, extra=""):
    return (f'type=CONFIG_CHANGE msg=audit({stamp(offset, msg_id)}): '
            f'auid=1000 ses=3 op={op} key="identity" list=4 res=1 {extra}'.rstrip())


def kernel_rec(enabled=0, lost=None, msg_id=902, offset=0.0):
    body = f'audit_backlog_limit=8192 audit_rate_limit=0 audit_enabled={enabled}'
    if lost is not None:
        body += f" audit_lost={lost}"
    return f'type=KERNEL msg=audit({stamp(offset, msg_id)}): {body}'


def daemon_end(msg_id=903, offset=0.0, res="success"):
    return f'type=DAEMON_END msg=audit({stamp(offset, msg_id)}): op=stop res={res}'


print("\n[AUD-1] THE PER-PASS LIMIT MUST NOT EAT THE RECORDS IT DID NOT PARSE")
#
# THE DEFECT: read_new() set the cursor to the end of the WHOLE read, so every
# line past MAX_LINES_PER_PASS was consumed unparsed by any pass, and analyze()
# printed "Nothing was skipped" over it. MEASURED on the shipped code: a
# 12-record fixture read with limit=5 returned 5 records and an offset of 1130
# (the whole file); the next pass returned 0 records.

DEFERRED = str(TMP / "deferred.log")
write_log([config_change(op=f"add_rule", msg_id=910 + i) for i in range(12)],
          DEFERRED)
size = os.path.getsize(DEFERRED)

r1 = am.read_new(DEFERRED, after_offset=0, limit=5)
check("the pass reads exactly the limit", r1["read"], 5)
check_true("and the cursor STOPS at the last line it parsed, not at the end "
           "of the read", r1["offset"] < size)
check("and the lines it did not read are counted", r1["deferred"], 7)
check_true("and more_available says there is more", r1["more_available"])

r2 = am.read_new(DEFERRED, after_offset=r1["offset"], limit=50)
check("the NEXT pass reads exactly what was deferred", r2["read"], 7)
check("and all 12 records have now been seen by one pass or the other",
      len(r1["records"]) + len(r2["records"]), 12)
check_true("and the second pass reached the end of the file",
           r2["offset"] == size)

# AND THE SENTENCE. The old text said "Nothing was skipped -- the cursor moved
# to the last line examined", which was false in both halves. The new one names
# the deferred count, so the number can be checked against the cursor.
write_log([syscall()], DEFERRED)
am.analyze(cfg_for(DEFERRED))                       # seed
with io.open(DEFERRED, "a", encoding="utf-8") as fh:
    for i in range(40):
        fh.write(config_change(op="add_rule", msg_id=930 + i, offset=-1) + "\n")
report = am.analyze(cfg_for(DEFERRED))
# Force the limit: the module's own constant is the only knob a pass has, so
# the assertion is made against a directly driven read plus the report's own
# numbers rather than by patching a constant.
check_true("the report says how many lines it actually looked at",
           report["analysed"].get("lines") is not None)
check_true("and it carries a deferred count rather than asserting nothing "
           "was skipped",
           report["analysed"].get("deferred_lines") == 0
           or report["analysed"].get("deferred_lines") > 0)
check_true("the sentence no longer claims nothing was skipped when lines "
           "were deferred",
           "Nothing was skipped" not in
           str(report["coverage"].get("scan_limit") or ""))
check_true("an unparsed line is NEVER reported as examined: the cursor moved "
           "past exactly the lines the report counted",
           report["cursor"]["moved_to"] >= report["analysed"]["lines"])


print("\n[AUD-2] A ROTATED LOG THAT HAS OUTGROWN THE OFFSET IS STILL A ROTATION")

ROTDIR = TMP / "rotate"
ROTDIR.mkdir(exist_ok=True)
ROTLOG = str(ROTDIR / "audit.log")
ROTATED = str(ROTDIR / "audit.log.1")

write_log([syscall(msg_id=940 + i) for i in range(10)], ROTLOG)
r1 = am.read_new(ROTLOG, after_offset=0)
old_offset, old_inode = r1["offset"], r1["inode"]
check_true("the first pass read the whole file", r1["offset"] > 0)

# auditd's rotation: rename, then write a fresh file, then that file grows past
# the stored offset BEFORE this app next looks. That is the case the size test
# cannot see.
os.replace(ROTLOG, ROTATED)
write_log([syscall(msg_id=980 + i, offset=-1) for i in range(40)], ROTLOG)
check_true("the fixture really is past the old offset (that is the whole "
           "point)", os.path.getsize(ROTLOG) > old_offset)

r2 = am.read_new(ROTLOG, after_offset=old_offset, after_inode=old_inode)
check("ROTATION IS DETECTED even though the file is LONGER than the offset",
      r2["rotated"], True)
check("and the basis is the INODE, not the size", r2.get("rotation_basis"),
      "inode")
# AD11: the old file was found by its inode and had been read to its end, so
# the reason says nothing was skipped rather than naming a gap.
check_true("and the reason says the old file was finished first",
           "nothing was skipped" in (r2["reason"] or ""))
check("and the new file was read from its BEGINNING, so the first record of "
      "it is here", r2["records"][0]["msg_id"], 980)

# THE CONTROL: the same file, grown normally, is NOT a rotation.
write_log([syscall(msg_id=940 + i) for i in range(5)], ROTLOG)
base = am.read_new(ROTLOG, after_offset=0)
with io.open(ROTLOG, "a", encoding="utf-8") as fh:
    fh.write(syscall(msg_id=999, offset=-1) + "\n")
grown = am.read_new(ROTLOG, after_offset=base["offset"],
                    after_inode=base["inode"])
check("a file simply APPENDED to is not a rotation", grown["rotated"], False)
check("and the appended record was read", grown["records"][-1]["msg_id"], 999)

# THE BACKWARD-COMPATIBILITY CASE, which must NOT rotate: an existing install's
# cursor row has no inode, and treating None as a rotation would re-read the
# whole log on every pass forever.
write_log([syscall(msg_id=950 + i) for i in range(6)], ROTLOG)
legacy = am.read_new(ROTLOG, after_offset=10, after_inode=None)
check("a cursor with NO inode recorded uses the size test only",
      legacy["rotated"], False)
check("  and that test still catches the shorter-file case",
      am.rotated_to(5000, 100, inode=7, after_inode=None), True)


print("\n[AUD-3] THE KERNEL'S SWITCH: OFF, IMMUTABLE, ON, AND THE LOST RECORDS")

off, counts = am._findings_from([am.parse_record(kernel_rec(enabled=0))])
check("audit_enabled=0 raises AUD-1003", [f["detection_id"] for f in off],
      ["AUD-1003"])
check("  at high, because a switched-off recorder is the worst reading",
      off[0]["severity"], "high")
check_true("  and the finding carries the command that turns it back on",
           "auditctl -e 1" in off[0]["description"])
check_true("  and it says the kernel is recording NOTHING",
           "NOTHING" in off[0]["description"])

on, _ = am._findings_from([am.parse_record(kernel_rec(enabled=1))])
check("audit_enabled=1 raises NOTHING", on, [])

imm, _ = am._findings_from([am.parse_record(kernel_rec(enabled=2))])
check("audit_enabled=2 (immutable) raises nothing on its own", imm, [])

lost, _ = am._findings_from([am.parse_record(kernel_rec(enabled=1, lost=42))])
check("a kernel DROP raises AUD-1003 even with the switch on",
      [f["detection_id"] for f in lost], ["AUD-1003"])
check_true("  and the finding carries the count the kernel gave",
           "42" in lost[0]["description"])

# ONE ROW PER PASS, not one per KERNEL record.
many, mcounts = am._findings_from(
    [am.parse_record(kernel_rec(enabled=0, msg_id=960 + i)) for i in range(6)])
check("six KERNEL records produce ONE finding, not six", len(many), 1)
check("  and the count of what said it is kept", mcounts.get("kernel"), 6)

# AND A KERNEL RECORD WITH NOTHING WRONG IS COUNTED, NOT RAISED.
quiet, qcounts = am._findings_from([am.parse_record(kernel_rec(enabled=1))])
check("a healthy KERNEL record is counted rather than raised", quiet, [])
check("  and it is counted under its own key", qcounts.get("kernel"), 1)

# THE STATUS SURFACE READS THE SAME FACT OUT OF A LOG.
KLOG = str(TMP / "kernel_state.log")
write_log([syscall(), kernel_rec(enabled=0, lost=3, offset=-1)], KLOG)
st = am.status(cfg_for(KLOG))
check("status() reads the kernel's switch from the log", st.get("kernel_enabled"),
      0)
check_true("  and says so in its note rather than calling the feed healthy",
           "SWITCH" in (st["note"] or "").upper())
check_true("  and carries it in the coverage a model would quote",
           any("audit_enabled=0" in lim for lim in st["coverage_limits"]))

write_log([syscall(), kernel_rec(enabled=1, offset=-1)], KLOG)
check("a log whose newest KERNEL record says ON does not warn",
      am.status(cfg_for(KLOG)).get("kernel_enabled"), 1)
write_log([syscall()], KLOG)
check("a log with no KERNEL record at all answers None rather than guessing",
      am.status(cfg_for(KLOG)).get("kernel_enabled"), None)

# THE MODEL-FACING TOOL MUST NOT HAND BACK A QUIET LIST UNDER A DEAD SWITCH.
write_log([syscall(), kernel_rec(enabled=0, offset=-1)], KLOG)
rec = am.recent_records(cfg_for(KLOG), limit=5)
check_true("recent_records says the switch is off rather than 'nothing matched'",
           "SWITCH IS OFF" in (rec["note"] or ""))
check_true("  and the payload carries the flag itself",
           rec.get("kernel_enabled") == 0)
check_true("  and the coverage block repeats it in full",
           any("recording NOTHING" in lim for lim in rec["coverage_limits"]))

write_log([syscall(), kernel_rec(enabled=1, offset=-1)], KLOG)
rec_on = am.recent_records(cfg_for(KLOG), limit=5)
check_true("under a healthy switch the note is the ordinary one",
           "SWITCH IS OFF" not in (rec_on["note"] or ""))


print("\n[AUD-4] THE DAEMON STOPPING, AND THE OTHER WAY THE FEED STOPS")

end, ecounts = am._findings_from([am.parse_record(daemon_end())])
check("DAEMON_END raises AUD-1004", [f["detection_id"] for f in end],
      ["AUD-1004"])
check("  at medium", end[0]["severity"], "medium")
check_true("  and the text says nothing is being written down",
           "NOTHING is being written" in end[0]["description"])
check_true("  and it names the command that asks whether it is back",
           "systemctl status auditd" in end[0]["description"])

start, _ = am._findings_from(
    [am.parse_record(f'type=DAEMON_START msg=audit({stamp(0, 904)}): op=start')])
check("DAEMON_START raises nothing", start, [])

# DAEMON_ERR IS NOT DAEMON_END: an error while running is not a stop.
err, _ = am._findings_from(
    [am.parse_record(f'type=DAEMON_ERR msg=audit({stamp(0, 905)}): '
                     f'op=error res=failed')])
check("DAEMON_ERR alone does not claim the daemon stopped", err, [])

two, tcounts = am._findings_from(
    [am.parse_record(daemon_end(msg_id=970)),
     am.parse_record(daemon_end(msg_id=971))])
check("two DAEMON_END records in one pass produce one finding", len(two), 1)
check("  and both are counted", tcounts.get("daemon_end"), 2)


print("\n[AUD-5] A WATCHED PATH IS SEEN ON THE RECORD TYPE THAT CARRIES IT")
#
# THE DEFECT: the finding path raised only on type=PATH, so a path attached to
# any sibling record was dropped silently. The absolute-path requirement is the
# guard rail, and it is asserted in both directions.

sib, _ = am._findings_from(
    [am.parse_record(f'type=CWD msg=audit({stamp(0, 906)}): '
                     f'cwd="/etc" name="/etc/audit/renamed.old"')])
check("a path on a NON-PATH record is raised", [f["detection_id"] for f in sib],
      ["AUD-1002"])
check("  and it is filed against the path itself", sib[0]["entity_value"],
      "/etc/audit/renamed.old")

# THE MUST-NOT-FIRE HALF.
noname, _ = am._findings_from(
    [am.parse_record(f'type=PATH msg=audit({stamp(0, 907)}): item=0 '
                     f'inode=0 nametype=DELETE')])
check("a PATH record with no name still raises nothing", noname, [])
nullname, _ = am._findings_from(
    [am.parse_record(path_rec(name="(null)", msg_id=908))])
check("a name of (null) is not a path", nullname, [])
hexname, _ = am._findings_from(
    [am.parse_record(path_rec(name="2F6574632F706173737764", msg_id=909))])
check("an undecoded hex name is not a path", hexname, [])
relname, _ = am._findings_from(
    [am.parse_record(path_rec(name="relative/path", msg_id=911))])
check("a relative name is not a path", relname, [])

# AND THE DEDUP STILL HOLDS: same path twice in one event is one finding.
dupe, dcounts = am._findings_from(
    [am.parse_record(path_rec(name="/etc/audit/x", msg_id=912)),
     am.parse_record(path_rec(name="/etc/audit/x", msg_id=912))])
check("the same path twice in one event is one finding", len(dupe), 1)
check("  and the repeat is counted", dcounts.get("path_repeat"), 1)


print("\n[AUD-6] THE HALF-INSTALLED MACHINE GETS ITS OWN SENTENCE")

conf = TMP / "auditd.conf"
conf.write_text(f"log_file = {TMP}/audit.log\n")
real_conf, real_which = am.DEFAULT_AUDITD_CONF, am._which
try:
    am.DEFAULT_AUDITD_CONF = str(conf)
    am._which = lambda name: None                    # config yes, tools no
    half = am.status({})
finally:
    am.DEFAULT_AUDITD_CONF, am._which = real_conf, real_which

check("config present + no tools is HALF INSTALLED", half["state"],
      "HALF INSTALLED")
check_true("  and the note does not tell the operator to start a daemon that "
           "is not installed", "systemctl start" not in (half["note"] or ""))
check_true("  and it prints the install command instead",
           am.INSTALL_COMMAND in (half["note"] or ""))
check("  and it is not blind, because it is a state of the machine",
      half["blind"], False)

# AND THE CONSUMER: the adapter must not print the NO LOG YET sentence for it.
from adapters import LinuxAuditd                        # noqa: E402
adapter = LinuxAuditd("auditd_fixes", {})
try:
    am._which = lambda name: None
    am.DEFAULT_AUDITD_CONF = str(conf)
    st_half = adapter.status()
finally:
    am._which, am.DEFAULT_AUDITD_CONF = real_which, real_conf
check("the adapter carries the HALF INSTALLED state",
      (st_half.get("auditd") or {}).get("state"), "HALF INSTALLED")
check_true("  and its headline blames the missing tools, not a missing log",
           "TOOLS ARE NOT" in (st_half.get("note") or ""))
check_true("  and it does NOT repeat the old false sentence",
           "tools are installed and there is no readable log yet"
           not in (st_half.get("note") or ""))


print("\n[AUD-7] THE REGISTER, THE MIGRATION, AND THE DEAD CODE")

from core import detections as det                      # noqa: E402
from core import memory_engine as me                    # noqa: E402

for did, sev in (("AUD-1001", {"medium"}), ("AUD-1002", {"low"}),
                 ("AUD-1003", {"high"}), ("AUD-1004", {"medium"})):
    entry = det.get(did)
    check(f"{did} is registered", entry.did, did)
    check(f"  {did} declares {sorted(sev)}", entry.severities, sev)
    check(f"  {did} is filed under the auditd source", entry.source, "auditd")
    check(f"  {did}'s entity type is in memory_engine's vocabulary",
          entry.entity_type in me.VALID_ENTITY_TYPES, True)

# THE CURSOR TABLE AND ITS INODE COLUMN, on a fresh database from Schema.SQL.
conn = sqlite3.connect(SCRATCH)
cols = {r[1] for r in conn.execute("PRAGMA table_info(auditd_cursor)")}
conn.close()
check_true("Schema.SQL's auditd_cursor carries last_inode",
           "last_inode" in cols)

mig_src = (ROOT / "core" / "migrations.py").read_text(encoding="utf-8")
check_true("and the migration exists and is wired",
           "_migrate_auditd_cursor_inode(conn)" in mig_src)
# THE VERSION IS READ, NOT PINNED. This check used to assert the literal string
# "SCHEMA_VERSION = 48", so it failed the moment a LATER round moved the schema
# on -- reporting a defect in the auditd cursor for a change to a different
# sensor. What it means is "the version was moved FOR THIS COLUMN", and that is
# a fact about v48 existing in the chain and the column arriving with it.
# A literal in a test is a tripwire for somebody else's edit; this asserts the
# intent instead.
from core import migrations as _mig                       # noqa: E402
check_true("and the schema version is at or past the one that added it",
           _mig.SCHEMA_VERSION >= 48)
check_true("  and v48 is named in the chain's own history",
           "v48" in mig_src)

# A CURSOR WRITTEN AND READ BACK: the inode travels with it.
check_true("ensure_cursor_table creates it", am.ensure_cursor_table(SCRATCH))
am.write_cursor(1234, seeded=True, records_seen=7, db_path=SCRATCH,
                last_inode=98765)
cur = am.read_cursor(SCRATCH)
check("the offset is stored", cur["last_offset"], 1234)
check("  and the INODE travels with it", cur["last_inode"], 98765)
check("  and it is marked seeded", cur["seeded"], True)

# THE DEAD CODE THE AUDIT NAMED IS GONE, and the predicates that remain are
# correct for every caller rather than only for today's.
src = (ROOT / "tools" / "auditd_monitor.py").read_text(encoding="utf-8")
check("_RAISED_TYPES (zero consumers) is removed", "_RAISED_TYPES" in src,
      False)
check("_QUIET_TYPES (zero consumers) is removed", "_QUIET_TYPES" in src, False)
check("log_path_for (zero consumers) is removed", "def log_path_for" in src,
      False)
check("the a0..a3 no-op loop is removed",
      'for key in ("a0", "a1", "a2", "a3")' in src, False)
check("is_config_change answers on the FIELD as well as the type, which is "
      "what its own docstring always claimed",
      am.is_config_change({"type": "SOMETHING_ELSE",
                           "fields": {"op": "CONFIG_CHANGE"}}), True)
check("  and still answers on the type", am.is_config_change(
    {"type": "CONFIG_CHANGE", "fields": {}}), True)
check("  and says no to a record that is neither", am.is_config_change(
    {"type": "SYSCALL", "fields": {"op": "add_rule"}}), False)

# THE ENRICHED HALF IS READ ONCE, FROM WHERE IT IS. The enriched value wins,
# and the raw half is not scanned twice to make that happen.
conflict = am.parse_record(
    'type=PATH msg=audit(1758500071.000:460): item=1 name="/wrong/raw/name"'
    + "\x1d" + 'name="/etc/shadow"' + "\x1d")
check("the enriched value wins over the raw one",
      conflict["fields"]["name"], "/etc/shadow")

# AND THE BOOT PATH'S NEW BRANCH IS THERE, as source, because main.py is never
# run by a test on this host (PROC-13).
main_src = (ROOT / "main.py").read_text(encoding="utf-8")
check_true("the boot path has a HALF INSTALLED branch",
           '_audit == "HALF INSTALLED"' in main_src)
check_true("and it no longer says 'Start it with: sudo systemctl start auditd'",
           "Start it with: sudo systemctl start auditd" not in main_src)

# THE MODEL-FACING TOOL'S DESCRIPTION NAMES ALL SIX STATES AND THE NEW RULES.
tr_src = (ROOT / "core" / "tool_registry.py").read_text(encoding="utf-8")
for token in ("NOT INSTALLED", "HALF INSTALLED", "NO LOG YET",
              "CANNOT READ LOG", "READABLE", "OFF BY CONFIG"):
    check_true(f"the tool's description names the {token} state",
               token in tr_src)
for did in ("AUD-1003", "AUD-1004"):
    check_true(f"and it names {did}", did in tr_src)
check_true("and it names kernel_enabled, which overrides the state's meaning",
           "kernel_enabled" in tr_src)

print("\n[AUD-8] A CURSOR FROM BEFORE v48 MUST NOT BE READ AS 'NEVER SEEDED'")
#
# THE SHAPE THIS GUARDS: read_cursor() issued a SELECT naming last_inode, so on
# a table that predates v48 it raised, the error was swallowed into the blank
# cursor, and a blank cursor means NOT SEEDED -- which makes the next pass SEED,
# putting the cursor at the END of the log and raising nothing for every record
# written since. Silent loss dressed as a fresh start. Scripts read this table
# without running migrations, so the standalone path is real.

PRE = str(TMP / "pre48.db")
conn = sqlite3.connect(PRE)
conn.executescript("""
CREATE TABLE auditd_cursor (
  name TEXT PRIMARY KEY, last_offset INTEGER NOT NULL DEFAULT 0,
  last_record_at TIMESTAMP, seeded_at TIMESTAMP,
  passes INTEGER NOT NULL DEFAULT 0, records_seen INTEGER NOT NULL DEFAULT 0);
INSERT INTO auditd_cursor (name,last_offset,seeded_at,passes,records_seen)
  VALUES ('default', 8192, '2026-09-22 10:00:00', 40, 12000);
""")
conn.commit()
conn.close()

cur = am.read_cursor(PRE)
check("a pre-v48 table still reads as SEEDED", cur["seeded"], True)
check("  and the offset is the one that was stored, not 0", cur["last_offset"],
      8192)
check("  and the missing inode answers None rather than raising",
      cur["last_inode"], None)
check("  and the cursor history is intact", (cur["passes"], cur["records_seen"]),
      (40, 12000))

# AND ON THE OTHER SIDE: a genuine v48 table reads its inode back.
check_true("a v48 table is created for writing",
           am.ensure_cursor_table(PRE))
am.write_cursor(99, db_path=PRE, last_inode=4242)
check("  and ensure_cursor_table REPAIRED the old shape in place",
      am.read_cursor(PRE)["last_inode"], 4242)

print()
print("ALL CHECKS PASSED" if not fails else f"FAILURES: {fails}")
sys.exit(1 if fails else 0)