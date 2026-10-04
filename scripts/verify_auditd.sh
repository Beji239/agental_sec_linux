#!/usr/bin/env bash
# scripts/verify_auditd.sh -- L4's evidence.
#
# The counterpart to scripts/verify_local_integrity.sh, verify_ebpf_events.sh
# and verify_case_memory.sh, and it exists for the same reason: a unit test
# proves a function, only a REAL BOOT proves the daemon calls it.
#
# WHAT THIS PROVES THAT NO UNIT TEST CAN
#
#   * THE REAL APP BOOTS with the audit reader in its module table, and the
#     reader reaches /api/status -- so the state is readable by a person
#     rather than only existing inside a findings row.
#
#   * THE BOOT LOG NAMES THE ABSENCE. On this host auditd is not installed,
#     and the boot line has to say so with the one command rather than
#     leaving an empty findings list to be read as a quiet machine. That is
#     the owner's Q7 wording for this whole tier and it is asserted as a
#     literal, because it is a sentence the owner asked for.
#
#   * A REAL CHANGE IS RAISED, through the REAL adapter, the REAL register
#     and the REAL findings table. The script appends records to a fixture
#     log in auditd's own format, including the ENRICHED form that a parser
#     knowing only the raw form silently under-counts.
#
#   * THE FIRST PASS SEEDS BY ITSELF, on the reader's own clock, without
#     anything telling it to. A sensor that needed a poke to behave would
#     pass every unit test and shout on a real install.
#
#   * The cursor lives in the schema's own table (v45), so a machine that
#     installs auditd later does not also need a migration.
#
# WHY THE LIVE HALF SKIPS, AND WHY THAT SKIP IS THE POINT
#
# THERE IS NO LIVE HALF AND THE SKIP IS NOT A LIMITATION, it is the state of
# the machine this was written on. auditd is not installed here, so a fixture
# log is the ONLY honest subject: the real kernel feed is what this module
# reads, and there is not one. Pointing the reader at a fixture through the
# sensors.auditd.log_path override is exactly what that override exists for.
#
# SO THE CHEAP HALF IS THE WHOLE HALF, unlike the camera's verifier where
# three checks need root and are named individually. What would need root is
# `sudo apt install auditd`, which is the OWNER'S command and not this
# script's -- a verifier that installs a kernel audit daemon on the owner's machine
# to prove a reader works is a verifier that does too much.
#
# WHEN THE OWNER RUNS IT, this script gets a second, better subject for free: with
# auditd installed and its log at the default path, the reader picks it up
# with no configuration change, and the READABLE branch is exercised against
# a file the KERNEL is writing. That path is asserted here in the only way
# this host allows: by proving the reader follows auditd.conf when no
# override is set.
#
# THE OPERATOR'S THINGS ARE RESTORED AND ASSERTED
#
# config.json is modified for this run and restored, byte-identically, with
# the restore ASSERTED after it happens rather than assumed. The live
# database is never touched: the boot runs against a COPY, and the last check
# confirms the original is still at the schema version it was at before this
# script ran.
set -uo pipefail

# The tree, its owner and the owner's home are read at run time. A copy run
# from elsewhere names the tree with AGENTAL_ROOT.
ROOT="${AGENTAL_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
[[ -f "$ROOT/main.py" ]] || { echo "no main.py in $ROOT: set AGENTAL_ROOT to the tree" >&2; exit 2; }
OWNER="$(stat -c %U "$ROOT")"
OWNER_HOME="$(getent passwd "$OWNER" | cut -d: -f6)"
USER_SITE="$OWNER_HOME/.local/lib/python$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')/site-packages"
PORT=5217
TMP=$(mktemp -d /tmp/agental_auditd_live.XXXXXX)
FIXTURE="$TMP/audit.log"

echo "mode            : FIXTURE (no auditd on this host, and none will be"
echo "                  installed: that is the owner's command, not this"
echo "                  script's. See the header.)"
echo "port under test : $PORT (the owner's copy on 5000 is untouched)"
echo "fixture log     : $FIXTURE"
echo "scratch         : $TMP"
echo

PASS=0; FAIL=0; SKIP=0
ok()   { echo "  [PASS] $1"; PASS=$((PASS+1)); }
no()   { echo "  [FAIL] $1"; FAIL=$((FAIL+1)); }
skip() { echo "  [SKIP] $1"; SKIP=$((SKIP+1)); }
chk()  { if [[ "$2" == "1" ]]; then ok "$1"; else no "$1"; fi; }

# ONE READER FOR EVERY FLAG FILE, defined with the other helpers so no section
# can use it before it exists -- which is exactly what happened when these sat
# further down the file and section A lost seven checks to "flag: command not
# found". Nothing is `eval`-ed: see section B for the two defects that came of
# doing that (a shell error inside a check, and a flags file written to the
# wrong directory by a print redirect).
flag() { grep "^$1=" "$2" | cut -d= -f2-; }
flagA() { flag "$1" "$TMP/a.flags"; }
flagB() { flag "$1" "$TMP/b.flags"; }
flagC() { flag "$1" "$TMP/c.flags"; }

BOOT_PID=""

# LA-4: THE RESTORE AND ITS PROOF
# The residue rule, carried the way verify_launchers_live.sh carries it, so
# every script that swaps the operator's config.json does it the same way:
#
#   1. THE OWNER'S FILE IS THE REFERENCE, taken BEFORE anything is written. A
#      reference taken after the swap would be the swap.
#   2. A COPY THAT IS SECRETLY A LINK IS REFUSED. A scratch tree that hard-
#      links the project and then `cp`s a modified config over one of those
#      links writes THROUGH the link into the owner's real file (measured 2026-09-25:
#      nlink=4 on config.json and .env). `-ef` is the inode test.
#   3. THE RESTORE LIVES IN THE TRAP, so it runs on every exit path. MEASURED
#      on this host's bash 5.2.21, 2026-09-25: the trap runs on a plain exit,
#      on Ctrl+C, on SIGTERM and on a closed window; it does NOT run on
#      `kill -9`, the OOM killer or a power cut -- the one door left open,
#      named rather than implied. The INT/TERM/HUP traps are measured too: a
#      SIGINT that reaches the shell ALONE otherwise lets the script run on
#      to its end and exit 0, so an interrupted run would print its normal
#      summary and read green.
#   4. THE RESTORE IS PROVEN, and a failed proof KEEPS the copy and forces a
#      non-zero status. A script that cannot prove it put the owner's file back must
#      leave the material for putting it back by hand.
#   5. NOBODY CAN CLOSE THE kill -9 DOOR FROM INSIDE, and this file does not
#      pretend to. A run killed with no moment to run a trap leaves the
#      operator's file on that run's scratch port, and a later run cannot
#      tell THE OWNER'S bytes from a scratch copy's without risking an overwrite of
#      a setting the owner changed on purpose. The door is NAMED, not papered over.

# THE REFERENCE, taken before anything is written. This is the only place the
# operator's config.json is READ for restoration, and it happens before the
# swap; the trap is the only place it is written back.
cp "$ROOT/config.json" "$TMP/config.orig.json"

cleanup() {
    [[ -n "$BOOT_PID" ]] && kill -TERM -"$BOOT_PID" 2>/dev/null
    sleep 2
    pkill -f "agental_auditd_live" 2>/dev/null
    if [[ -f "$TMP/config.orig.json" ]]; then
        if ! cmp -s "$ROOT/config.json" "$TMP/config.orig.json"; then
            cp "$TMP/config.orig.json" "$ROOT/config.json"
            echo "  (the operator's config.json was put back by this script's trap)"
        fi
        if cmp -s "$ROOT/config.json" "$TMP/config.orig.json"; then
            rm -f "$TMP/config.orig.json"
        else
            echo "  *** THE OPERATOR'S config.json COULD NOT BE RESTORED ***"
            echo "  *** the copy is KEPT for a manual put-back: $TMP/config.orig.json"
            echo "  *** expected sha256: $(sha256sum "$TMP/config.orig.json" | cut -d' ' -f1)"
            echo "  *** current  sha256: $(sha256sum "$ROOT/config.json" 2>/dev/null | cut -d' ' -f1)"
            chown -R "$OWNER:$OWNER" "$TMP" 2>/dev/null
            exit 1
        fi
    fi
    chown -R "$OWNER:$OWNER" "$TMP" 2>/dev/null
    rm -rf "$TMP"
}
trap cleanup EXIT
# The signals a hand-run verifier meets, mapped to the exit codes a shell
# reports for them: 130 = 128+INT, 143 = 128+TERM, 129 = 128+HUP.
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

# LA-4: THE LINK CHECKS
# THEY SIT HERE, AFTER THE TRAPS AND BEFORE ANY WRITE TO THE OPERATOR'S FILE,
# and the order is measured rather than stylistic: earlier in this file they
# would be refusals that litter -- with no trap registered yet, `exit 2` leaves
# the scratch directory behind. Here the traps are registered, so a refusal
# cleans up after itself.
#
# BOTH TESTS ARE ABOUT LINKS, NOT BYTES, and both come from one measured
# condition (2026-09-25: nlink=4 on the operator's config.json and .env, four
# scratch trees each holding a second name for the owner's file):
#
#   1. THE SCRATCH COPY MUST NOT *BE* THE OWNER'S FILE. One inode with two names is
#      how a `cp` writes through a link: it opens the path and truncates the
#      inode, so the "copy" lands in the operator's file.
#   2. THE OWNER'S FILE MUST HAVE EXACTLY ONE NAME. If anything -- a scratch tree, an
#      old harness, a hand-made link -- holds another name for it, the swap
#      below writes the scratch config through THAT name too.
# A refusal names what it found and how to find the other name.
if [[ -e "$TMP/config.orig.json" && "$ROOT/config.json" -ef "$TMP/config.orig.json" ]]; then
    echo "REFUSING TO RUN: $TMP/config.orig.json is the SAME FILE as"
    echo "  $ROOT/config.json (one inode, two names). A run with that copy in"
    echo "  place would write into the operator's config through the link."
    # DROP THE SPARE NAME, NOT THE FILE: removing the scratch path removes one
    # link and leaves the operator's own file exactly where it was.
    rm -f "$TMP/config.orig.json"
    echo "  (the spare name has been dropped; the owner's file's own link count is the owner's)"
    exit 2
fi

LIVE_LINKS=$(stat -c %h "$ROOT/config.json" 2>/dev/null || echo 1)
if [[ "$LIVE_LINKS" != "1" ]]; then
    echo "REFUSING TO RUN: $ROOT/config.json has $LIVE_LINKS links, so a"
    echo "  second name for the operator's file exists somewhere. Swapping the"
    echo "  config would write the scratch values through THAT name too."
    echo "  Find the other name with:"
    echo "    find / -xdev -samefile $ROOT/config.json 2>/dev/null"
    exit 2
fi

# A. THE MODULE, ON THIS HOST, BEFORE ANY BOOT
echo "A. the module's answer about THIS machine, before anything is configured"

python3 - "$ROOT" > "$TMP/a.txt" 2>"$TMP/a.err" <<'PY'
import json, sys
sys.path.insert(0, sys.argv[1])
from tools import auditd_monitor as am
st = am.status({})
out = {
    "state": st.get("state"),
    "installed": st.get("installed"),
    "blind": st.get("blind"),
    "install_command": st.get("install_command"),
    "log_path": st.get("log_path"),
    "log_path_source": st.get("log_path_source"),
    "tools": st.get("tools_present"),
    "note": st.get("note"),
    "has_install_line": am.INSTALL_COMMAND in (
        (st.get("note") or "") + " ".join(st.get("coverage_limits") or [])),
}
print(json.dumps(out))
PY
sed 's/^/   /' "$TMP/a.txt"
grep -v DeprecationWarning "$TMP/a.err" | sed 's/^/   [stderr] /' | head -6

python3 - "$TMP/a.txt" "$TMP/a.flags" <<'PY' > /dev/null
import json, sys
d = json.load(open(sys.argv[1]))
f = {}
f["STATE_KNOWN"] = 1 if d.get("state") in (
    "NOT INSTALLED", "NO LOG YET", "CANNOT READ LOG", "READABLE",
    "OFF BY CONFIG") else 0
f["NOT_BLIND"] = 0 if d.get("blind") else 1
f["COMMAND"] = 1 if d.get("install_command") == "sudo apt install auditd" else 0
f["HAS_NOTE"] = 1 if d.get("note") else 0
f["SOURCE_NAMED"] = 1 if d.get("log_path_source") else 0
# ON A HOST WITH NO AUDITD THE ANSWER MUST NAME THE ABSENCE *AND* THE COMMAND.
# Both, not either: the state alone sends a reader looking for a package, and
# the command alone does not say why it is needed.
f["ABSENCE_SAYS_COMMAND"] = 1 if (
    d.get("state") != "NOT INSTALLED" or d.get("has_install_line")) else 0
with open(sys.argv[2], "w") as fh:
    for k, v in f.items():
        fh.write("%s=%s\n" % (k, v))
PY
flagA() { grep "^$1=" "$TMP/a.flags" | cut -d= -f2-; }

chk "the module reports this machine in one of the five known states" \
    "$(flagA STATE_KNOWN)"
chk "and it does NOT report blind for a machine with no auditd" \
    "$(flagA NOT_BLIND)"
chk "the one command is the literal the owner asked for" "$(flagA COMMAND)"
chk "the absence is accompanied by a sentence, not a bare flag" \
    "$(flagA HAS_NOTE)"
chk "and the log path says WHERE that path came from" "$(flagA SOURCE_NAMED)"
chk "the absent case names the install command in its own words" \
    "$(flagA ABSENCE_SAYS_COMMAND)"

if [[ "$(id -u)" == "0" ]]; then
    skip "the CANNOT READ LOG case (running as root, so mode 000 is readable)"
fi

# B. A FIXTURE LOG IN AUDIT'S OWN TWO FORMATS
echo
echo "B. a fixture log, written in BOTH of audit 3.x's formats"

python3 - "$FIXTURE" > "$TMP/b.txt" <<'PY'
import sys, time
now = time.time()
GS = "\x1d"
lines = [
    f'type=SYSCALL msg=audit({now:.3f}:100): arch=c000003e syscall=257 '
    f'success=yes exit=3 a0=1 a1=2 a2=3 a3=4 items=1 ppid=1 pid=4242 '
    f'auid=1000 uid=0 gid=0 euid=0 comm="vim" exe="/usr/bin/vim" '
    f'key="identity"',
    f'type=PATH msg=audit({now:.3f}:100): item=0 name="/etc/passwd" '
    f'inode=1234 dev=08:01 mode=0100644 ouid=0 ogid=0 rdev=00:00 '
    f'nametype=NORMAL',
    # THE ENRICHED FORM. A parser that knows only the raw form gets a
    # plausible SMALLER count from this and reports no error anywhere.
    (f'type=CONFIG_CHANGE msg=audit({now - 2:.3f}:101): auid=1000 ses=3 '
     f'op=add_rule' + GS + 'key="identity"' + GS + 'list="4"' + GS
     + 'res="yes"' + GS),
    # THE RECORD TYPES THAT SAY THE RECORDING STOPPED.
    #
    # THE KERNEL'S OWN SWITCH. auditctl -e 0 sets audit_enabled=0 and the
    # kernel then records nothing at all; -e 2 makes the rules immutable.
    # Nothing else in this app can read this fact, and an empty findings list
    # under it is the one wrong reading this tier exists to prevent.
    f'type=KERNEL msg=audit({now - 1:.3f}:102): audit_backlog_limit=8192 '
    f'audit_lost=0 audit_rate_limit=0 audit_enabled=1',
    # THE DAEMON STOPPING. A stop is not an error (DAEMON_ERR) and not the
    # end of the log, so a parser that knows only "quiet" cannot see it.
    f'type=DAEMON_END msg=audit({now - 1:.3f}:103): op=stop res=success',
]
open(sys.argv[1], "w", encoding="utf-8").write("\n".join(lines) + "\n")
print("wrote %d record(s), %d byte(s), 1 of them in the enriched format"
      % (len(lines), len("\n".join(lines)) + 1))
PY
sed 's/^/   /' "$TMP/b.txt"

python3 - "$ROOT" "$FIXTURE" "$TMP/b.flags" > /dev/null <<'PY'
import json, sys
sys.path.insert(0, sys.argv[1])
from tools import auditd_monitor as am
cfg = {"sensors": {"auditd": {"enabled": True, "log_path": sys.argv[2]}}}
r = am.recent_records(cfg)
f = {}
f["STATE"] = r.get("auditd_state")
f["COUNT"] = len(r.get("records") or [])
f["TYPES"] = json.dumps(r.get("counts_by_type") or {})
# THE RAW HALF AND THE ENRICHED HALF ARE BOTH PRESENT, which is the whole
# reason this verifier writes one of each.
f["HAS_RAW"] = 1 if (r.get("counts_by_type") or {}).get("PATH") else 0
f["HAS_ENRICHED"] = 1 if (r.get("counts_by_type") or {}).get(
    "CONFIG_CHANGE") else 0
# AND THE ENRICHED FIELDS WERE LIFTED, not just the record type. The raw half
# of that record carries `op`; only the enriched half carries `key`.
keys = [x["fields"].get("key") for x in (r.get("records") or [])]
f["ENRICHED_FIELDS_LIFTED"] = 1 if any(k == "identity" for k in keys) else 0
f["OVERRIDE_NAMED"] = 1 if "overrides" in (r.get("log_path_source") or "") else 0
# A CONFIGURED LOG ON A HOST WITH NO AUDITD CARRIES ITS WARNING.
f["WARNED"] = 1 if (r.get("log_path_warning")) else 0
# THE KERNEL'S OWN SWITCH IS IN THE PAYLOAD.
#
# The fixture's newest KERNEL record says audit_enabled=1, so the tool must
# answer 1 rather than None or 0: a reader that cannot tell "recording" from
# "turned off" hands back the same empty list for both.
f["KERNEL_ENABLED"] = r.get("kernel_enabled") if r.get("kernel_enabled") is not None else "NONE"
# AND THE TWO NEW RECORD TYPES ARE COUNTED, which is how a reader can see the
# pass looked at them at all.
f["HAS_KERNEL"] = 1 if (r.get("counts_by_type") or {}).get("KERNEL") else 0
f["HAS_DAEMON_END"] = 1 if (r.get("counts_by_type") or {}).get("DAEMON_END") else 0
# THE FLAGS ARE WRITTEN BY PYTHON, NOT PRINTED FOR `eval`. Two defects in one
# line, both paid for on this script's first run:
#
#   * `eval` on a line reading TYPES={"SYSCALL": 1, "PATH": 1} runs `1,` as a
#     COMMAND, so a shell error landed in the middle of the verification and
#     read as a failed check;
#   * `print(... > "$TMP/b.flags")` sent the file to the WRONG PLACE when the
#     python call's argv[0] was the project root, so the file was written
#     beside the project and every value in it was lost.
#
# So python writes the file it was TOLD to write, and the shell reads each
# value back by name instead of sourcing anything.
with open(sys.argv[3], "w") as fh:
    for k, v in f.items():
        fh.write("%s=%s\n" % (k, v))
PY
flagB() { flag "$1" "$TMP/b.flags"; }
sed 's/^/   /' "$TMP/b.flags"

chk "the fixture log is READABLE through the override" \
    "$([[ "$(flagB STATE)" == "READABLE" ]] && echo 1 || echo 0)"
chk "and all five records parsed" \
    "$([[ "$(flagB COUNT)" == "5" ]] && echo 1 || echo 0)"
chk "  the RAW format is represented in the counts" "$(flagB HAS_RAW)"
chk "  and the ENRICHED format is too" "$(flagB HAS_ENRICHED)"
chk "  and the enriched half's own FIELDS were lifted, not just its type" \
    "$(flagB ENRICHED_FIELDS_LIFTED)"
chk "the override is NAMED as the reason for the path" \
    "$(flagB OVERRIDE_NAMED)"
chk "and a configured log on a host with no auditd is WARNED about" \
    "$(flagB WARNED)"
chk "THE KERNEL'S OWN SWITCH is read out of the log, not guessed" \
    "$([[ "$(flagB KERNEL_ENABLED)" == "1" ]] && echo 1 || echo 0)"
chk "and a KERNEL record reaches the counts" "$(flagB HAS_KERNEL)"
chk "and so does a DAEMON_END record" "$(flagB HAS_DAEMON_END)"

# C. THE SCHEMA CARRIES THE CURSOR, SO A LATER INSTALL NEEDS NO MIGRATION
echo
echo "C. the cursor table is in the schema AND in the migration"

python3 - "$ROOT" > "$TMP/c.flags" <<'PY'
import pathlib, re, sqlite3, sys, tempfile
root = pathlib.Path(sys.argv[1])
f = {}
schema = (root / "Schema.SQL").read_text(encoding="utf-8")
f["IN_SCHEMA"] = 1 if "CREATE TABLE IF NOT EXISTS auditd_cursor" in schema else 0
f["COLUMNS_IN_SCHEMA"] = 1 if all(
    c in schema.split("CREATE TABLE IF NOT EXISTS auditd_cursor", 1)[1]
             .split(");", 1)[0]
    for c in ("last_offset", "last_inode", "last_record_at", "seeded_at",
              "passes", "records_seen")) else 0

mig = (root / "core" / "migrations.py").read_text(encoding="utf-8")
f["IN_MIGRATION"] = 1 if "def _migrate_auditd_cursor" in mig else 0
f["MIGRATION_WIRED"] = 1 if (
    "auditd_cursor_added    = _migrate_auditd_cursor(conn)" in mig) else 0
# v48: the cursor gained the file's identity. A byte offset cannot tell a
# rotated log from a grown one, so the column AND its migration are both
# required -- an install that gets one without the other is worse than neither.
f["INODE_IN_SCHEMA"] = 1 if "last_inode" in schema.split(
    "CREATE TABLE IF NOT EXISTS auditd_cursor", 1)[1].split(");", 1)[0] else 0
f["INODE_MIGRATION"] = 1 if "def _migrate_auditd_cursor_inode" in mig else 0
f["INODE_MIGRATION_WIRED"] = 1 if (
    "auditd_inode_added     = _migrate_auditd_cursor_inode(conn)" in mig) else 0
f["READER_READS_INODE"] = 1 if "last_inode" in (
    (root / "tools" / "auditd_monitor.py").read_text(encoding="utf-8")) else 0

# PARSED, NOT PINNED. A literal version number here would go red the moment
# an unrelated feature migrates, which is how two tests in this tree were
# already broken once.
m = re.search(r"SCHEMA_VERSION\s*=\s*(\d+)", mig)
f["SCHEMA_VERSION"] = int(m.group(1)) if m else 0

# AND THE TWO CONVERGE: a FRESH database built from Schema.SQL must have the
# table, or a new install and a migrated one differ on the one table the
# reader assumes exists.
tmp = tempfile.mktemp(suffix=".db")
conn = sqlite3.connect(tmp)
try:
    conn.executescript(schema)
    conn.commit()
    names = {r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    cols = {r[1] for r in conn.execute("PRAGMA table_info(auditd_cursor)")}
    f["FRESH_HAS_TABLE"] = 1 if "auditd_cursor" in names else 0
    f["FRESH_COLUMNS"] = 1 if {
        "name", "last_offset", "last_inode", "last_record_at", "seeded_at",
        "passes", "records_seen"} <= cols else 0
finally:
    conn.close()
    pathlib.Path(tmp).unlink(missing_ok=True)

print("\n".join("%s=%s" % (k, v) for k, v in f.items()))
PY
# ONE READER FOR EVERY FLAG FILE, defined at the top with the other helpers.
# Nothing is `eval`-ed here: see section B for the two defects that came of
# doing that.

sed 's/^/   /' "$TMP/c.flags"

chk "auditd_cursor is in Schema.SQL" "$(flagC IN_SCHEMA)"
chk "  with every column the reader writes" "$(flagC COLUMNS_IN_SCHEMA)"
chk "and the migration exists" "$(flagC IN_MIGRATION)"
chk "  and is wired into the runner" "$(flagC MIGRATION_WIRED)"
chk "the cursor carries the file's inode (v48)" "$(flagC INODE_IN_SCHEMA)"
chk "  and a migration adds it to an install that predates it" \
    "$(flagC INODE_MIGRATION)"
chk "    and that migration is wired" "$(flagC INODE_MIGRATION_WIRED)"
chk "  and the reader actually reads it" "$(flagC READER_READS_INODE)"
chk "a FRESH install gets the table without migrating" \
    "$(flagC FRESH_HAS_TABLE)"
chk "  with the same columns the migrated one has" "$(flagC FRESH_COLUMNS)"

# D. THE REAL APP BOOTS WITH THE READER, AGAINST A COPY
echo
echo "D. the real app boots with the reader in its module table"

cp "$ROOT/agental_sec.db" "$TMP/test.db"
# The reference copy was taken in the LA-4 head, above, before anything was
# written; this is only the scratch copy the boot will read.
cp "$ROOT/config.json" "$TMP/config.json"

python3 - "$TMP/config.json" "$PORT" "$FIXTURE" <<'PY'
import json, sys
p, port, fixture = sys.argv[1], int(sys.argv[2]), sys.argv[3]
c = json.load(open(p))
c["flask"]["port"] = port
c["flask"]["auto_open_browser"] = False
# THE READER POINTED AT THE FIXTURE, through the override the module
# documents. This is the ONLY way to exercise the reading half on a host with
# no auditd, and it is what that key exists for.
c.setdefault("sensors", {}).setdefault("auditd", {})
c["sensors"]["auditd"]["enabled"] = True
c["sensors"]["auditd"]["log_path"] = fixture
# A FAST POLL so a pass happens inside this run rather than within a minute.
c["sensors"]["auditd"]["poll_interval"] = 5
# THE DUTY LOOP IS OFF ON PURPOSE: it would spend real tokens investigating
# whatever this run trips, and what is being verified is the SENSOR.
c.setdefault("duty_loop", {})["enabled"] = False
json.dump(c, open(p, "w"), indent=2)
PY

cat > "$TMP/read.py" <<'PY'
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception as e:
    print("UNREADABLE", e); sys.exit(0)
for part in sys.argv[2].split("."):
    if isinstance(d, list):
        try:
            d = d[int(part)]
            continue
        except Exception:
            print("MISSING"); sys.exit(0)
    if not isinstance(d, dict) or part not in d:
        print("MISSING"); sys.exit(0)
    d = d[part]
# json.dumps for EVERY value: the shell compares against JSON's true/false,
# and Python prints True/False. That mismatch once failed five checks on a
# correct payload in this tree's own verifiers.
print(json.dumps(d))
PY
val() { python3 "$TMP/read.py" "$@"; }

cp "$TMP/config.json" "$ROOT/config.json"

( setsid unshare -r bash -c "cd '$ROOT' && HOME=$OWNER_HOME USER=$OWNER \
    SUDO_USER=$OWNER PYTHONPATH='$USER_SITE:$ROOT' \
    AGENTALSEC_TEST_DB='$TMP/test.db' python3 main.py" \
    >"$TMP/boot.out" 2>&1 ) &
BOOT_PID=$!

READY=0
for _ in $(seq 1 240); do
    if grep -q 'AgentalSec ready' "$TMP/boot.out" 2>/dev/null; then READY=1; break; fi
    kill -0 "$BOOT_PID" 2>/dev/null || break
    sleep 1
done
chk "the app reached ready" "$READY"
chk "auditd is in the boot's own module table" \
    "$(grep -q '\[OK\] auditd' "$TMP/boot.out" && echo 1 || echo 0)"
chk "the boot did NOT report it as failing to load" \
    "$(grep -q 'auditd did not load' "$TMP/boot.out" && echo 0 || echo 1)"
# THE BOOT LOG MUST NAME WHICH STATE IT FOUND, in words. "the reader is
# broken" and "this machine has no audit feed" are different sentences and
# the boot log is where that is decided.
chk "and it named the auditd state in words" \
    "$(grep -Eq 'auditd: (THE KERNEL AUDIT FEED IS NOT INSTALLED|the kernel audit feed is being read|the audit log is readable|the audit tools are installed|the audit log EXISTS|the audit reader is switched)' "$TMP/boot.out" && echo 1 || echo 0)"
grep -E 'auditd' "$TMP/boot.out" | sed 's/^/         /' | head -5

echo
echo "E. the reader analysed the fixture by itself, on its own clock"
CURSOR=0
for _ in $(seq 1 40); do
    CURSOR=$(python3 - "$TMP/test.db" <<'PY'
import sqlite3, sys
try:
    conn = sqlite3.connect("file:%s?mode=ro" % sys.argv[1], uri=True)
    print(conn.execute("SELECT COUNT(*) FROM auditd_cursor").fetchone()[0])
except Exception:
    print(0)
PY
)
    [[ "$CURSOR" != "0" ]] && break
    sleep 2
done
chk "the reader's own poll seeded its cursor (${CURSOR} row(s))" \
    "$([[ "$CURSOR" != "0" ]] && echo 1 || echo 0)"

SEEDED=$(python3 - "$TMP/test.db" <<'PY'
import sqlite3, sys
try:
    conn = sqlite3.connect("file:%s?mode=ro" % sys.argv[1], uri=True)
    row = conn.execute("SELECT seeded_at IS NOT NULL, last_offset "
                       "FROM auditd_cursor").fetchone()
    print("1" if row and row[0] else "0")
except Exception:
    print("0")
PY
)
chk "and marked it as SEEDED, which is what stops a first pass shouting" \
    "$SEEDED"

# THE CURSOR SITS AT THE END OF THE FILE, not at zero. An offset of zero is
# a different state from a cursor that has never been written, and the two
# must not be confused: zero would re-read the whole fixture next pass.
AT_END=$(python3 - "$TMP/test.db" "$FIXTURE" <<'PY'
import os, sqlite3, sys
try:
    conn = sqlite3.connect("file:%s?mode=ro" % sys.argv[1], uri=True)
    off = conn.execute("SELECT last_offset FROM auditd_cursor").fetchone()[0]
    print("1" if off == os.path.getsize(sys.argv[2]) else "0")
except Exception:
    print("0")
PY
)
chk "and the cursor sits at the END of the file, not at zero" "$AT_END"

# F. THE STATUS IS SERVED OVER HTTP, COVERAGE INCLUDED
echo
echo "F. the status is served over HTTP, the auditd state included"
python3 - "$ROOT" "$TMP/config.json" "$TMP/key.txt" <<'PY'
import json, pathlib, sys
root, cfg_path, out = sys.argv[1], sys.argv[2], sys.argv[3]
sys.path.insert(0, root)
from core import secret_store
cfg = json.load(open(cfg_path))
try:
    pathlib.Path(out).write_text(
        secret_store.resolve(cfg, pathlib.Path(root))["app_api_key"])
except Exception as e:
    pathlib.Path(out).write_text("")
    print("could not resolve the API key: %s" % e)
PY
KEY=$(cat "$TMP/key.txt" 2>/dev/null)

if [[ -z "$KEY" ]]; then
    no "could not resolve the API key from .env"
else
    sleep 2
    curl -s -H "X-API-Key: $KEY" "http://127.0.0.1:$PORT/api/status" \
        > "$TMP/status.json"
    python3 - "$TMP/status.json" "$TMP/au.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
json.dump(d.get("modules", {}).get("auditd", {}), open(sys.argv[2], "w"))
PY
    python3 - "$TMP/au.json" <<'PY' | sed 's/^/   /'
import json, sys
d = json.load(open(sys.argv[1]))
print(json.dumps({k: d.get(k) for k in
      ("running", "blind", "note", "auditd", "coverage_limits")},
      indent=2)[:1200])
PY

    chk "/api/status carries the auditd module" \
        "$([[ "$(val "$TMP/au.json" running)" != "MISSING" ]] && echo 1 || echo 0)"
    chk "its nested block carries the state string" \
        "$([[ "$(val "$TMP/au.json" auditd.state)" != "MISSING" ]] && echo 1 || echo 0)"
    chk "and the state is READABLE for the fixture" \
        "$([[ "$(val "$TMP/au.json" auditd.state)" == '"READABLE"' ]] && echo 1 || echo 0)"
    chk "its headline names the state rather than recomputing it" \
        "$(python3 - "$TMP/au.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
n = d.get("note") or ""
s = (d.get("auditd") or {}).get("state") or ""
print(1 if s and ("state: %s" % s) in n else 0)
PY
)"
    chk "and it is NOT reported blind" \
        "$([[ "$(val "$TMP/au.json" blind)" != "true" ]] && echo 1 || echo 0)"
    # THE HEADLINE, ON THE ONE SURFACE A PERSON LOOKS AT. It is READABLE and
    # recent and the audit userspace is not installed, so the sentence has to
    # be about the file rather than about a subsystem that does not exist.
    chk "the headline does NOT claim an uninstalled subsystem is recording" \
        "$(python3 - "$TMP/au.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
n = d.get("note") or ""
bad = "the audit subsystem is recording" in n
print(0 if bad else 1)
PY
)"
    chk "and the coverage block carries the warning about the configured path" \
        "$(python3 - "$TMP/au.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
print(1 if any("NOT being written by a running auditd" in x
               for x in (d.get("coverage_limits") or [])) else 0)
PY
)"
fi

# G. TRIP IT FOR REAL, THROUGH THE REAL ADAPTER
echo
echo "G. a change is raised through the real adapter, register and findings table"

python3 - "$TMP/test.db" "$ROOT" "$FIXTURE" > "$TMP/trip.txt" 2>"$TMP/trip.err" <<'PY'
import json, sys, time
db, root, fixture = sys.argv[1], sys.argv[2], sys.argv[3]
sys.path.insert(0, root)
from core import memory_engine as me
me.DB_PATH = db
from core import sensors as sn
sn.register_local()

now = time.time()
GS = "\x1d"
# A REALLY NEW CONFIG_CHANGE and A REALLY NEW WATCHED-PATH HIT, appended the
# way auditd appends: at the end of the file, after the cursor.
with open(fixture, "a", encoding="utf-8") as fh:
    fh.write(f'type=CONFIG_CHANGE msg=audit({now:.3f}:200): auid=1000 '
             f'ses=3 op=remove_rule' + GS + 'key="identity"' + GS
             + 'list="4"' + GS)
    fh.write("\n")
    fh.write(f'type=PATH msg=audit({now:.3f}:201): item=0 '
             f'name="/etc/sudoers" inode=99 dev=08:01 ouid=0 ogid=0'
             + GS + 'name="/etc/sudoers"' + GS + 'key="identity"' + GS)
    fh.write("\n")

from tools import auditd_monitor as am
cfg = {"sensors": {"auditd": {"enabled": True, "log_path": fixture,
                              "poll_interval": 5}}}
report = am.analyze(cfg, db_path=db)
ids = sorted({f["detection_id"] for f in report["findings"]})
print("RAISED_IDS=%s" % json.dumps(ids))
print("SEEDED=%s" % ("1" if report["seeded"] else "0"))
print("ANALYSED=%s" % json.dumps(report["analysed"]))
print("STATE=%s" % report["coverage"].get("auditd_state"))
print("ERROR=%s" % (report.get("error") or "none"))

# THE REAL ADAPTER WRITES THEM, through the real register and the real table.
import importlib
adapters = importlib.import_module("adapters")
ad = adapters.LinuxAuditd("verify_auditd", cfg)
ad._running = True
written = ad._emit_all(report["findings"])
print("WRITTEN=%s" % written)

rows = me.query_findings(limit=50)
mine = [r for r in rows if r.get("source") == "auditd"]
print("FINDINGS_IN_TABLE=%s" % len(mine))
for r in mine[:4]:
    print("  ROW %s %s %s" % (r.get("detection_id"), r.get("entity_type"),
                              r.get("entity_value")))
print("UNREGISTERED=%s" % json.dumps(ad._unregistered))
st = ad.status()
print("STATUS_BLIND=%s" % ("1" if st.get("blind") else "0"))
print("STATUS_STATE=%s" % (st.get("auditd") or {}).get("state"))
print("STATUS_NOTE=%s" % ((st.get("note") or ""))[:400])

# THE TOOL, over the same wiring, because a sensor that is right in its own
# file and not reachable from the app is the failure this project has paid
# for twice.
from core import tool_registry as tr
tr.init_registry("verify_auditd", {"auditd": ad})
out = tr.execute_tool("query_audit_events", {"record_type": "PATH", "limit": 5})
inner = out.get("result") if isinstance(out, dict) else {}
inner = inner if isinstance(inner, dict) else {}
print("TOOL_IN_MANIFEST=%s" % (
    "1" if any(t.get("name") == "query_audit_events"
               for t in tr.TOOL_MANIFEST) else "0"))
print("TOOL_ERROR_NULL=%s" % ("1" if (out or {}).get("error") is None else "0"))
print("TOOL_STATE=%s" % inner.get("auditd_state"))
print("TOOL_RECORDS=%s" % len(inner.get("records") or []))
print("TOOL_FENCED=%s" % ("1" if (out or {}).get("untrusted") else "0"))
PY
sed 's/^/   /' "$TMP/trip.txt"
[[ -s "$TMP/trip.err" ]] && grep -v DeprecationWarning "$TMP/trip.err" \
    | sed 's/^/   [stderr] /' | head -8

chk "the reader raised the audit-rule change (AUD-1001)" \
    "$(grep -q '"AUD-1001"' "$TMP/trip.txt" && echo 1 || echo 0)"
chk "and the watched-path hit (AUD-1002)" \
    "$(grep -q '"AUD-1002"' "$TMP/trip.txt" && echo 1 || echo 0)"
chk "the real adapter wrote them to the findings table" \
    "$(grep -q 'WRITTEN=[1-9]' "$TMP/trip.txt" && echo 1 || echo 0)"
chk "and NO id was refused as unregistered (no silent no-op)" \
    "$(grep -q 'UNREGISTERED={}' "$TMP/trip.txt" && echo 1 || echo 0)"
chk "the adapter's own status carries the state string" \
    "$(grep -q 'STATUS_STATE=READABLE' "$TMP/trip.txt" && echo 1 || echo 0)"
chk "and it is not blind, because a readable file is readable" \
    "$(grep -q 'STATUS_BLIND=0' "$TMP/trip.txt" && echo 1 || echo 0)"
# THE HEADLINE MUST NOT CLAIM A SUBSYSTEM IS RECORDING when the audit
# userspace is not installed. This is a fixture run, so nothing is recording,
# and the first version of this adapter said otherwise.
chk "and its headline does NOT claim the subsystem is recording" \
    "$(grep -q 'STATUS_NOTE=.*the audit subsystem is recording' "$TMP/trip.txt" && echo 0 || echo 1)"
chk "  because it says instead that the userspace is not installed" \
    "$(grep -q 'STATUS_NOTE=.*AUDIT USERSPACE IS NOT INSTALLED' "$TMP/trip.txt" && echo 1 || echo 0)"
chk "query_audit_events is in the manifest" \
    "$(grep -q 'TOOL_IN_MANIFEST=1' "$TMP/trip.txt" && echo 1 || echo 0)"
chk "and dispatches without raising" \
    "$(grep -q 'TOOL_ERROR_NULL=1' "$TMP/trip.txt" && echo 1 || echo 0)"
chk "and serves records with the state beside them" \
    "$(grep -q 'TOOL_STATE=READABLE' "$TMP/trip.txt" && echo 1 || echo 0)"
chk "and its output is FENCED, because the fields are attacker-chosen" \
    "$(grep -q 'TOOL_FENCED=1' "$TMP/trip.txt" && echo 1 || echo 0)"

# H. NO TRACEBACK, CLEAN SHUTDOWN, AND THE OPERATOR'S THINGS BACK
echo
echo "H. traceback, shutdown, and the operator's files"
chk "the boot log has no traceback" \
    "$(grep -q 'Traceback' "$TMP/boot.out" && echo 0 || echo 1)"

kill -TERM -"$BOOT_PID" 2>/dev/null
# A 15-SECOND GRACE, for the reason verify_ebpf_events.sh records: with three
# seconds the shutdown line had not been written yet and the check read the
# moment BEFORE the shutdown, reporting a clean shutdown as missing.
SHUT=0
for _ in $(seq 1 30); do
    if grep -q 'AgentalSec stopped cleanly' "$TMP/boot.out" 2>/dev/null; then
        SHUT=1; break
    fi
    sleep 1
done
chk "the app shut down cleanly" "$SHUT"

# THE RESTORE HAPPENS HERE SO THE SUMMARY CAN SHOW IT, AND IN THE TRAP SO
# EVERY EXIT PATH HAS IT. The trap's copy is the one that matters when this
# line is never reached -- Ctrl+C, a closed window, a killed shell -- and the
# trap PROVES its restore the same way this one does, by comparing bytes. Two
# restores of one file is deliberate: each is idempotent (the trap writes only
# when the file differs) and each ends in a comparison, so a restore that did
# not land FAILS on either path instead of reading as a silent success.
cp "$TMP/config.orig.json" "$ROOT/config.json"
if cmp -s "$ROOT/config.json" "$TMP/config.orig.json"; then
    ok "the operator's config.json is restored byte-identically"
else
    no "config.json was NOT restored byte-identically"
fi

# AND THE LIVE DATABASE WAS NEVER MIGRATED BY THIS SCRIPT. Asserted rather
# than assumed: "we only opened a copy" is exactly the kind of claim this
# project writes checks for.
python3 - "$ROOT/agental_sec.db" > "$TMP/live.txt" <<'PY'
import sqlite3, sys
try:
    conn = sqlite3.connect("file:%s?immutable=1" % sys.argv[1], uri=True)
    tables = [r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' "
        "AND name LIKE 'auditd%'")]
    ver = conn.execute("SELECT value FROM user_preferences "
                       "WHERE key='schema_version'").fetchone()
    print("LIVE_AUDITD_TABLES=%s" % ("NONE" if not tables
                                     else ",".join(tables)))
    print("LIVE_SCHEMA=%s" % (ver[0] if ver else "?"))
    conn.close()
except Exception as e:
    print("READ_ERROR=%s" % e)
PY
sed 's/^/   /' "$TMP/live.txt"

echo
echo "======================================================================"
echo "  $PASS passed, $FAIL failed, $SKIP skipped"
if [[ "$SKIP" != "0" ]]; then
    echo "  The $SKIP skipped check(s) are named above, not counted as green."
fi
if [[ $FAIL -gt 0 ]]; then
    echo "  FAILED. The scratch directory is removed on exit; re-run with"
    echo "  'bash -x $0' if you need to see where it stopped."
fi
echo "======================================================================"
exit $(( FAIL > 0 ? 1 : 0 ))
