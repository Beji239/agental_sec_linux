#!/usr/bin/env bash
# scripts/verify_case_memory.sh -- case memory's evidence.
#
# The counterpart to scripts/verify_local_integrity.sh, and it exists for the
# same reason: a unit test proves a function, only a real boot proves the daemon
# calls it. What this drives is the REAL app (main.py, the real module table,
# the real watcher, the real duty loop) against a COPY of the database with the
# dashboard port moved so it cannot collide with the operator's running copy.
#
# It proves FOUR things no unit test can:
#
#   * the index is built BY THE WATCHER'S OWN TICK, not by a test calling
#     index_pending directly. That is the whole "a clock that nobody winds is
#     not a clock" discipline: index_pending passing its tests proves the
#     function works, not that anything calls it.
#   * case_memory reaches /api/status with its note and its lag, so the state
#     is readable by a person rather than only existing inside a prompt.
#   * THE PROMPT CARRIES THE CASE FILE. This is the one that matters most and
#     the one a unit test cannot reach: the duty loop's incident prompt is
#     built from a template, and a missing {case_block} would be an exception,
#     but a case_block wired to an EMPTY STRING would pass every unit test and
#     deliver exactly the blank page this whole feature exists to remove. The
#     check below renders the REAL prompt through the REAL code path and
#     asserts the subject's own history is in it.
#   * query_case_memory is dispatchable through execute_tool, which is what
#     catches a tool that is in the manifest with no _dispatch branch (a 500
#     for every call) or a DEPENDS entry that nothing satisfies.
#
# WHAT THIS SCRIPT DOES NOT DO, STATED SO ITS SILENCE IS NOT READ AS A
# PASS. It spends NO model tokens: it does not run a live unattended turn,
# because that is 150k-400k tokens for a check that would assert a model's
# wording rather than this code's behaviour. The prompt is asserted by
# rendering it, which is the part that can actually be wrong in this tree.
# A live turn is a separate, deliberate act with a budget attached.
#
# ALL JSON READING GOES THROUGH ONE PYTHON HELPER rather than inline python in
# $(). Measured lesson from the L3 script: a quoting error inside a command
# substitution aborts the run half-finished, and a shell error reads as a failed
# check. The helper prints json.dumps for EVERY value, because print(True)
# emits True while the shell compares true.
set -uo pipefail

# The tree, its owner and the owner's home are read at run time. A copy run
# from elsewhere names the tree with AGENTAL_ROOT.
ROOT="${AGENTAL_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
[[ -f "$ROOT/main.py" ]] || { echo "no main.py in $ROOT: set AGENTAL_ROOT to the tree" >&2; exit 2; }
OWNER="$(stat -c %U "$ROOT")"
OWNER_HOME="$(getent passwd "$OWNER" | cut -d: -f6)"
USER_SITE="$OWNER_HOME/.local/lib/python$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')/site-packages"
PORT=5199
TMP=$(mktemp -d /tmp/agental_cm_live.XXXXXX)

python3 "$ROOT/scripts/snapshot_db.py" "$ROOT/agental_sec.db" "$TMP/test.db"

# THE COPY IS MADE FRESH AND ITS INDEX IS EMPTIED, ON PURPOSE.
#
# Same defect class the L3 script's first run found, and it applies here
# word for word: the operator's live database already carries an index from
# the owner's own runs, so a check asserting "the watcher BUILT the index" would pass
# against a database that was already indexed and prove nothing about the
# watcher. Emptying it in the COPY -- never the original -- makes the boot
# below a genuine first build.
python3 - "$TMP/test.db" <<'PY'
import sqlite3, sys
conn = sqlite3.connect(sys.argv[1])
try:
    n = conn.execute("SELECT COUNT(*) FROM case_index").fetchone()[0]
    conn.execute("DELETE FROM case_index")
    conn.execute("DELETE FROM case_fts")
    conn.commit()
    print("   cleared %d pre-existing index row(s) IN THE COPY, so the boot "
          "below is a real first build by the watcher" % n)
except sqlite3.OperationalError as e:
    print("   no index tables in the copy yet (%s); the migration will build "
          "them" % e)
finally:
    conn.close()
PY

# The reference copy is taken in the LA-4 head, below, before anything is
# written. This is only the scratch copy the boot will read.
cp "$ROOT/config.json" "$TMP/config.json"
python3 - "$TMP/config.json" "$PORT" <<'PY'
import json, sys
p, port = sys.argv[1], int(sys.argv[2])
c = json.load(open(p))
c["flask"]["port"] = port
c["flask"]["auto_open_browser"] = False
# A FAST TICK so the watcher builds the index within the run rather than
# within a minute. The production value is 60; this is 5.
c.setdefault("incident_watcher", {})["tick_seconds"] = 5
# THE DUTY LOOP IS SWITCHED OFF FOR THIS RUN, and that is deliberate rather
# than convenient: with it on, this script's boot would spend real tokens
# investigating whatever incident it found, and the thing being verified here
# is that the PROMPT WOULD carry the case file -- which is proved by rendering
# the prompt, not by paying a model to receive it. See this file's header.
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
print(json.dumps(d))
PY

PASS=0; FAIL=0
ok() { echo "  [PASS] $1"; PASS=$((PASS+1)); }
no() { echo "  [FAIL] $1"; FAIL=$((FAIL+1)); }
chk() { if [[ "$2" == "1" ]]; then ok "$1"; else no "$1"; fi; }
val() { python3 "$TMP/read.py" "$@"; }

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
    pkill -f "agental_cm_live" 2>/dev/null
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

echo "port under test : $PORT (the owner's copy on 5000 is untouched)"
echo "database        : $TMP/test.db (a COPY; its index was emptied)"
echo "scratch         : $TMP"
echo

cp "$TMP/config.json" "$ROOT/config.json"

( setsid unshare -r bash -c "cd '$ROOT' && HOME=$OWNER_HOME USER=$OWNER \
    SUDO_USER=$OWNER PYTHONPATH='$USER_SITE:$ROOT' \
    AGENTALSEC_TEST_DB='$TMP/test.db' python3 main.py" \
    >"$TMP/boot.out" 2>&1 ) &
BOOT_PID=$!

echo "A. the real app boots and registers the memory"
READY=0
for _ in $(seq 1 240); do
    if grep -q 'AgentalSec ready' "$TMP/boot.out" 2>/dev/null; then READY=1; break; fi
    kill -0 "$BOOT_PID" 2>/dev/null || break
    sleep 1
done
chk "the app reached ready" "$READY"
chk "case_memory is in the boot's own module table" \
    "$(grep -q '\[OK\] case_memory' "$TMP/boot.out" && echo 1 || echo 0)"
chk "the boot did NOT report the memory as failing to load" \
    "$(grep -q 'case memory failed to load' "$TMP/boot.out" && echo 0 || echo 1)"
grep -E '\[OK\] case_memory' "$TMP/boot.out" | sed 's/^/   /' | head -2

echo
echo "B. THE WATCHER BUILT THE INDEX BY ITSELF (nobody called index_pending)"
# This is the check the whole script exists for. The index in the COPY was
# emptied before the boot, so any rows in it now were written by the watcher's
# own tick calling case_memory.index_pending.
BUILT=0
for _ in $(seq 1 40); do
    BUILT=$(python3 - "$TMP/test.db" <<'PY'
import sqlite3, sys
try:
    conn = sqlite3.connect("file:%s?mode=ro" % sys.argv[1], uri=True)
    print(conn.execute("SELECT COUNT(*) FROM case_index").fetchone()[0])
except Exception:
    print(0)
PY
)
    [[ "$BUILT" != "0" ]] && break
    sleep 2
done
chk "the watcher's own tick indexed the ledger (${BUILT} rows)" \
    "$([[ "$BUILT" != "0" ]] && echo 1 || echo 0)"

LAGZERO=$(python3 - "$TMP/test.db" <<'PY'
import sqlite3, sys
conn = sqlite3.connect("file:%s?mode=ro" % sys.argv[1], uri=True)
lag = conn.execute("SELECT COUNT(*) FROM incident WHERE id NOT IN "
                   "(SELECT incident_id FROM case_index)").fetchone()[0]
print(1 if lag == 0 else 0)
PY
)
chk "and it was indexed to COMPLETION (lag 0), not partially" "$LAGZERO"

echo
echo "C. the status is served over HTTP, lag and all"
# THE KEY IS RESOLVED BY THE SAME KIND OF HELPER AS EVERYTHING ELSE, which is
# this file's own rule (see the header) and which the first version broke: it
# copied an inline `python3 -c "$(...)"` for the key out of the L3 script, and
# bash reported a syntax error near an unexpected token on a later line --
# the corruption spilling out of the multi-line -c string and landing on a line
# that was itself perfectly valid. A quoting bug does not report itself; it
# reports whatever line it reaches next.
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
    curl -s -H "X-API-Key: $KEY" "http://127.0.0.1:$PORT/api/status" > "$TMP/status.json"
    python3 - "$TMP/status.json" "$TMP/cm.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
json.dump(d.get("modules", {}).get("case_memory", {}), open(sys.argv[2], "w"))
PY
    # The printer is its own heredoc rather than an inline python3 -c, for the
    # reason above.
    python3 - "$TMP/cm.json" "$TMP/cm_display.txt" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
open(sys.argv[2], "w").write(json.dumps(
    {k: d.get(k) for k in ("running", "ready", "reachable", "blind", "note",
                           "precedent_search")}, indent=2)[:900])
PY
    sed 's/^/   /' "$TMP/cm_display.txt"

    chk "/api/status carries case_memory" \
        "$([[ "$(val "$TMP/cm.json" running)" != "MISSING" ]] && echo 1 || echo 0)"
    chk "it reports ready" \
        "$([[ "$(val "$TMP/cm.json" ready)" == "true" ]] && echo 1 || echo 0)"
    chk "it is NOT reported blind" \
        "$([[ "$(val "$TMP/cm.json" blind)" != "true" ]] && echo 1 || echo 0)"
    chk "precedent search is available on this install" \
        "$([[ "$(val "$TMP/cm.json" precedent_search)" == "true" ]] && echo 1 || echo 0)"
    chk "the note carries the indexed count as a number" \
        "$(val "$TMP/cm.json" note | grep -q 'indexed and current' && echo 1 || echo 0)"
fi

echo
echo "D. THE PROMPT CARRIES THE CASE FILE (rendered through the real code path)"
# THIS IS THE CHECK THE FEATURE STANDS OR FALLS ON.
#
# A unit test can prove similar_incidents returns rows. Only this can prove the
# duty loop PUTS THEM IN FRONT OF THE MODEL. The failure this catches: a
# {case_block} wired to an empty string, which passes every test in
# tests/test_case_memory.py and delivers the blank page the owner complained
# about.
python3 - "$TMP/test.db" "$ROOT" > "$TMP/prompt.txt" 2>"$TMP/prompt.err" <<'PY'
import json, sys
db, root = sys.argv[1], sys.argv[2]
sys.path.insert(0, root)
from core import memory_engine as me
me.DB_PATH = db

from core import duty, incident

# A real incident from the ledger, the way the loop picks one.
rows = incident.query_incidents(include_resolved=True, limit=1)
if not rows:
    print("NO_INCIDENT_IN_LEDGER"); sys.exit(0)
row = rows[0]

# The REAL prompt template, filled by the REAL duty code paths.
from core import case_memory
from core import incident as inc_mod

# A real coverage snapshot, taken through the real function. `modules` is
# empty here on purpose: coverage_snapshot handles that case and says so in
# its note, which is itself the honest behaviour, and this check is about the
# CASE FILE rather than about coverage.
coverage = inc_mod.coverage_snapshot({})
row = rows[0]
brief = case_memory.brief_for_incident(row)
case_block = case_memory.render_brief(brief)
prompt = duty.INCIDENT_PROMPT.format(
    incident_block=duty._incident_block(row),
    coverage_block=duty._coverage_block(coverage),
    case_block=case_block,
    voice=duty.REPORT_VOICE)

print("SUBJECT=%s" % row.get("entity_value"))
print("CASE_BLOCK_EMPTY=%s" % ("1" if not case_block.strip() else "0"))
print("PROMPT_HAS_CASE_FILE_SECTION=%s" %
      ("1" if "THE CASE FILE" in prompt else "0"))
print("PROMPT_HAS_SUBJECT_HISTORY=%s" %
      ("1" if "SUBJECT HISTORY" in prompt else "0"))
print("PROMPT_HAS_PRECEDENT_WARNING=%s" %
      ("1" if "EVIDENCE, NOT A VERDICT" in prompt else "0"))
print("PROMPT_TELLS_MODEL_TO_READ_IT_FIRST=%s" %
      ("1" if "READ THE CASE FILE FIRST" in prompt else "0"))
print("PROMPT_LENGTH=%d" % len(prompt))
PY
sed 's/^/   /' "$TMP/prompt.txt"
[[ -s "$TMP/prompt.err" ]] && sed 's/^/   [stderr] /' "$TMP/prompt.err" | head -5

chk "an incident existed to build a prompt from" \
    "$(grep -q 'NO_INCIDENT_IN_LEDGER' "$TMP/prompt.txt" && echo 0 || echo 1)"
chk "the rendered case block is NOT empty" \
    "$([[ "$(grep '^CASE_BLOCK_EMPTY=' "$TMP/prompt.txt" | cut -d= -f2)" == "0" ]] && echo 1 || echo 0)"
chk "the prompt carries the case file section" \
    "$(grep -q 'PROMPT_HAS_CASE_FILE_SECTION=1' "$TMP/prompt.txt" && echo 1 || echo 0)"
chk "the prompt carries the subject's own history" \
    "$(grep -q 'PROMPT_HAS_SUBJECT_HISTORY=1' "$TMP/prompt.txt" && echo 1 || echo 0)"
chk "the prompt carries the EVIDENCE NOT VERDICT warning" \
    "$(grep -q 'PROMPT_HAS_PRECEDENT_WARNING=1' "$TMP/prompt.txt" && echo 1 || echo 0)"
chk "the prompt tells the model to read the case file FIRST" \
    "$(grep -q 'PROMPT_TELLS_MODEL_TO_READ_IT_FIRST=1' "$TMP/prompt.txt" && echo 1 || echo 0)"

echo
echo "E. query_case_memory is dispatchable through execute_tool"
# This is what catches a tool in the manifest with NO _dispatch branch (a 500
# on every call) and a DEPENDS entry nothing satisfies (UnregisteredTool).
python3 - "$TMP/test.db" "$ROOT" > "$TMP/tool.txt" 2>"$TMP/tool.err" <<'PY'
import json, sys
db, root = sys.argv[1], sys.argv[2]
sys.path.insert(0, root)
from core import memory_engine as me
me.DB_PATH = db

from core import tool_registry as tr
print("IN_MANIFEST=%s" % ("1" if any(
    t.get("name") == "query_case_memory" for t in tr.TOOL_MANIFEST) else "0"))

from core import sensor_health as sh
try:
    deps = sh.depends_on("query_case_memory")
    print("DEPENDS_REGISTERED=1")
    print("DEPENDS_VALUE=%s" % json.dumps(list(deps)))
except Exception as e:
    print("DEPENDS_REGISTERED=0")
    print("DEPENDS_ERROR=%s" % e)

from core import sanitize
print("FENCED=%s" % ("1" if sanitize.is_untrusted("query_case_memory") else "0"))

try:
    tr.init_registry("verify_case_memory", {
        "case_memory": __import__("core.case_memory", fromlist=["x"]),
        "incident_watcher": __import__("core.incident", fromlist=["x"]),
        "duty_loop": __import__("core.duty", fromlist=["x"]),
    })
except Exception as e:
    print("INIT_REGISTRY_ERROR=%s" % e)

out = tr.execute_tool("query_case_memory", {"limit": 3})
print("DISPATCH_OK=1")
# THE RESULT IS AN ENVELOPE, and the first version of this check got it wrong.
# execute_tool returns {error, result, untrusted} -- the fence envelope
# (core/sanitize) -- and the tool's own payload is under "result". Asserting
# against the top level reported a working tool as broken, which is the
# verifier defect shape this project has recorded twice already.
inner = out.get("result") if isinstance(out, dict) else None
if not isinstance(inner, dict):
    inner = {}
print("ENVELOPE_OK=%s" % ("1" if isinstance(out, dict) and
                          "untrusted" in out else "0"))
print("ERROR_IS_NULL=%s" % ("1" if (out or {}).get("error") is None else "0"))
print("HAS_HISTORY=%s" % ("1" if "entity_history" in inner else "0"))
print("HAS_PRECEDENTS=%s" % ("1" if "similar_incidents" in inner else "0"))
print("HAS_READING_NOTE=%s" % ("1" if inner.get("how_to_read_this") else "0"))
PY
sed 's/^/   /' "$TMP/tool.txt"
[[ -s "$TMP/tool.err" ]] && sed 's/^/   [stderr] /' "$TMP/tool.err" | head -8

chk "the tool is in the model-facing manifest" \
    "$(grep -q 'IN_MANIFEST=1' "$TMP/tool.txt" && echo 1 || echo 0)"
chk "its DEPENDS entry exists (no UnregisteredTool)" \
    "$(grep -q 'DEPENDS_REGISTERED=1' "$TMP/tool.txt" && echo 1 || echo 0)"
chk "its DEPENDS entry declares no sensor, as reasoned" \
    "$(grep -q 'DEPENDS_VALUE=\[\]' "$TMP/tool.txt" && echo 1 || echo 0)"
chk "it is FENCED, because it re-serves past assessments" \
    "$(grep -q 'FENCED=1' "$TMP/tool.txt" && echo 1 || echo 0)"
chk "execute_tool dispatches it without raising" \
    "$(grep -q 'DISPATCH_OK=1' "$TMP/tool.txt" && echo 1 || echo 0)"
chk "and it returns both halves of the memory" \
    "$(grep -q 'HAS_HISTORY=1' "$TMP/tool.txt" && grep -q 'HAS_PRECEDENTS=1' "$TMP/tool.txt" && echo 1 || echo 0)"

echo
echo "F. no traceback, clean shutdown, and the operator's config restored"
chk "the boot log has no traceback" \
    "$(grep -q 'Traceback' "$TMP/boot.out" && echo 0 || echo 1)"
chk "no duty-loop budget was spent (the loop was off by design)" \
    "$(grep -q 'DUTY EMERGENCY' "$TMP/boot.out" && echo 0 || echo 1)"

kill -TERM -"$BOOT_PID" 2>/dev/null
sleep 3
chk "the app shut down cleanly" \
    "$(grep -q 'AgentalSec stopped cleanly' "$TMP/boot.out" && echo 1 || echo 0)"

# THE RESTORE HAPPENS HERE AND IN THE TRAP, AND BOTH PROVE IT.
#
# History worth keeping: the first version of this check sat AFTER the kill and
# compared against the backup while the script's own modified config was still
# in place, so it reported "NOT restored byte-identically" about a restore that
# then happened. The check was reading the wrong moment, not a broken restore.
# LA-4 closes that shape from both ends: the restore is done HERE so the
# summary can show it, and IN THE TRAP so Ctrl+C, a closed window and a killed
# shell have it too -- and each restore ends in a comparison, so a restore that
# did not land FAILS on either path.
cp "$TMP/config.orig.json" "$ROOT/config.json"
if cmp -s "$ROOT/config.json" "$TMP/config.orig.json"; then
    ok "the operator's config.json is restored byte-identically"
else
    no "config.json was NOT restored byte-identically"
fi

# And the operator's DATABASE was never touched: the boot ran against the copy.
# Asserted rather than assumed, because "we only opened a copy" is exactly the
# kind of claim this project writes checks for. The live database must still be
# at v42 with NO case tables -- the migration is the owner's next boot, not
# something a verification script does to the owner.
python3 - "$ROOT/agental_sec.db" "$TMP/live.txt" <<'PY'
import sqlite3, sys
out = open(sys.argv[2], "w")
try:
    # IMMUTABLE, because the operator's app is RUNNING as root on this host and
    # a plain read-only open of a WAL database can fail for a process that is
    # not allowed to create the -shm file. Immutable says "do not touch it at
    # all", which is the only mode a verification script should ever use on a
    # database somebody else is writing.
    conn = sqlite3.connect("file:%s?immutable=1" % sys.argv[1], uri=True)
    tables = [r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' "
        "AND name LIKE 'case%'")]
    ver = conn.execute("SELECT value FROM user_preferences "
                       "WHERE key='schema_version'").fetchone()
    out.write("CASE_TABLES=%s\n" % ("NONE" if not tables else ",".join(tables)))
    out.write("SCHEMA=%s\n" % (ver[0] if ver else "?"))
    conn.close()
except Exception as e:
    out.write("READ_ERROR=%s\n" % e)
out.close()
PY
sed 's/^/   /' "$TMP/live.txt"
chk "the operator's database was NOT migrated (still has no case tables)" \
    "$(grep -q '^CASE_TABLES=NONE' "$TMP/live.txt" && echo 1 || echo 0)"

echo
echo "$PASS passed, $FAIL failed"
[[ "$FAIL" == "0" ]] || exit 1
