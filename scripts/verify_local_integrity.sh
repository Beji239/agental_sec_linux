#!/usr/bin/env bash
# scripts/verify_local_integrity.sh, L3's evidence.
#
# The counterpart to scripts/verify_duty_live.sh, and it exists for the same
# reason: a unit test proves a function, only a real boot proves the daemon
# calls it. What this drives is the REAL app (main.py, the real module table,
# the real adapter) against a COPY of the database with the dashboard port
# moved so it cannot collide with the operator's running copy, then:
#
#   * checks the sensor LOADED and that its status is served over real HTTP
#   * trips a check FOR REAL, by adding a line to a key file, and reads the
#     finding back out of the API
#   * proves the setuid sweep runs and reports its coverage
#   * proves tier C, the dpkg verification, RUNS FOR REAL and seeds
#   * proves the read-only helper's state is reported in all three of its cases
#   * proves the metadata-only limit is STATED rather than implied
#   * puts the operator's config.json and authorized_keys back, verified
#
# IF THE OPERATOR'S OWN APP IS RUNNING, IT WILL ALSO SEE THE TRIP.
#
# THE TRIP IS REAL AND IT IS ON THE REAL MACHINE. This script appends a key to
# the OPERATOR's own ~/.ssh/authorized_keys, because that is the only way to
# prove the sensor notices a key being added. It puts the file back
# byte-identically, verified. But a second AgentalSec process watching the same
# host -- the owner's copy on port 5000 -- is watching the same file, on its own
# database, and it will correctly file its OWN LNX-2002 rows in THE OWNER'S database
# about a key that appeared and then vanished.
#
# MEASURED, 2026-09-22: exactly that happened. The owner's running app filed
# "SSH key added to ~/.ssh/authorized_keys" and then "SSH key
# removed" in the owner's database while this script was verifying against a copy.
#
# THAT IS NOT A LEAK AND IT IS NOT A FALSE FINDING: a key genuinely was added
# and genuinely was removed, and the owner's app reported it accurately. It is noise
# this script causes on a machine where a second copy is running, and the
# honest thing is to SAY SO HERE rather than let the owner find two unexplained SSH
# findings and wonder who touched the owner's key file. Stop the owner's copy first, or expect
# the two rows and dismiss them.
#
# TIER C IS DRIVEN OFF ITS PRODUCTION CADENCE HERE, and that is deliberate.
# In the app it runs every three hours after a five minute delay, because a
# full run MEASURED 209s on this host. This script asks for a short interval
# so the whole thing is observable in a few minutes. The numbers the checks
# assert on come from the T5_LOCAL_INTEGRITY measurement, not from this run.
#
# ALL THE JSON READING IS DONE BY ONE PYTHON HELPER rather than by inline
# python inside $( ). The first version of this file did the latter and died
# on an unmatched quote with the whole run half-finished, which is a fine
# demonstration of why a verification script should keep its parsing in one
# place: a shell error inside a check reads as a failed check.
set -uo pipefail

# The tree, its owner and the owner's home are read at run time. A copy run
# from elsewhere names the tree with AGENTAL_ROOT.
ROOT="${AGENTAL_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
[[ -f "$ROOT/main.py" ]] || { echo "no main.py in $ROOT: set AGENTAL_ROOT to the tree" >&2; exit 2; }
OWNER="$(stat -c %U "$ROOT")"
OWNER_HOME="$(getent passwd "$OWNER" | cut -d: -f6)"
USER_SITE="$OWNER_HOME/.local/lib/python$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')/site-packages"
PORT=5197
TMP=$(mktemp -d /tmp/agental_li_live.XXXXXX)
python3 "$ROOT/scripts/snapshot_db.py" "$ROOT/agental_sec.db" "$TMP/test.db"

# THE COPY IS MADE FRESH FOR THIS RUN, ON PURPOSE.
#
# THIS IS A DEFECT THIS SCRIPT'S OWN FIRST RUN FOUND. The operator's live
# database already carries tier A and tier B baselines from earlier work, so
# the check below -- "it seeded rather than shouting on the first look" --
# FAILED against a correct sensor, because there was nothing left to seed.
# A verifier that asserts a first-run behaviour against a database that has
# already had its first run reports the code as broken.
#
# So the baseline table is emptied IN THE COPY (never the original, which this
# script does not touch), which makes every tier a genuine first run: the file
# watch seeds, the sweep seeds, and the package verification seeds. That is
# the state a fresh install is in, and it is the state this script is about.
python3 - "$TMP/test.db" <<'PY'
import sqlite3, sys
conn = sqlite3.connect(sys.argv[1])
try:
    rows = conn.execute("SELECT name FROM local_integrity_baseline").fetchall()
    print("clearing %d pre-existing baseline(s) in the COPY so every tier "
          "seeds: %s" % (len(rows), ", ".join(r[0] for r in rows) or "none"))
    conn.execute("DELETE FROM local_integrity_baseline")
    conn.commit()
except sqlite3.OperationalError as e:
    print("no baseline table in the copy yet (%s); every tier will seed" % e)
finally:
    conn.close()
PY

cp "$ROOT/config.json" "$TMP/config.json"
python3 - "$TMP/config.json" "$PORT" <<'PY'
import json, sys
p, port = sys.argv[1], int(sys.argv[2])
c = json.load(open(p))
c["flask"]["port"] = port
c["flask"]["auto_open_browser"] = False
c.setdefault("sensors", {}).setdefault("local_integrity", {})
c["sensors"]["local_integrity"]["poll_interval"] = 5      # so a trip is seen
c["sensors"]["local_integrity"]["sweep_interval_seconds"] = 60
# TIER C, OFF ITS PRODUCTION CADENCE FOR THIS RUN ONLY. 300 is the code floor;
# the production value in config.json is 10800. The FIRST_DPKG_DELAY of 300s is
# still honoured by the adapter, which is why this script waits rather than
# expecting a run immediately -- and it is why the whole verification takes
# several minutes. See this file's header: the numbers asserted come from the
# measurement, not from a shortened run.
c["sensors"]["local_integrity"]["dpkg_interval_seconds"] = 600
c["sensors"]["local_integrity"]["dpkg_exclude_boot"] = True
# THE FIRST-RUN DELAY, off its 300s production value and onto its 30s FLOOR.
# The floor is enforced in the adapter, so a script cannot ask for a first run
# during the boot even by accident -- which is the property that makes this
# knob safe to have at all.
c["sensors"]["local_integrity"]["dpkg_first_delay_seconds"] = 30
json.dump(c, open(p, "w"), indent=2)
PY

# ONE reader, used by every check below. Takes a JSON file and a dotted path,
# prints the value or the word MISSING. Never raises.
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
# json.dumps for EVERY value, not just containers. The first version of this
# helper printed Python's True/False for a bool while the shell compared it
# against JSON's true/false, so five checks failed on a payload that was
# correct. A verifier with a parsing bug reports the code as broken.
print(json.dumps(d))
PY

# The finding probe: does a row with this detection id exist in the payload.
cat > "$TMP/probe.py" <<'PY'
import json, sys
path, did, field, want = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
d = json.load(open(path))
rows = d if isinstance(d, list) else (d.get("findings") or [])
hit = [r for r in rows if r.get("detection_id") == did]
if not hit:
    print("0"); sys.exit(0)
if want == "*":
    print("1"); sys.exit(0)
got = str(hit[0].get(field) or "")
print("1" if got.endswith(want) else "0")
PY

PASS=0; FAIL=0
ok() { echo "  [PASS] $1"; PASS=$((PASS+1)); }
no() { echo "  [FAIL] $1"; FAIL=$((FAIL+1)); }
chk() { if [[ "$2" == "1" ]]; then ok "$1"; else no "$1"; fi; }
val() { python3 "$TMP/read.py" "$@"; }

AK="$HOME/.ssh/authorized_keys"
cp "$AK" "$TMP/authorized_keys.orig"

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
    pkill -f "agental_li_live" 2>/dev/null
    # THE OPERATOR'S FILES GO BACK. authorized_keys is restored here as it was
    # before; the config restore carries the LA-4 proof below it.
    cp "$TMP/authorized_keys.orig" "$AK" 2>/dev/null
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
    # A FAILED RUN KEEPS ITS SCRATCH DIR. The epilogue below tells the reader
    # to inspect it, and an instruction that cannot be followed is worse than
    # none: the first version deleted the directory and then pointed at it.
    if [[ "${FAIL:-0}" -gt 0 ]]; then
        echo "  (scratch kept for inspection, see below)"
    else
        rm -rf "$TMP"
    fi
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
echo "database        : $TMP/test.db (a COPY)"
echo "scratch         : $TMP"
echo

# The reference copy was taken in the LA-4 head, above, before anything was
# written; this is only the swap that points the boot at the scratch copy.
cp "$TMP/config.json" "$ROOT/config.json"

( setsid unshare -r bash -c "cd '$ROOT' && HOME=$OWNER_HOME USER=$OWNER \
    SUDO_USER=$OWNER PYTHONPATH='$USER_SITE:$ROOT' \
    AGENTALSEC_TEST_DB='$TMP/test.db' python3 main.py" \
    >"$TMP/boot.out" 2>&1 ) &
BOOT_PID=$!

echo "A. the real app boots with the sensor in the module table"
READY=0
for _ in $(seq 1 240); do
    if grep -q 'AgentalSec ready' "$TMP/boot.out" 2>/dev/null; then READY=1; break; fi
    kill -0 "$BOOT_PID" 2>/dev/null || break
    sleep 1
done
chk "the app reached ready" "$READY"
chk "local_integrity loaded" \
    "$(grep -q '\[OK\] local_integrity' "$TMP/boot.out" && echo 1 || echo 0)"
chk "it says what it watches, in its own words" \
    "$(grep -q 'watching THIS host' "$TMP/boot.out" && echo 1 || echo 0)"
chk "and names the two clocks rather than one" \
    "$(grep -q 'Tier B, the setuid/setgid/capability sweep' "$TMP/boot.out" && echo 1 || echo 0)"
chk "it seeded rather than shouting on the first look" \
    "$(grep -q 'seeded the baseline' "$TMP/boot.out" && echo 1 || echo 0)"
grep -E '\[OK\] local_integrity|local_integrity: ' "$TMP/boot.out" \
    | sed 's/^/   /' | head -4

KEY=$(python3 -c "
import json,sys,pathlib
root = pathlib.Path('$ROOT')
sys.path.insert(0,str(root))
from core import secret_store
cfg = json.load(open('$TMP/config.json'))
print(secret_store.resolve(cfg, root)['app_api_key'])
" 2>/dev/null)

if [[ -z "$KEY" ]]; then
    no "could not resolve the API key from .env"
else
    echo
    echo "B. the status is served over HTTP, coverage included"
    sleep 3
    curl -s -H "X-API-Key: $KEY" "http://127.0.0.1:$PORT/api/status" > "$TMP/status.json"
    python3 - "$TMP/status.json" "$TMP/li.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
json.dump(d.get("modules", {}).get("local_integrity", {}), open(sys.argv[2], "w"))
PY
    cat "$TMP/li.json" | python3 -c "
import json,sys
d = json.load(sys.stdin)
print(json.dumps({k: d.get(k) for k in
      ('running','blind','files_metadata_only','coverage_limits',
       'scope_note')}, indent=2)[:900])" | sed 's/^/   /'

    chk "/api/status carries the module" \
        "$([[ "$(val "$TMP/li.json" running)" != "MISSING" ]] && echo 1 || echo 0)"
    chk "it reports running" \
        "$([[ "$(val "$TMP/li.json" running)" == "true" ]] && echo 1 || echo 0)"
    chk "it is NOT reported blind for the unelevated sudoers limit" \
        "$([[ "$(val "$TMP/li.json" blind)" == "false" ]] && echo 1 || echo 0)"
    chk "the metadata-only limit is STATED, and names /etc/sudoers" \
        "$(val "$TMP/li.json" files_metadata_only | grep -q sudoers && echo 1 || echo 0)"
    chk "and says a content edit leaving the metadata identical is NOT detected" \
        "$(val "$TMP/li.json" coverage_limits | grep -q 'NOT detected' && echo 1 || echo 0)"
    chk "it says which host it is talking about, so it is not confused with linux_monitor" \
        "$(val "$TMP/li.json" scope_note | grep -q 'NOT tools/linux_monitor' && echo 1 || echo 0)"

    echo
    echo "C. TRIP: a key is added to the operator's own authorized_keys"
    # THE TRIP IS CHECKED AGAINST A CLEARED FINDING ROW, AND THIS IS
    # THE SECOND DEFECT THIS SCRIPT'S OWN RUNS FOUND.
    #
    # The first version appended the trip key and waited for LNX-2002 to appear
    # over the API. It passed on the first run and FAILED on the second, and
    # the sensor was correct both times: `memory_engine.finding_already_open`
    # dedups on (source, entity_type, entity_value, title) ACROSS THE WHOLE
    # DATABASE and deliberately NOT per session -- TODO §90, built because 220
    # Defender findings re-raised on every boot. The database this script
    # copies already had an undismissed "SSH key added to
    # .../authorized_keys", so the second trip correctly wrote nothing.
    #
    # A verifier that trips the same entity twice and expects a row twice is
    # asserting that dedup does not work. So the fixture is cleared first --
    # IN THE COPY, never the operator's database -- and the assertion is about
    # what the trip produces, not about what the table already held.
    python3 - "$TMP/test.db" <<'PY'
import sqlite3, sys
conn = sqlite3.connect(sys.argv[1])
n = conn.execute(
    "SELECT COUNT(*) FROM findings WHERE detection_id LIKE 'LNX-200%'").fetchone()[0]
conn.execute("DELETE FROM findings WHERE detection_id LIKE 'LNX-200%'")
conn.commit()
conn.close()
print("   cleared %d pre-existing LNX-20xx finding row(s) in the COPY, so the "
      "trip below is a real first raise rather than one dedup correctly "
      "suppresses" % n)
PY
    echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILiveTripVerificationKeyXXXXXXXXXXXXXXXXXXXX agental-live-trip" >> "$AK"
    FOUND=0
    for _ in $(seq 1 30); do
        sleep 2
        curl -s -H "X-API-Key: $KEY" \
             "http://127.0.0.1:$PORT/api/findings?limit=20" > "$TMP/findings.json"
        FOUND=$(python3 "$TMP/probe.py" "$TMP/findings.json" LNX-2002 "*" "*" 2>/dev/null)
        [[ "$FOUND" == "1" ]] && break
    done
    chk "the finding appeared over the API without anyone asking for it" "$FOUND"
    chk "the finding names the FILE as its entity" \
        "$(python3 "$TMP/probe.py" "$TMP/findings.json" LNX-2002 entity_value authorized_keys)"
    python3 - "$TMP/findings.json" <<'PY' | sed 's/^/   /'
import json, sys
d = json.load(open(sys.argv[1]))
rows = d if isinstance(d, list) else (d.get("findings") or [])
for r in rows:
    if r.get("detection_id") == "LNX-2002":
        print(json.dumps({k: r.get(k) for k in
              ("detection_id", "severity", "entity_type", "entity_value",
               "title", "found_at")}, indent=2))
        break
else:
    print("no LNX-2002 row in the payload")
PY

    echo
    echo "D. the query_local_integrity tool answers over the agent path"
    python3 - "$ROOT" "$TMP/tool.json" <<'PY'
import json, sys, pathlib
root = pathlib.Path(sys.argv[1])
sys.path.insert(0, str(root))
out = {}
try:
    from core import tool_registry as tr
    from core import sensor_health
    out["in_manifest"] = tr.tool_exists("query_local_integrity")
    out["declares_dependency"] = list(sensor_health.depends_on("query_local_integrity"))
    out["not_gated"] = not tr.requires_permission("query_local_integrity", {})
    out["read_only"] = not tr.tool_writes("query_local_integrity")
    # The real dispatch, against the module table the boot built. The boot's
    # own process holds it, so this is the SHAPE check: does the tool raise
    # UnregisteredTool, and is an unloaded module answered rather than fatal.
    tr._modules = {}
    r = tr._dispatch("query_local_integrity", {})
    out["unloaded_answer_has_no_loaded_key"] = ("loaded" in r and r["loaded"] is False)
    out["unloaded_answer_says_so"] = "NOT LOADED" in (r.get("note") or "")
except Exception as e:
    out["error"] = f"{type(e).__name__}: {e}"
json.dump(out, open(sys.argv[2], "w"), indent=2)
PY
    cat "$TMP/tool.json" | sed 's/^/   /'
    chk "the tool is in the manifest" \
        "$([[ "$(val "$TMP/tool.json" in_manifest)" == "true" ]] && echo 1 || echo 0)"
    chk "it declares its sensor dependency" \
        "$(val "$TMP/tool.json" declares_dependency | grep -q local_integrity && echo 1 || echo 0)"
    chk "it is read-only and asks no permission" \
        "$([[ "$(val "$TMP/tool.json" not_gated)" == "true" \
            && "$(val "$TMP/tool.json" read_only)" == "true" ]] && echo 1 || echo 0)"
    chk "an unloaded module is answered, not raised" \
        "$([[ "$(val "$TMP/tool.json" unloaded_answer_says_so)" == "true" ]] && echo 1 || echo 0)"
fi

echo
echo "E. TIER C: dpkg -V RUNS FOR REAL, SEEDS, AND SAYS WHAT IT COULD NOT SEE"
# THE WAIT IS THE POINT OF THIS SECTION. The adapter holds the first run for
# dpkg_first_delay_seconds (30 here, 300 in production) because a full run is
# 209s and the boot is starting eight sensors. So this waits for the wait, then
# waits again for dpkg itself. Nothing here shortens dpkg.
echo "   waiting for the first dpkg run (the adapter's own delay, then dpkg's"
echo "   measured 209s)..."
DPKG_DONE=0
for _ in $(seq 1 90); do
    sleep 5
    curl -s -H "X-API-Key: $KEY" "http://127.0.0.1:$PORT/api/status" \
        > "$TMP/status2.json" 2>/dev/null
    python3 - "$TMP/status2.json" "$TMP/li2.json" <<'PY' 2>/dev/null
import json, sys
d = json.load(open(sys.argv[1]))
json.dump(d.get("modules", {}).get("local_integrity", {}), open(sys.argv[2], "w"))
PY
    if [[ "$(val "$TMP/li2.json" tier_c.runs 2>/dev/null)" != "MISSING" ]] \
       && [[ "$(val "$TMP/li2.json" tier_c.runs 2>/dev/null)" != "0" ]]; then
        DPKG_DONE=1
        break
    fi
    kill -0 "$BOOT_PID" 2>/dev/null || break
done
chk "tier C completed a dpkg run inside the session" "$DPKG_DONE"

if [[ "$DPKG_DONE" == "1" ]]; then
    echo
    cat "$TMP/li2.json" | python3 -c "
import json,sys
d = json.load(sys.stdin)
tc = d.get('tier_c', {})
print(json.dumps({k: tc.get(k) for k in
      ('runs','seeded','last_seconds','packages_verified','refused_count',
       'excluded_boot','aborted','coverage')}, indent=2)[:1400])" | sed 's/^/   /'

    chk "it SEEDED rather than producing a page of findings" \
        "$([[ "$(val "$TMP/li2.json" tier_c.seeded)" == "true" ]] && echo 1 || echo 0)"
    chk "it named a real package count, not zero" \
        "$(python3 -c "
import json,sys
n = json.load(open('$TMP/li2.json')).get('tier_c',{}).get('packages_verified') or 0
print(1 if n > 1000 else 0)")"
    chk "it reports how long dpkg took, in the minutes the measurement says" \
        "$(python3 -c "
import json,sys
s = json.load(open('$TMP/li2.json')).get('tier_c',{}).get('last_seconds') or 0
print(1 if s > 30 else 0)")"
    chk "/boot was excluded, as the config knob asked" \
        "$([[ "$(val "$TMP/li2.json" tier_c.excluded_boot)" == "true" ]] && echo 1 || echo 0)"
    chk "it did NOT abort" \
        "$([[ "$(val "$TMP/li2.json" tier_c.aborted)" == "false" ]] && echo 1 || echo 0)"
    chk "the coverage block states the unreadable-file consequence" \
        "$(python3 -c "
import json,sys
c = json.load(open('$TMP/li2.json')).get('tier_c',{}).get('coverage') or {}
n = c.get('note') or ''
print(1 if 'NOT about the files' in n else 0)")"

    # THE COVERAGE FINDING IS REACHABLE END TO END.
    # LNX-2005 must appear: dpkg cannot load example-app's control file, and the
    # seed pass raises that as a coverage hole. This is the check that proves
    # the whole path works -- sensor, adapter, register, findings table, API.
    curl -s -H "X-API-Key: $KEY" \
         "http://127.0.0.1:$PORT/api/findings?limit=100" > "$TMP/findings2.json"
    chk "LNX-2005 reached the findings table from a REAL dpkg run" \
        "$(python3 "$TMP/probe.py" "$TMP/findings2.json" LNX-2005 "*" "*" 2>/dev/null)"
    chk "and its entity_type is the FILE vocabulary, not an ip" \
        "$(python3 -c "
import json
d = json.load(open('$TMP/findings2.json'))
rows = d if isinstance(d, list) else (d.get('findings') or [])
hits = [r for r in rows if r.get('detection_id') == 'LNX-2005']
print(1 if hits and hits[0].get('entity_type') == 'file' else 0)")"
    python3 - "$TMP/findings2.json" <<'PY' | sed 's/^/   /'
import json, sys
d = json.load(open(sys.argv[1]))
rows = d if isinstance(d, list) else (d.get("findings") or [])
for r in rows:
    if str(r.get("detection_id", "")).startswith("LNX-200"):
        print(json.dumps({k: r.get(k) for k in
              ("detection_id", "severity", "entity_type", "entity_value",
               "title")}, indent=2)[:700])
        break
else:
    print("no LNX-200x row in the payload")
PY
else
    echo "   (tier C did not complete in this run, so its findings cannot be"
    echo "    checked here. The run's own reason is above.)"
    no "tier C completed a dpkg run inside the session"
fi

echo
echo "F. TIER D: THE READ-ONLY HELPER'S STATE IS REPORTED, ALL THREE CASES"
# THE HELPER IS NOT INSTALLED ON THIS MACHINE, and that is the honest state to
# verify: the sensor must say so, must not claim the coverage, and must not
# fail. The installed-and-working case is proved by
# scripts/install_read_helper.sh --verify, which needs the owner's password and
# therefore cannot run inside this script.
python3 - "$ROOT" <<'PY'
import json, pathlib, sys
root = pathlib.Path(sys.argv[1])
sys.path.insert(0, str(root))
out = {}
try:
    from tools import local_integrity as li
    li.helper_forget()
    st = li.helper_status(force=True)
    out["available"] = st.get("available")
    out["euid"] = st.get("euid")
    out["reason"] = st.get("reason")
    out["helper"] = st.get("helper")
    note = li.helper_coverage_note()
    out["uncovered"] = note.get("uncovered")
    out["covered"] = note.get("covered")
except Exception as e:
    out["error"] = f"{type(e).__name__}: {e}"
json.dump(out, open(str(root) + "/helper_state.json", "w"), indent=2)
PY
chk "the helper's state is reported, not guessed" \
    "$([[ "$(val "$ROOT/helper_state.json" available)" != "MISSING" ]] && echo 1 || echo 0)"
chk "and the coverage note names the sets that stay unread" \
    "$(python3 -c "
import json
d = json.load(open('$ROOT/helper_state.json'))
u = d.get('uncovered') or []
print(1 if any('sudoers' in x for x in u) and any('authorized_keys' in x for x in u) else 0)")"
chk "and /etc/shadow is named as refused in EVERY state" \
    "$(python3 -c "
import json
d = json.load(open('$ROOT/helper_state.json'))
print(1 if any('shadow' in x for x in (d.get('uncovered') or [])) else 0)")"
chk "and the sensor's own coverage block carries the same statement" \
    "$(python3 -c "
import json
d = json.load(open('$TMP/li2.json'))
n = d.get('tier_a', {}).get('coverage', {}) or {}
print(1 if 'files_read_elevated' in n else 0)")"
rm -f "$ROOT/helper_state.json"

echo
echo "G. shutting down cleanly, and the sweep and dpkg threads go with it"
kill -TERM -"$BOOT_PID" 2>/dev/null
for _ in $(seq 1 40); do
    kill -0 "$BOOT_PID" 2>/dev/null || break
    sleep 1
done
chk "SIGTERM shuts the app down cleanly" \
    "$(grep -q 'AgentalSec stopped cleanly' "$TMP/boot.out" && echo 1 || echo 0)"
chk "no traceback anywhere in the boot log" \
    "$(grep -q 'Traceback' "$TMP/boot.out" && echo 0 || echo 1)"
chk "the port is released" \
    "$(! ss -ltn | grep -q "127.0.0.1:$PORT" && echo 1 || echo 0)"

echo
echo "H. the operator's files are restored, byte for byte"
cp "$TMP/authorized_keys.orig" "$AK"
chk "authorized_keys is byte-identical to before the trip" \
    "$(cmp -s "$TMP/authorized_keys.orig" "$AK" && echo 1 || echo 0)"
# THE RESTORE HAPPENS HERE AND IN THE TRAP, AND BOTH PROVE IT. Here, so the
# summary can show it; in the trap, so Ctrl+C, a closed window and a killed
# shell have it too.
cp "$TMP/config.orig.json" "$ROOT/config.json"
chk "config.json is byte-identical to before this script ran" \
    "$(cmp -s "$TMP/config.orig.json" "$ROOT/config.json" && echo 1 || echo 0)"

echo
echo "======================================================================"
echo "  $PASS passed, $FAIL failed"
[[ $FAIL -gt 0 ]] && echo "  FAILED, inspect $TMP"
echo "======================================================================"
exit $(( FAIL > 0 ? 1 : 0 ))
