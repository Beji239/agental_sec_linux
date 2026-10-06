#!/usr/bin/env bash
# scripts/verify_feeds.sh -- MISP and OTX's evidence.
#
# The counterpart to scripts/verify_auditd.sh, verify_local_integrity.sh and
# verify_ebpf_events.sh, and it exists for the same reason: a unit test proves
# a function, only a REAL BOOT proves the daemon calls it.
#
# WHAT THIS PROVES THAT NO UNIT TEST CAN
#
#   * THE REAL MISP FEED IS REACHABLE AND PARSES. The unit tests prove the
#     parser given a fixture; this fetches the manifest and the newest events
#     from circl.lu and asserts that real rows come out of real bytes. The
#     fixture shapes were read from this service, so if it changes shape this
#     is the check that notices.
#
#   * THE PRIVATE-ADDRESS FILTER HOLDS ON REAL DATA. The CIRCL OSINT events
#     really do list two private 10.x addresses, and one of them is THIS
#     host's gateway. This asserts none of them reached the threat_feed table.
#
#   * A FEED REFUSAL IS NOT A QUIET NETWORK. With no OTX key on this host, the
#     feed must report a reason naming the variable -- over the API, not only
#     in a log line -- while the rest of the matcher carries on.
#
#   * THE CURSORS DO NOT MOVE THE POLICY DIGEST (v46). Measured on the copy
#     BEFORE and AFTER a real refresh, from the integrity journal itself.
#
#   * A REAL BOOT starts the matcher, and /api/status serves the feed state.
#
# WHAT IT DOES *NOT* DO, AND WHY
#
# IT DOES NOT SET AN OTX KEY, because there is not one on this host and this
# script will not sign anybody up for an account. That half is exercised
# against a stubbed response in tests/test_feed_matcher.py instead, and the
# live half here asserts the ABSENCE is reported correctly -- which is the
# state this machine is actually in.
#
# IT DOES NOT INSTALL ANYTHING. No apt, no pip, no sudo.
#
# THE OPERATOR'S THINGS ARE RESTORED AND ASSERTED
#
# config.json is copied, modified and restored BYTE-IDENTICALLY (verified with
# cmp, not assumed). The live database is NEVER touched: every check that
# writes runs against a copy, and the last check confirms the original is
# still at its own schema version. The MISP fetch is a read from a public
# service and touches nothing of the operator's.
#
# NOTHING OF THE OPERATOR'S IS STOPPED, KILLED OR OTHERWISE TOUCHED.
set -uo pipefail

# The tree, its owner and the owner's home are read at run time. A copy run
# from elsewhere names the tree with AGENTAL_ROOT.
ROOT="${AGENTAL_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
[[ -f "$ROOT/main.py" ]] || { echo "no main.py in $ROOT: set AGENTAL_ROOT to the tree" >&2; exit 2; }
OWNER="$(stat -c %U "$ROOT")"
OWNER_HOME="$(getent passwd "$OWNER" | cut -d: -f6)"
PORT=5231
TMP=$(mktemp -d /tmp/agental_feeds.XXXXXX)
COPYDB="$TMP/agental_sec.db"

echo "port under test : $PORT (the owner's copy on 5000 is untouched)"
echo "database        : a COPY at $COPYDB; the live file is never opened"
echo "network         : one real read of circl.lu's MISP manifest + events"
echo "scratch         : $TMP"
echo

PASS=0; FAIL=0; SKIP=0
ok()   { echo "  [PASS] $1"; PASS=$((PASS+1)); }
no()   { echo "  [FAIL] $1"; FAIL=$((FAIL+1)); }
skip() { echo "  [SKIP] $1"; SKIP=$((SKIP+1)); }
chk()  { if [[ "$2" == "1" ]]; then ok "$1"; else no "$1"; fi; }

# STDERR IS SHOWN FROM THE BOTTOM, and the whole file's line count is printed.
# `head -6` HID THE REAL ERROR IN A REAL RUN OF THIS SCRIPT: a Traceback is the
# LAST thing on stderr, so a crash came out as six unexplained FAILs with the
# reason cut off above the fold. Same class as the auditd verifier's two
# defects -- the apparatus failing in a way that reads as the code failing.
show_stderr() {   # $1 = file, $2 = label
    local f="$1" n=0
    [[ -s "$f" ]] || return 0
    n=$(grep -cv 'DeprecationWarning' "$f" 2>/dev/null || true)
    [[ -z "$n" || "$n" == "0" ]] && return 0
    grep -v DeprecationWarning "$f" | sed "s/^/   [$2] /" | tail -40
    [[ "$n" -gt 40 ]] && echo "   [$2] ... $n lines of stderr in total"
    return 0
}

# ONE READER FOR EVERY FLAGS FILE, defined with the other helpers so no section
# can use it before it exists. Nothing is eval-ed: see verify_auditd.sh's
# header for the two defects that came of doing that.
flag() { grep "^$1=" "$2" | cut -d= -f2-; }
flagA() { flag "$1" "$TMP/a.flags"; }
flagB() { flag "$1" "$TMP/b.flags"; }
flagC() { flag "$1" "$TMP/c.flags"; }
flagD() { flag "$1" "$TMP/d.flags"; }

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
    pkill -f "agental_feeds_verify" 2>/dev/null
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

python3 "$ROOT/scripts/snapshot_db.py" "$ROOT/agental_sec.db" "$COPYDB"
# The reference copy was taken above, in the LA-4 head, so the trap could see
# it from the first line of the run; taking it twice is what LA-4 removed.

echo "A. THE FEED TABLE, ON THIS MACHINE, BEFORE ANY BOOT"

python3 - "$ROOT" > "$TMP/a.txt" 2>"$TMP/a.err" <<'PY'
import json, sys
sys.path.insert(0, sys.argv[1])
from tools import feed_matcher as fm

out = {
    "feeds": sorted(fm.FEEDS.keys()),
    "misp_keyless": fm.FEEDS["misp"].get("needs_key") is False,
    "otx_key": fm.FEEDS["otx"].get("needs_key"),
    "feodo_key": fm.FEEDS["feodo"].get("needs_key"),
    "otx_var_set": bool((__import__("os").environ.get("AGENTAL_OTX_KEY") or "").strip()),
    "has_parse_misp": hasattr(fm, "parse_misp_event"),
    "has_parse_otx": hasattr(fm, "parse_otx_pulses"),
    "cursor_table": fm._CURSOR_TABLE,
    "misp_ceiling": fm.MISP_MAX_EVENTS_CEILING,
    "otx_ceiling": fm.OTX_MAX_PULSES_CEILING,
}
print(json.dumps(out))
PY
sed 's/^/   /' "$TMP/a.txt"
show_stderr "$TMP/a.err" stderr

python3 - "$TMP/a.txt" "$TMP/a.flags" <<'PY' > /dev/null
import json, sys
d = json.load(open(sys.argv[1]))
f = {}
f["FIVE_FEEDS"] = 1 if set(d.get("feeds") or []) >= {
    "feodo", "urlhaus", "threatfox", "misp", "otx"} else 0
# THE KEY WIRING IS THE THING THAT GOES WRONG SILENTLY. feodo/urlhaus/threatfox
# share the abuse.ch key (True, kept as an alias); OTX names its OWN VARIABLE;
# MISP needs none. A fetcher that cannot tell which key is which sends the
# abuse.ch key to OTX, gets a 403, and reports it as a bad key for the wrong
# provider -- so the variable NAMES are asserted, not merely that a key is
# wanted.
f["MISP_KEYLESS"] = 1 if d.get("misp_keyless") else 0
f["OTX_OWN_VAR"] = 1 if d.get("otx_key") == "AGENTAL_OTX_KEY" else 0
f["ABUSECH_ALIAS"] = 1 if d.get("feodo_key") is True else 0
f["PARSERS"] = 1 if d.get("has_parse_misp") and d.get("has_parse_otx") else 0
f["CURSOR_TABLE_IS_ITS_OWN"] = 1 if d.get("cursor_table") == "feed_cursor" else 0
f["CEILINGS"] = 1 if (d.get("misp_ceiling") == 60
                      and d.get("otx_ceiling") == 100) else 0
with open(sys.argv[2], "w") as fh:
    for k, v in f.items():
        fh.write("%s=%s\n" % (k, v))
PY

chk "all five feeds are declared" "$(flagA FIVE_FEEDS)"
chk "MISP declares itself KEYLESS" "$(flagA MISP_KEYLESS)"
chk "OTX names its OWN key variable, not abuse.ch's" "$(flagA OTX_OWN_VAR)"
chk "the three abuse.ch feeds still resolve to the abuse.ch key" \
    "$(flagA ABUSECH_ALIAS)"
chk "both new parsers exist" "$(flagA PARSERS)"
chk "the cursors live in a table of their own, not the policy table" \
    "$(flagA CURSOR_TABLE_IS_ITS_OWN)"
chk "both per-feed windows have a ceiling" "$(flagA CEILINGS)"

echo
echo "B. THE REAL MISP FEED, FETCHED FOR REAL"
#
# A READ FROM A PUBLIC SERVICE. Nothing of the operator's is involved.

MISP_STATUS="reachable"
if ! python3 -c "
import socket
socket.setdefaulttimeout(8)
socket.create_connection(('www.circl.lu', 443)).close()
" 2>/dev/null; then
    MISP_STATUS="unreachable"
fi

if [[ "$MISP_STATUS" != "reachable" ]]; then
    skip "the live MISP fetch (www.circl.lu:443 did not answer from here)"
else
    timeout 300 python3 - "$ROOT" > "$TMP/b.txt" 2>"$TMP/b.err" <<'PY'
import json, sys, time
sys.path.insert(0, sys.argv[1])
from tools import feed_matcher as fm

t0 = time.time()
rows, err, detail = fm.fetch_misp_events(6)
ips = [r[0] for r in rows if r[1] == "ip"]
domains = [r[0] for r in rows if r[1] == "domain"]

# THE PRIVATE-ADDRESS QUESTION, ASKED OF THE REAL DATA: is any returned
# indicator something that must never have been stored?
unmatchable = [r[0] for r in rows if not fm._is_matchable_ip(r[0])
               and r[1] == "ip"]

out = {
    "err": err,
    "rows": len(rows),
    "ips": len(ips),
    "domains": len(domains),
    "unmatchable_ips": unmatchable[:5],
    "secs": round(time.time() - t0, 1),
    "in_archive": (detail or {}).get("events_in_archive"),
    "window": (detail or {}).get("window"),
    "note": (detail or {}).get("note"),
    "sample_domain": domains[0] if domains else None,
    "candidates": [r for r in rows if r[1] == "domain"][:3],
}
print(json.dumps(out))
PY
    sed 's/^/   /' "$TMP/b.txt"
    show_stderr "$TMP/b.err" stderr

    python3 - "$TMP/b.txt" "$TMP/b.flags" <<'PY' > /dev/null
import json, sys
d = json.load(open(sys.argv[1]))
f = {}
f["FETCHED"] = 1 if not d.get("err") else 0
f["HAS_ROWS"] = 1 if (d.get("rows") or 0) > 0 else 0
f["HAS_DOMAINS"] = 1 if (d.get("domains") or 0) > 0 else 0
# THE FILTER, ON REAL BYTES. The CIRCL events genuinely carry a private 10.x address.
f["NO_INTERNAL_IPS"] = 1 if not (d.get("unmatchable_ips") or []) else 0
# THE HONEST WINDOW: the note has to say how many events were NOT read.
f["SAYS_WHAT_IT_LEFT"] = 1 if "were NOT read" in (d.get("note") or "") else 0
f["NAMES_THE_ARCHIVE"] = 1 if (d.get("in_archive") or 0) > 0 else 0
f["WINDOW_IS_BOUNDED"] = 1 if (d.get("window") or 0) <= 60 else 0
with open(sys.argv[2], "w") as fh:
    for k, v in f.items():
        fh.write("%s=%s\n" % (k, v))
PY

    chk "the real MISP feed was fetched and parsed" "$(flagB FETCHED)"
    chk "and it yielded indicators" "$(flagB HAS_ROWS)"
    chk "and domains are among them" "$(flagB HAS_DOMAINS)"
    chk "NO internal address survived the filter, on real data" \
        "$(flagB NO_INTERNAL_IPS)"
    chk "the answer says how many events were NOT read" \
        "$(flagB SAYS_WHAT_IT_LEFT)"
    chk "and names the size of the archive it read from" \
        "$(flagB NAMES_THE_ARCHIVE)"
    chk "the window is bounded by the ceiling" "$(flagB WINDOW_IS_BOUNDED)"
fi

echo
echo "C. A REFRESH ON A COPY OF THE DATABASE, AND WHAT IT DID TO THE JOURNAL"
#
# THE v46 CHECK, and it is the one that matters most here. Before this step,
# the matcher's cursors were rows in user_preferences, which core/integrity
# digests as THE POLICY and journals a `config_observed` entry on ANY
# difference. So this asserts BOTH halves: a refresh must not move the policy
# digest, and a genuine policy change must still move it -- or the check is
# not strict, it is broken.
#
# TWO VERIFIER DEFECTS ARE BURIED IN THIS SECTION'S OWN HISTORY, and both were
# found by running it rather than by reading it.
#
# 1. THE HELPER COMMITTED NOTHING AND LOCKED EVERYTHING. `ig.snapshot_config`
#    only commits when it OPENED the connection; handed one, it leaves the
#    commit to the caller -- a rule `scripts/prune_db.py` carries a comment
#    about, from being bitten by it. This section handed it one and did not
#    commit, so the connection sat on an open write transaction while the code
#    under test wrote through its OWN connection via memory_engine._get_conn.
#    Every one of those writes failed with "database is locked", the four
#    messages went to stderr, and the check read a cursor that was never
#    written. So `fm._set_cursor(...)` proved nothing here, and the script
#    reported SIX failures for a defect in the script: what it was testing
#    never ran.
# 2. THE CRASH READ AS SIX FAILED CHECKS. The locked write meant no row
#    existed, `fetchone()[0]` raised TypeError, the JSON line was never
#    printed, and all six `flagC` reads came back empty. The traceback was on
#    stderr, and `head -6` cut it off.
#
# WHAT IT LOOKS LIKE NOW: the connection is committed after every snapshot,
# each cursor write is CONFIRMED against the database, and the whole section
# runs inside its own try so a crash is reported as ONE named failure with its
# reason instead of six orphaned ones. The lesson is the auditd verifier's:
# when a verifier fails, suspect the verifier first.

if python3 - "$ROOT" "$COPYDB" > "$TMP/c.txt" 2>"$TMP/c.err" <<'PY'
import json, os, sqlite3, sys, traceback
sys.path.insert(0, sys.argv[1])
os.environ["AGENTALSEC_TEST_DB"] = sys.argv[2]

try:
    from core import memory_engine as me
    from core import migrations
    from core import integrity as ig

    mig = migrations.run_migrations()
    from tools import feed_matcher as fm

    def last_digest(conn):
        row = conn.execute(
            "SELECT payload_digest FROM integrity_journal"
            " WHERE operation='config_observed' ORDER BY id DESC LIMIT 1"
        ).fetchone()
        return row[0] if row else None

    conn = sqlite3.connect(sys.argv[2])
    out = {"schema": mig.get("version"),
           "feed_cursor_added": mig.get("feed_cursor_added")}

    # COMMIT AFTER EVERY SNAPSHOT. See defect 1 in the shell above: without
    # this the connection holds a write transaction and the CODE UNDER TEST
    # cannot write at all, which is the check testing nothing.
    ig.snapshot_config("verify-before", conn=conn)
    conn.commit()
    before = last_digest(conn)

    # THE BOOKKEEPING A MATCHER WRITES EVERY FIVE MINUTES, and the refresh
    # result beside it. THROUGH THE REAL WRITER, so this exercises the same
    # path a running matcher uses rather than a hand-written INSERT.
    fm._set_cursor(fm._CUR_PACKETS, 987654)
    fm._set_cursor(fm._CUR_DNS, 12)
    fm._set_cursor(fm._CUR_TLS, 34)
    fm._cursor_write(fm._LAST_RESULT, '{"misp": {"ok": true}}')
    # AND THE REFRESH TIME, which is the one v46 originally MISSED: it stayed
    # in user_preferences after the three cursors moved, so a successful
    # refresh still moved the policy digest. This write is new with the fix.
    fm._cursor_write(fm._LAST_REFRESH, "2026-09-23T08:00:00+00:00")

    # CONFIRMED, not assumed: each write is read back from the database
    # through a SECOND connection, which is exactly the one that was locked.
    verify = sqlite3.connect(sys.argv[2])
    out["cursors_confirmed"] = {
        name: verify.execute(
            "SELECT value FROM feed_cursor WHERE name = ?", (name,)).fetchone()
        for name in (fm._CUR_PACKETS, fm._CUR_DNS, fm._CUR_TLS,
                     fm._LAST_RESULT, fm._LAST_REFRESH)}
    out["cursors_all_written"] = all(
        v is not None for v in out["cursors_confirmed"].values())
    verify.close()

    conn.commit()
    after = last_digest(conn)
    out["digest_moved_by_bookkeeping"] = (before is not None
                                          and after is not None
                                          and before != after)

    # THE NEGATIVE CONTROL. A real policy change must still register.
    conn.execute("INSERT OR REPLACE INTO user_preferences(key, value)"
                 " VALUES ('alert_suppression_at', 'medium')")
    conn.commit()
    ig.snapshot_config("verify-after-real-change", conn=conn)
    conn.commit()
    control = last_digest(conn)
    out["control_change_registered"] = (after is not None and control is not None
                                        and after != control)

    # AND: no feed key is left in the policy table -- the refresh TIME as well
    # as the cursors, which is the key that was left behind the first time.
    out["feed_keys_in_prefs"] = conn.execute(
        "SELECT COUNT(*) FROM user_preferences WHERE key LIKE 'feed%'").fetchone()[0]
    out["refresh_key_in_prefs"] = conn.execute(
        "SELECT COUNT(*) FROM user_preferences WHERE key = ?",
        (fm._LAST_REFRESH,)).fetchone()[0]
    out["cursor_rows"] = conn.execute(
        "SELECT COUNT(*) FROM feed_cursor").fetchone()[0]
    out["in_cursor_table"] = conn.execute(
        "SELECT value FROM feed_cursor WHERE name = ?",
        (fm._CUR_PACKETS,)).fetchone()[0]
    conn.close()
    out["ok"] = True
except Exception:
    out = {"ok": False, "traceback": traceback.format_exc()}

print(json.dumps(out))
PY
then
    SECTION_C_OK=1
else
    SECTION_C_OK=0
fi
sed 's/^/   /' "$TMP/c.txt"
show_stderr "$TMP/c.err" stderr

python3 - "$TMP/c.txt" "$TMP/c.flags" <<'PY' > /dev/null
import json, sys
d = json.load(open(sys.argv[1]))
f = {}
# SECTION_OK GATES EVERYTHING BELOW, and it is not decoration. Before this the
# flags were computed from whatever the JSON happened to hold, and a crashed
# section produces an EMPTY dict -- from which `digest_moved_by_bookkeeping`
# is falsy and DIGEST_STILL would have come out as 1, a PASS, on a run where
# nothing was examined at all. That is the "0 violations found" versus "0
# things examined" trap, and it is exactly how the six failures this section
# used to report stayed unexplained.
f["SECTION_OK"] = 1 if d.get("ok") else 0
ok = bool(d.get("ok"))
f["MIGRATED"] = 1 if ok and d.get("schema") == 46 else 0
f["TABLE_ADDED"] = 1 if ok and d.get("feed_cursor_added") else 0
# THE WHOLE POINT, both directions.
f["DIGEST_STILL"] = 1 if ok and not d.get("digest_moved_by_bookkeeping") else 0
f["CONTROL_MOVES"] = 1 if ok and d.get("control_change_registered") else 0
f["NOT_IN_PREFS"] = 1 if ok and (d.get("feed_keys_in_prefs") or 0) == 0 else 0
f["TIME_NOT_IN_PREFS"] = 1 if ok and (d.get("refresh_key_in_prefs") or 0) == 0 else 0
f["CURSORS_WRITTEN"] = 1 if ok and d.get("cursors_all_written") else 0
f["IN_CURSOR_TABLE"] = 1 if ok and str(d.get("in_cursor_table")) == "987654" else 0
with open(sys.argv[2], "w") as fh:
    for k, v in f.items():
        fh.write("%s=%s\n" % (k, v))
PY

# ONE NAMED FAILURE WHEN THE SECTION DID NOT RUN, before the eight claims that
# depend on it -- so a crash reads as "the check did not run" rather than as
# eight separate defects in the app.
if [[ "$(flagC SECTION_OK)" != "1" ]]; then
    no "SECTION C did not run to completion; the reasons for the failures below are in its output above"
fi
chk "the copy migrated to v46" "$(flagC MIGRATED)"
chk "and feed_cursor was created by that step" "$(flagC TABLE_ADDED)"
chk "every bookkeeping write was CONFIRMED in the database" \
    "$(flagC CURSORS_WRITTEN)"
chk "a cursor write did NOT move the policy digest" "$(flagC DIGEST_STILL)"
chk "A REAL POLICY CHANGE STILL DOES (the control)" "$(flagC CONTROL_MOVES)"
chk "no feed key is left in the policy table" "$(flagC NOT_IN_PREFS)"
# THE ONE THIS SECTION MISSED THE FIRST TIME. The three match cursors moved out
# of the policy table and the refresh TIME did not, so a successful refresh
# still moved the digest. Asserted separately from the cursors, because "no
# feed% keys" is satisfied by moving two of the three keys.
chk "and the refresh time is not in the policy table either" \
    "$(flagC TIME_NOT_IN_PREFS)"
chk "the cursor landed in feed_cursor with its value" "$(flagC IN_CURSOR_TABLE)"

echo
echo "D. A REAL BOOT, WITH THE FEEDS WIRED IN"
#
# The config is pointed at the copy, the port is one the operator's copy cannot
# be using, and the run is short: a boot proves the matcher STARTS and that
# /api/status serves the feed state. The real fetch that a boot performs is a
# read from circl.lu, which section B has already established is reachable.

python3 - "$ROOT" "$PORT" > "$TMP/cfg.txt" <<'PY'
import json, sys
sys.path.insert(0, sys.argv[1])
p = sys.argv[1] + "/config.json"
c = json.load(open(p))
c["flask"]["port"] = int(sys.argv[2])
c["sensors"] = c.get("sensors") or {}
# Everything that reaches the network or needs privileges is off for this run:
# the boot is being used to prove the FEED wiring, not to sweep anything.
for name in ("packet_sniffer", "network_scanner", "port_scanner",
             "linux_monitor"):
    if name in c["sensors"]:
        c["sensors"][name]["enabled"] = False
if isinstance(c.get("linux_monitor"), dict):
    c["linux_monitor"]["enabled"] = False
if isinstance(c.get("router_monitor"), dict):
    c["router_monitor"]["enabled"] = False
# THE MISP WINDOW IS SIX, NOT THREE, and the number is a measurement rather
# than a round figure. MEASURED on this archive 2026-09-23: FOUR of the newest
# SIX events are prose reports carrying no indicators at all, so a window of
# three lands entirely inside that run and the feed CORRECTLY refuses to write
# anything. That is the honest behaviour of a correct fetch -- but a boot test
# whose subject is the WIRING should not be arranged so that its most likely
# outcome is a refusal. Six is the smallest window that reached real
# indicators on the day this was written (~12 MB), and the check below tolerates
# BOTH outcomes, because tomorrow's six may all be prose again.
c.setdefault("threat_feeds", {})["misp_max_events"] = 6
c["threat_feeds"]["refresh_hours"] = 6
# Duty loop off: this boot must not spend tokens.
if isinstance(c.get("duty_loop"), dict):
    c["duty_loop"]["enabled"] = False
json.dump(c, open(p, "w"), indent=2)
print("port=%d, feeds=%s, misp_max_events=%s"
      % (int(sys.argv[2]), c["threat_feeds"].get("feeds"),
         c["threat_feeds"].get("misp_max_events")))
PY
sed 's/^/   /' "$TMP/cfg.txt"

# THE COPY IS PUT BACK TO A NEVER-REFRESHED STATE FIRST, and this is not
# housekeeping -- it is the difference between a boot that proves the wiring
# and a boot that proves nothing.
#
# SECTION C NOW WRITES A FRESH `feed_last_refresh_at` into this copy, because
# that key is its subject. A boot against a copy carrying a stamp from minutes
# ago does the honest thing: refresh_once sees the age is below refresh_hours
# and returns `skipped: True` without fetching anything. So the boot wrote no
# per-feed lines, section D's three MISP/OTX checks failed, and the failure was
# in the APPARATUS -- the same shape as the L3 verifier asserting first-run
# behaviour against a database that had already had its first run.
#
# Clearing ONE key, deliberately: the match cursors stay where section C left
# them, so this boot still exercises reading a cursor that was seeded rather
# than created fresh.
python3 - "$COPYDB" <<'PY'
import sqlite3, sys
conn = sqlite3.connect(sys.argv[1])
try:
    deleted = conn.execute(
        "DELETE FROM feed_cursor WHERE name = 'feed_last_refresh_at'").rowcount
    conn.commit()
    print(f"   cleared {deleted} refresh stamp(s) in the copy so this boot "
          f"actually refreshes")
finally:
    conn.close()
PY

LOG="$TMP/boot.log"
setsid unshare -r env AGENTALSEC_TEST_DB="$COPYDB" \
    python3 "$ROOT/main.py" > "$LOG" 2>&1 &
BOOT_PID=$!

READY=0
for _ in $(seq 1 90); do
    if grep -q "AgentalSec ready" "$LOG" 2>/dev/null; then READY=1; break; fi
    if ! kill -0 "$BOOT_PID" 2>/dev/null; then break; fi
    sleep 1
done
chk "the app booted to its ready line" "$READY"

# THE FEEDS NEED TIME: the first refresh happens at boot, and a real MISP
# window is ~15 MB of download. Poll the log for the outcome rather than
# sleeping a fixed time.
#
# THE PATTERN MATCHES BOTH LINE SHAPES, and the first version did not: it
# looked for "Feed misp " with a space, which matches the REFUSAL
# ("Feed misp not refreshed: ...") and NOT the success line
# ("Feed misp: 12616 indicators" -- a colon follows the name). So the wait
# ended early on exactly the run where the feed worked, and the checks below
# then read a log that was still being written. Same defect as the flag check
# in section D: an assertion that only recognises one of the two outcomes.
FEED_DONE=0
for _ in $(seq 1 180); do
    if grep -qE "Feed (misp|otx)[: ]" "$LOG" 2>/dev/null; then FEED_DONE=1; break; fi
    if ! kill -0 "$BOOT_PID" 2>/dev/null; then break; fi
    sleep 1
done

if [[ "$READY" != "1" ]]; then
    no "the boot never reached its ready line; see $LOG"
    tail -25 "$LOG" | sed 's/^/   /'
else
    # ASSERTED, NOT NARRATED. This line used to be an unconditional ok() that
    # ran whenever the app booted, with a comment saying it was "asserted below
    # via the log" -- but the flag that would have done that, FEED_DONE, was
    # computed and never checked. A boot that reached its ready line and then
    # never refreshed a single feed passed this check, which is the vacuous
    # green this project writes rules about.
    chk "the feed refresh ran inside the boot" "$FEED_DONE"
fi

grep -E "Feed (misp|otx|feodo|urlhaus|threatfox)|\[OK\] feed_matcher|NO INDICATORS|NOT CHECKED" \
    "$LOG" | sed 's/^/   /' | head -20

python3 - "$LOG" "$TMP/d.flags" <<'PY'
import sys
log = open(sys.argv[1], errors="replace").read()
f = {}
f["MATCHER_OK"] = 1 if "[OK] feed_matcher" in log else 0

# THE MISP CHECK USED TO ASSERT THAT MISP SUCCEEDED WHILE CLAIMING ONLY THAT IT
# REPORTED. It grepped for the literal "misp:", which appears in exactly one of
# the two lines the boot can write:
#
#     Feed misp: 12616 indicators          <- success, matches
#     Feed misp not refreshed: <reason>.   <- refusal, does NOT match
#
# So a feed that correctly reported a named refusal read as a feed that had not
# run at all, and the failure was in the CHECK. Found by running it -- the same
# class as the auditd verifier's two defects and the L3 verifier's two: when a
# verifier fails, suspect the verifier first.
#
# WHAT THE LABEL ACTUALLY CLAIMS is that the feed reported a RESULT, so that is
# what is tested: either shape is a result, and the line is printed so the
# reader can see WHICH came back. A feed that reported nothing at all -- the
# real failure this check exists for -- still fails.
misp_lines = [ln.strip() for ln in log.splitlines() if "Feed misp" in ln]
f["MISP_RAN"] = 1 if misp_lines else 0
f["MISP_SUCCEEDED"] = 1 if any("indicators" in ln and "not refreshed" not in ln
                               for ln in misp_lines) else 0
f["MISP_NAMED_ITS_REASON"] = 1 if any(
    "not refreshed" in ln and ":" in ln.split("not refreshed", 1)[1]
    for ln in misp_lines) else 0
f["MISP_LINE"] = (misp_lines[0][:160] if misp_lines else "")

f["OTX_SAID_WHY"] = 1 if ("AGENTAL_OTX_KEY" in log) else 0
f["NO_TRACEBACK"] = 0 if "Traceback" in log else 1
with open(sys.argv[2], "w") as fh:
    for k, v in f.items():
        fh.write("%s=%s\n" % (k, v))
PY

if [[ -n "$(flagD MISP_LINE)" ]]; then
    echo "   MISP reported: $(flagD MISP_LINE)"
fi

chk "feed_matcher is in the boot's own module table" "$(flagD MATCHER_OK)"
chk "the MISP feed reported a result during the boot" "$(flagD MISP_RAN)"
# EITHER OUTCOME IS A PASS, and they are checked separately so the output says
# which one happened rather than collapsing both into one word.
chk "and it either loaded, or named the reason it did not" \
    "$([[ "$(flagD MISP_SUCCEEDED)" == "1" || "$(flagD MISP_NAMED_ITS_REASON)" == "1" ]] && echo 1 || echo 0)"
chk "OTX named its own missing variable in the boot log" "$(flagD OTX_SAID_WHY)"
chk "the boot logged no traceback" "$(flagD NO_TRACEBACK)"

# THE API. The feed state has to reach a person, not only the log.
KEY=$(python3 -c "
import json,sys
c=json.load(open('$ROOT/config.json'))
print((c.get('flask') or {}).get('api_key') or '')
" 2>/dev/null)
if [[ -z "$KEY" ]]; then
    KEY=$(python3 -c "
import re
s=open('$ROOT/.env').read()
m=re.search(r'AGENTAL_APP_API_KEY=([0-9a-fA-F]+)', s)
print(m.group(1) if m else '')
" 2>/dev/null)
fi

if [[ -z "$KEY" ]]; then
    skip "the /api/status read (no API key found to authenticate with)"
elif [[ "$READY" != "1" ]]; then
    skip "the /api/status read (the boot did not come up)"
else
    curl -sS --max-time 20 -H "X-API-Key: $KEY" \
        "http://127.0.0.1:$PORT/api/status" -o "$TMP/status.json" \
        2>"$TMP/status.err"
    if [[ ! -s "$TMP/status.json" ]]; then
        no "/api/status returned nothing"
        sed 's/^/   [curl] /' "$TMP/status.err" | head -4
    else
        python3 - "$TMP/status.json" "$TMP/d.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
json.dump({k: d.get(k) for k in ("modules", "feeds", "threat_feed",
                                "unregistered_finding_types")},
          open(sys.argv[2], "w"))
PY
        python3 - "$TMP/d.json" "$TMP/status.json" "$TMP/d.flags" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
raw = open(sys.argv[2]).read()
f = {}
f["STATUS_200"] = 1
mods = d.get("modules") or {}
f["FEED_IN_STATUS"] = 1 if "feed_matcher" in mods else 0
# The feed state has to be SERVED, in one of the fields the dashboard reads.
f["FEED_STATE_SERVED"] = 1 if ("feed_loaded" in raw and "indicator_count" in raw) else 0
f["PER_FEED_SERVED"] = 1 if "per_feed" in raw else 0
with open(sys.argv[3], "a") as fh:
    for k, v in f.items():
        fh.write("%s=%s\n" % (k, v))
PY
        chk "/api/status answered and carries feed_matcher in its module map" \
            "$(flagD FEED_IN_STATUS)"
        chk "the feed coverage state is served over HTTP" "$(flagD FEED_STATE_SERVED)"
        chk "and the per-feed breakdown is served too" "$(flagD PER_FEED_SERVED)"
    fi
fi

# SHUTDOWN, and the port released.
if [[ -n "$BOOT_PID" ]]; then
    kill -TERM -"$BOOT_PID" 2>/dev/null
    for _ in $(seq 1 30); do
        kill -0 "$BOOT_PID" 2>/dev/null || break
        sleep 1
    done
fi
sleep 1
if ss -ltn 2>/dev/null | grep -q ":$PORT "; then
    no "port $PORT is still held after the shutdown"
else
    ok "the port was released on shutdown"
fi
chk "the shutdown logged no traceback" "$(flagD NO_TRACEBACK)"

echo
echo "E. THE OPERATOR'S THINGS ARE AS THEY WERE"

# THE RESTORE HAPPENS HERE AND IN THE TRAP, AND BOTH PROVE IT. Here, so the
# summary can show it; in the trap, so Ctrl+C, a closed window and a killed
# shell have it too. NOTE this script edits $ROOT/config.json IN PLACE rather
# than swapping a scratch copy in (it turns sensors off and moves the port for
# the boot), so the file on disk is the edited one until one of these two
# restores lands.
cp "$TMP/config.orig.json" "$ROOT/config.json"
if cmp -s "$TMP/config.orig.json" "$ROOT/config.json"; then
    ok "config.json was restored byte-identically (cmp)"
else
    no "config.json DIFFERS from the original"
fi

LIVE_SCHEMA=$(ROOT="$ROOT" python3 - <<'PY'
import os, sqlite3
c = sqlite3.connect(f"file:{os.environ['ROOT']}/agental_sec.db?mode=ro",
                    uri=True)
try:
    print(c.execute("SELECT value FROM user_preferences"
                    " WHERE key='schema_version'").fetchone()[0])
except Exception as e:
    print("error: %s" % e)
PY
)
echo "   live database schema version: $LIVE_SCHEMA (this script wrote nothing to it)"
if [[ "$LIVE_SCHEMA" == "44" || "$LIVE_SCHEMA" == "45" ]]; then
    ok "the live database is untouched at its own version (v$LIVE_SCHEMA)"
elif [[ "$LIVE_SCHEMA" == "46" ]]; then
    ok "the live database is at v46 (the owner has booted since the change)"
else
    no "the live database reports schema v$LIVE_SCHEMA, which is not expected"
fi

echo
echo "=========================================================="
echo "  $PASS passed, $FAIL failed, $SKIP skipped"
echo "=========================================================="
[[ "$FAIL" == "0" ]] || exit 1
exit 0
