#!/usr/bin/env python3
"""
scripts/control_dns_fixes.py — the negative control for register section 15,
the dns round (tools/dns_monitor.py + tools/dns_inspector.py), 2026-09-27.

WHAT A CONTROL IS FOR. tests/test_dns_fixes.py passing proves the NEW code
works. It does NOT prove the test can SEE the defects it was written for — a
check that cannot see a defect keeps passing after the fix is reverted. So
this harness puts the OLD behaviour back, one at a time, runs the round's own
test file in a copy of the tree, and requires the checks written for that
defect to go RED. A control that stays green means the check is broken, not
that the code is fine.

IT READS BACK WHAT IT WROTE. A patch that silently did not land — an anchor
that moved since the reversion was authored — produces a "GREEN" that means
nothing and looks exactly like a check that cannot see the defect. Every
reversion is verified against the bytes on disk, and one that did not change
them exits HARNESS BROKEN with its own code.

IT REQUIRES THE SUBJECT'S OWN CLOSING LINE. A subject that CRASHES prints no
closing line at all, and a missing line is not a green one: such a control
gets its own verdict and its own exit code, never confused with the outcome
this harness wants (checks red, rc 1, closing line present).

IT COMPARES THE COPIED SUBJECT AGAINST THE ORIGINAL before quoting any run,
because a harness that ran against a stale copy measures the wrong bytes.

METHOD. Textual replacements against the CURRENT source, each anchored on a
snippet asserted UNIQUE in its file. The old bodies are QUOTED from the
pre-round source; where the pre-round body cannot be restored without also
restoring an interface the round's fixtures drive (the cursor table, the
finding writer's sensor argument), the control moves the BEHAVIOUR the checks
assert and says in its own comment which layer it moved.

Run: python3 scripts/control_dns_fixes.py
"""
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SUBJECT = "tests/test_dns_fixes.py"

HARNESS_BROKEN = 3
SUBJECT_CRASHED = 4


def die(msg: str) -> None:
    print(f"\nHARNESS BROKEN: {msg}")
    sys.exit(HARNESS_BROKEN)


def copy_tree(dst: Path) -> None:
    """A working copy; caches and the big database are left out."""
    def ignore(_dir, names):
        skip = {"__pycache__", ".git", "logs", ".pytest_cache"}
        return [n for n in names
                if n in skip or n.endswith(".db") or n.startswith("agental_sec.db")
                or n.endswith(".db-wal") or n.endswith(".db-shm")]
    shutil.copytree(ROOT, dst, symlinks=True, ignore=ignore)


def run_subject(tree: Path) -> tuple:
    proc = subprocess.run([sys.executable, SUBJECT], cwd=str(tree),
                          capture_output=True, text=True, timeout=1800)
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def failed_labels(out: str) -> set:
    """Every label the subject printed as FAIL, read OUT of its own output."""
    return {m.group(1).strip()
            for m in re.finditer(r"^  FAIL  \[(.*?)\]: ", out, re.M)}


def completed(out: str) -> bool:
    """The subject reached one of its OWN two endings."""
    return ("ALL CHECKS PASSED" in out) or ("FAILURES: [" in out)


def apply_reversion(tree: Path, rel: str, old: str, new: str,
                    label: str) -> None:
    path = tree / rel
    if not path.exists():
        die(f"no such file for {label}: {rel}")
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        die(f"{label}: the anchor appears {count} times in {rel}, not once. "
            f"A reversion this ambiguous measures neither site.")
    patched = text.replace(old, new)
    if patched == text:
        die(f"{label}: the replacement changed nothing in {rel}")
    path.write_text(patched, encoding="utf-8")
    if path.read_text(encoding="utf-8") == text:
        die(f"{label}: the write did not land in {rel}")
    print(f"    patched {rel} ({len(old)} chars -> {len(new)})")


# THE REVERSIONS. Each names the defect it restores and the checks that must
# go red because of it.
#
# THE RENAMED IDS IN THE COMMENTS below are the round's own: DNS-1..DNS-18,
# as written up in bugfinder.md and register section 15.
CONTROLS = [
    {
        "name": "C1 -- the importer calls analyse_once without session_id "
                "(DNS-1)",
        "file": "main.py",
        "patch": {
            "old": "                        ins = dns_inspector.analyse_once("
                   "config, session_id)",
            "new": "                        ins = dns_inspector.analyse_once("
                   "config)",
        },
        "expect_failed": [
            "the inspection was REACHED on the first pass",
            "and received the caller's session_id",
        ],
    },
    {
        "name": "C2 -- the import cursor goes back into the policy table "
                "(DNS-2)",
        "file": "tools/dns_monitor.py",
        "patch": {
            # The behaviour, not the signature: import_once's rotation branch
            # is left alone because C3's checks drive it.
            "old": '''    def _do(conn):
        conn.execute(
            f"INSERT INTO {_CURSOR_TABLE} (name, value, identity) "
            f"VALUES (?, ?, ?) ON CONFLICT(name) DO UPDATE SET "
            f"value = excluded.value, identity = excluded.identity, "
            f"updated_at = CURRENT_TIMESTAMP",
            (name, None if value is None else str(value),
             None if identity is None else str(identity)))''',
            "new": '''    def _do(conn):
        from core import memory_engine as _me
        _me.set_preference(name, None if value is None else str(value))''',
        },
        "expect_failed": [
            "a cursor write does NOT move the policy digest",
            "and writes NO config_observed journal entry",
            "both cursors live in dns_cursor, value AND identity",
            "and NOT ONE dns key is left in the policy table",
            "no RUNNING line in either module writes a preference",
        ],
    },
    {
        "name": "C3 -- the rotation check reverts to the offset alone (DNS-3)",
        "file": "tools/dns_monitor.py",
        "patch": {
            "old": '''    rotated = (source == SOURCE_ADGUARD
               and stored_identity is not None
               and current_identity != stored_identity)''',
            "new": '''    rotated = (source == SOURCE_ADGUARD
               and stored_identity is not None
               and stored_identity != current_identity
               and False)''',
        },
        "expect_failed": [
            "pass 2 reads the ROTATED file from the start: all 12 rows land",
            "and the pass SAYS a rotation happened",
            "the store holds 3 + 12, not 3 + the rows past the old offset",
        ],
    },
    {
        "name": "C4 -- the last line is consumed whether or not it is "
                "complete (DNS-4)",
        "file": "tools/dns_monitor.py",
        "patch": {
            "old": '''            if not raw.endswith(b"\\n"):
                break''',
            "new": '''            if not raw.endswith(b"\\n"):
                end_offset += len(raw)
                break''',
        },
        "expect_failed": [
            "when the rest arrives the completed line IS read",
        ],
    },
    {
        "name": "C5 -- a malformed line is passed over in silence (DNS-5)",
        "file": "tools/dns_monitor.py",
        "patch": {
            "old": '                notes["line_skipped"] = notes.get('
                   '"line_skipped", 0) + 1',
            "new": "                pass",
        },
        "expect_failed": [
            "a malformed line is COUNTED in the notes",
        ],
    },
    {
        "name": "C6 -- the local timestamp goes back into the column (DNS-6)",
        "file": "tools/dns_monitor.py",
        "patch": {
            "old": '''    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat()''',
            "new": '''    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()''',
        },
        "expect_failed": [
            "an AdGuard local stamp is normalised to UTC",
            "the window now selects BOTH rows (the local one is inside it)",
        ],
    },
    {
        "name": "C7 -- the NXDOMAIN title carries its counts again (DNS-7)",
        "file": "tools/dns_inspector.py",
        "patch": {
            "old": '                title = f"Most of what {client_ip} asked '
                   'for does not exist"',
            "new": '                title = (f"Most of what {client_ip} asked '
                   'for does not "\n                         f"exist ({nxdomain} '
                   'of {total})")',
        },
        "expect_failed": [
            "four passes of ONE unchanged condition write ONE row",
            "and its title carries no count",
        ],
    },
    {
        "name": "C8 -- the volume title carries its count again (DNS-8)",
        "file": "tools/dns_inspector.py",
        "patch": {
            "old": '            title = f"Unusual DNS query volume from '
                   '{client_ip}"',
            "new": '            title = (f"Unusual DNS query volume from '
                   '{client_ip}: {total} "\n                     f"queries in '
                   '{DNS_ACTIVITY_WINDOW_HOURS}h")',
        },
        "expect_failed": [
            # READ OUT OF THE SUBJECT'S OWN OUTPUT, 2026-09-27, after the
            # first run of this harness. The draft also claimed the
            # two-client check would go red here, and it does NOT: a title
            # carrying a count still fires on the FIRST pass — what it breaks
            # is the SECOND pass, which writes a new row instead of collapsing
            # onto the open one, and that is what these two checks measure.
            # The two-client check is C11's business, and it does go red there.
            "the VOLUME title does not move with its count either",
            "the old moving title is gone: (f\"Unusual DNS query volume "
            "from {clie...",
        ],
    },
    {
        "name": "C9 -- the tunnel title carries its count again (DNS-9)",
        "file": "tools/dns_inspector.py",
        "patch": {
            "old": '        title = f"Possible DNS tunnel under {registered} '
                   'from {client_ip}"',
            "new": '        title = (f"Possible DNS tunnel: {client_ip} sent '
                   '{distinct} encoded "\n                 f"names under '
                   '{registered}")',
        },
        "expect_failed": [
            "the tunnel title does not move with its count",
            "the old moving title is gone: (f\"Possible DNS tunnel: "
            "{client_ip} se...",
        ],
    },
    {
        "name": "C10 -- the TXT title carries its count again (DNS-10)",
        "file": "tools/dns_inspector.py",
        "patch": {
            "old": '            title = f"Unusual TXT record volume from '
                   '{client_ip}"',
            "new": '            title = (f"Unusual TXT record volume from '
                   '{client_ip}: {txt} in "\n                     '
                   'f"{DNS_ACTIVITY_WINDOW_HOURS}h")',
        },
        "expect_failed": [
            "the TXT title does not move with its count either",
        ],
    },
    {
        "name": "C11 -- the median contains the subject again (DNS-11)",
        "file": "tools/dns_inspector.py",
        "patch": {
            "old": "    others = [t for ip, (t, _nx, _tx) in totals.items()\n"
                   "              if ip != client_ip and t >= "
                   "VOLUME_MEDIAN_FLOOR]\n"
                   "    return _median(others)",
            "new": "    others = [t for ip, (t, _nx, _tx) in totals.items()\n"
                   "              if t >= VOLUME_MEDIAN_FLOOR]\n"
                   "    return _median(others)",
        },
        "expect_failed": [
            "the median of the others for A=10000, B=60",
            "the two-client network now FIRES where the old code was silent",
        ],
    },
    {
        "name": "C12 -- the finding falls back to the HOST sensor again "
                "(DNS-12)",
        "file": "tools/dns_inspector.py",
        "patch": {
            "old": '''                        title=title,
                        sensor_id=resolver_sensor_id(),
                        description=(
                            f"Names that returned NXDOMAIN in the last "''',
            "new": '''                        title=title,
                        description=(
                            f"Names that returned NXDOMAIN in the last "''',
        },
        "expect_failed": [
            "the NXDOMAIN finding names the resolver sensor",
        ],
    },
    {
        "name": "C13 -- AdGuard's reason goes back to the bare code (DNS-13)",
        "file": "tools/dns_monitor.py",
        "patch": {
            "old": '                "status":        _adguard_reason('
                   'result.get("Reason")),',
            "new": '                "status":        result.get("Reason") or '
                   '"answered",',
        },
        "expect_failed": [
            "the reader stores the vendor's NAME, not the bare code",
        ],
    },
    {
        "name": "C14 -- Pi-hole status 18 is unknown and unblocked again "
                "(DNS-14)",
        "file": "tools/dns_monitor.py",
        "patch": {
            "old": '    18: "blocked_upstream_ede15",\n}',
            "new": "}",
        },
        "expect_failed": [
            "Pi-hole status 18 (EXTERNAL_BLOCKED_EDE15) is decoded",
        ],
    },
    {
        "name": "C15 -- a blocked query is counted as answered again "
                "(DNS-15)",
        "file": "tools/dns_monitor.py",
        "patch": {
            "old": "_PIHOLE_BLOCKED = {1, 4, 5, 6, 7, 8, 9, 10, 11, 15, 16, "
                   "18}",
            "new": "_PIHOLE_BLOCKED = {1, 4, 5, 6, 7, 8, 9, 10, 11, 15, 16}",
        },
        "expect_failed": [
            # READ OUT OF THE SUBJECT'S OWN OUTPUT, 2026-09-27. The first
            # draft carried the two leading spaces the check's label has in
            # the SOURCE, while the harness strips labels before comparing —
            # so this control reported a broken expectation against a run
            # that was really failing red, which is the expensive direction.
            "and it is COUNTED AS BLOCKED (FTL's own set includes it)",
            "the blocked set holds exactly the codes FTL marks blocked",
        ],
    },
    {
        "name": "C16 -- a quiet pass logs nothing again (DNS-16)",
        "file": "tools/dns_monitor.py",
        "patch": {
            "old": '''    dropped = notes.get("rows_dropped", 0)
    logger.info(''',
            "new": '''    dropped = notes.get("rows_dropped", 0)
    if result["seen"] == 0:
        return {
            "ran": True, "source": source, "sensor_id": sensor_id,
            "read": result["seen"], "inserted": result["inserted"],
            "cursor": new_cursor,
            "rows_read_at_source": notes.get("rows_read", result["seen"]),
            "rows_dropped": dropped, "rotated": rotated,
            "lines_skipped": notes.get("line_skipped", 0),
            "more_available": bool(notes.get("hit_limit")), "reason": None,
        }
    logger.info(''',
        },
        "expect_failed": [
            "a pass that read nothing still logs its own line",
            "and the line carries the counts",
        ],
    },
    {
        "name": "C17 -- more_available follows the survivors again (DNS-17)",
        "file": "tools/dns_monitor.py",
        "patch": {
            "old": '            "hit_limit": len(fetched) >= limit,',
            "new": '            "hit_limit": len(rows) >= limit,',
        },
        "expect_failed": [
            "a source with a FULL batch reports hit_limit from its own count",
        ],
    },
    {
        "name": "C18 -- perf's DNS window goes back to the space shape (DNS-18)",
        "file": "core/perf.py",
        "patch": {
            "old": "        dns_start, dns_end = _sql_ts_iso(hour_start), "
                   "_sql_ts_iso(\n"
                   "            hour_start + timedelta(hours=1))",
            "new": "        dns_start, dns_end = _sql_ts(hour_start), "
                   "_sql_ts(\n"
                   "            hour_start + timedelta(hours=1))",
        },
        "expect_failed": [
            "the hour's bucket carries the DNS row that fell inside it",
        ],
    },
    {
        "name": "C19 -- the beacon parses without its import again (DNS-19)",
        "file": "tools/dns_inspector.py",
        "patch": {
            "old": "    # Parsing the stored stamps needs these; the CUTOFF "
                   "does not, it goes\n"
                   "    # through the funnel. Do not delete this as unused.\n"
                   "    from datetime import datetime, timezone\n",
            "new": "",
        },
        "expect_failed": [
            "the beacon check RUNS and returns a count",
            "and DNS-1002 is in the store",
            "_check_beacons imports what it parses with",
        ],
    },
]


def main() -> int:
    work = Path(tempfile.mkdtemp(prefix="s15_control_"))
    print("negative control for register section 15 (dns_monitor + "
          "dns_inspector)")
    print(f"subject:  {SUBJECT}")
    print(f"workdir:  {work}\n")

    print("== baseline: the PRISTINE copy must be green before any control ==")
    base_tree = work / "baseline"
    copy_tree(base_tree)
    rc, out = run_subject(base_tree)
    base_failed = failed_labels(out)
    if rc != 0 or base_failed or not completed(out):
        print(out[-3000:])
        die(f"the pristine copy is not green (rc={rc}, "
            f"failed={sorted(base_failed)}, completed={completed(out)}). "
            f"Every control below would be measuring this, not the reversion.")
    print(f"    pristine copy: rc 0, 0 failures. "
          f"{len(re.findall(r'^  PASS', out, re.M))} checks pass.\n")

    summary = []
    for spec in CONTROLS:
        print(f"== {spec['name']} ==")
        tree = work / spec["name"].split(" ")[0]
        copy_tree(tree)
        apply_reversion(tree, spec["file"], spec["patch"]["old"],
                        spec["patch"]["new"], spec["name"])
        # The copy must really be a copy before this run is quoted.
        if subprocess.run(["diff", "-q", str(tree / SUBJECT),
                           str(ROOT / SUBJECT)],
                          capture_output=True).returncode != 0:
            die(f"{spec['name']}: the copied subject differs from the "
                f"original before the run; refusing to quote this control.")

        rc, out = run_subject(tree)
        if not completed(out):
            print(f"   SUBJECT PRINTED NO CLOSING LINE (rc={rc}). "
                  f"A crashed subject measures nothing.")
            print(out[-1500:])
            summary.append((spec["name"], "SUBJECT CRASHED"))
            continue

        got = failed_labels(out)
        missing = [e for e in spec["expect_failed"] if e not in got]
        if missing:
            print(f"   SUBJECT rc={rc}, red labels: {sorted(got)}")
            print(f"   MISSING EXPECTATIONS: {missing}")
            summary.append((spec["name"], "BROKEN EXPECTATION"))
            continue

        extra = sorted(got - set(spec["expect_failed"]))
        verdict = "RED AS INTENDED" if rc != 0 else "GREEN -- CHECK IS BLIND"
        print(f"   subject rc={rc}; the expected checks went red: "
              f"{len(spec['expect_failed'])} of {len(spec['expect_failed'])}")
        if extra:
            print(f"   (also red, and not claimed as this control's: {extra})")
        summary.append((spec["name"], verdict))

    print("\n" + "=" * 66)
    bad = [s for s in summary if s[1] != "RED AS INTENDED"]
    for name, verdict in summary:
        print(f"  {verdict:<24} {name}")
    print("=" * 66)
    if bad:
        print(f"\n{len(bad)} control(s) did not red their own checks. A "
              f"control that agrees with the fix is broken, or the check is "
              f"blind.")
        return 1
    print(f"\nAll {len(summary)} controls held: each defect's checks go red "
          f"when the defect is put back.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
