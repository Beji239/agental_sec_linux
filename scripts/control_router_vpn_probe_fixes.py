#!/usr/bin/env python3
"""
scripts/control_router_vpn_probe_fixes.py — the negative control for register
section 17, the router / VPN / presence trio (tools/router_monitor.py +
tools/vpn_state.py + tools/probe.py + adapters.py), 2026-09-27.

WHAT A CONTROL IS FOR. tests/test_router_vpn_probe_fixes.py passing proves the
NEW code works. It does NOT prove the test can SEE the defects it was written
for — a check that cannot see a defect keeps passing after the fix is
reverted. So this harness puts the OLD behaviour back, one at a time, runs the
round's own test file in a copy of the tree, and requires the checks written
for that defect to go RED. A control that stays green means the check is
broken, not that the code is fine.

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
snippet asserted UNIQUE in its file. Where a reversion would have to remove an
INTERFACE the round's own fixtures drive (a parameter the checks call with),
the control moves the BEHAVIOUR the checks assert and says in its own comment
which layer it moved — a reversion a fixture cannot build is not runnable.

Run: python3 scripts/control_router_vpn_probe_fixes.py
"""
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SUBJECT = "tests/test_router_vpn_probe_fixes.py"

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
# THE IDS IN THE COMMENTS below are the round's own: RVP-1..RVP-13, as written
# up in bugfinder.md and register section 17.
CONTROLS = [
    {
        "name": "C1 -- a refused interface read is 'disconnected' again "
                "(RVP-1)",
        "file": "tools/vpn_state.py",
        "patch": {
            # The old body put the try INSIDE _tunnels and returned an empty
            # list, which status() turned into 'disconnected' + measured.
            # The interface _read_interfaces/_tunnels split stays (the
            # fixtures and status() drive it); this moves the BEHAVIOUR the
            # checks assert, by making the refusal answer an empty table.
            "old": "        self.reading_error = None\n"
                   "        try:\n"
                   "            return psutil.net_if_stats()\n"
                   "        except Exception as e:\n"
                   "            self.reading_error = f\"{type(e).__name__}: {e}\"",
            "new": "        self.reading_error = None\n"
                   "        try:\n"
                   "            return psutil.net_if_stats()\n"
                   "        except Exception as e:\n"
                   "            self.reading_error = None\n"
                   "            return {}",
        },
        "expect_failed": [
            "a refused read is unknown",
            "and is not claimed as a measurement",
            "it says what went wrong",
        ],
    },
    {
        "name": "C2 -- the sensor id hashes the raw config string again (RVP-2)",
        "file": "tools/router_monitor.py",
        "patch": {
            "old": "    digest = hashlib.sha256(\n"
                   "        _normalise_router_host(host).encode(\"utf-8\")).hexdigest()[:8]",
            "new": "    digest = hashlib.sha256(host.encode(\"utf-8\")).hexdigest()[:8]",
        },
        "expect_failed": [
            "a leading zero is the same address",
            "the sensor id follows the normalisation",
        ],
    },
    {
        "name": "C3 -- status() does int(port) with no guard again (RVP-3)",
        "file": "tools/router_monitor.py",
        "patch": {
            "old": "    try:\n"
                   "        port = int(block.get(\"port\", 161))\n"
                   "    except (TypeError, ValueError):\n"
                   "        return {\"available\": False, \"configured\": True,\n"
                   "                \"reason\": (f\"router_monitor.port is not a number: \"\n"
                   "                           f\"{block.get('port')!r}\")}",
            "new": "    port = int(block.get(\"port\", 161))",
        },
        "expect_failed": [
            "a bad port does not raise",
        ],
    },
    {
        "name": "C4 -- the listener's name drops the bound address again "
                "(RVP-4)",
        "file": "tools/router_monitor.py",
        "patch": {
            "old": "            \"setting\": f\"listener:tcp:{port}:{local}\",",
            "new": "            \"setting\": f\"listener:tcp:{port}\",",
        },
        "expect_failed": [
            "both bound addresses are recorded separately",
            "a second pass over an unchanged router changes NOTHING",
        ],
    },
    {
        "name": "C5 -- the type walk takes the whole table with it again "
                "(RVP-5)",
        "file": "tools/router_monitor.py",
        "patch": {
            "old": "    types_readable = True\n"
                   "    try:\n"
                   "        for oid, value in session.walk(OID_ARP_TYPE):\n"
                   "            suffix = oid[prefix:]\n"
                   "            if len(suffix) == 5:\n"
                   "                types[suffix] = value\n"
                   "    except SnmpError as e:\n"
                   "        types_readable = False",
            "new": "    types_readable = True\n"
                   "    if True:\n"
                   "        for oid, value in session.walk(OID_ARP_TYPE):\n"
                   "            suffix = oid[prefix:]\n"
                   "            if len(suffix) == 5:\n"
                   "                types[suffix] = value\n"
                   "    if False:\n"
                   "        types_readable = False",
        },
        "expect_failed": [
            "the pass still runs",
            "the neighbour table is still read",
        ],
    },
    {
        "name": "C6 -- the walk cap is invisible on the result again (RVP-6)",
        "file": "tools/router_monitor.py",
        "patch": {
            "old": "        \"clients_truncated\": len(clients) >= MAX_WALK_ROWS,",
            "new": "        \"clients_truncated\": False,",
        },
        "expect_failed": [
            "and the answer SAYS it was cut",
        ],
    },
    {
        "name": "C7 -- a dismissed address is raised about again (RVP-7)",
        "file": "tools/router_monitor.py",
        "patch": {
            "old": "        if me.is_dismissed(\"ip\", client[\"ip\"]):\n"
                   "            logger.debug(f\"RTR-1001 not raised for {client['ip']}: dismissed\")\n"
                   "            continue",
            "new": "        if False:\n"
                   "            continue",
        },
        "expect_failed": [
            "a dismissed address raises nothing",
            "and nothing was written about it",
        ],
    },
    {
        "name": "C8 -- a standing condition is re-filed every pass again "
                "(RVP-7b)",
        "file": "tools/router_monitor.py",
        "patch": {
            "old": "        if me.finding_already_open(\"router_monitor\", \"ip\", client[\"ip\"], title):\n"
                   "            logger.debug(f\"RTR-1001 not raised for {client['ip']}: already \"\n"
                   "                         f\"open\")\n"
                   "            continue",
            "new": "        if False:\n"
                   "            continue",
        },
        "expect_failed": [
            "and is not raised again while that one is open",
        ],
    },
    {
        "name": "C9 -- one baseline test covers both legs again (RVP-8)",
        "file": "tools/router_monitor.py",
        "patch": {
            "old": "    clients_baseline = me.router_has_history(host, table=\"clients\")\n"
                   "    config_baseline = me.router_has_history(host, table=\"config\")",
            "new": "    clients_baseline = me.router_has_history(host)\n"
                   "    config_baseline = clients_baseline",
        },
        "expect_failed": [
            # READ OUT OF THE SUBJECT'S OWN OUTPUT. The first draft named the
            # helper-level check ("and NOT to the settings leg"), which a
            # reversion of the CALLER inside collect_once cannot move — the
            # harness reported MISSING EXPECTATIONS, correctly, and sent this
            # round after the check. The subject now drives the PRODUCTION path
            # for exactly this reason, and these are its labels.
            "no 'the router's <setting> changed' row exists about a "
            "configuration that was never recorded before",
        ],
    },
    {
        "name": "C10 -- sysUpTime is fetched and dropped again (RVP-9)",
        "file": "tools/router_monitor.py",
        "patch": {
            "old": "    uptime_ticks = system.get(OID_SYS_UPTIME)\n"
                   "    if isinstance(uptime_ticks, int):",
            "new": "    uptime_ticks = system.get(OID_SYS_UPTIME)\n"
                   "    if False:",
        },
        "expect_failed": [
            "sysUpTime is recorded as a setting",
        ],
    },
    {
        "name": "C11 -- the probe re-files a standing drift again (RVP-10)",
        "file": "tools/probe.py",
        "patch": {
            "old": "        if me.finding_already_open(\"probe\", \"ip\", ip, title):\n"
                   "            logger.debug(f\"PRB-1001 not raised for {ip}: already open\")\n"
                   "            return False",
            "new": "        if False:\n"
                   "            return False",
        },
        "expect_failed": [
            "pass 2 over the SAME unchanged drift files nothing",
            "so exactly one row exists about one standing condition",
        ],
    },
    {
        "name": "C12 -- the probe's drift count follows the call, not the "
                "writer (RVP-10b)",
        "file": "tools/probe.py",
        "patch": {
            "old": "        return not (isinstance(res, dict) and res.get(\"saved\") is False)",
            "new": "        return True",
        },
        "expect_failed": [
            "a pass whose only drift was declined by the store reports ZERO "
            "filed",
            "and the run record says the same thing",
        ],
    },
    {
        "name": "C13 -- the probe's note promises an hourly pass again (RVP-11)",
        "file": "tools/probe.py",
        "patch": {
            "old": "        if overdue:\n"
                   "            return (f\"Last pass {when} ago, past the {self.interval_days} day \"\n"
                   "                    f\"interval. The next check that comes due will run a pass, \"\n"
                   "                    f\"a fingerprint comparison and the retirement sweep; a \"\n"
                   "                    f\"check that is not due does none of them.\")",
            "new": "        if overdue:\n"
                   "            return (f\"Last pass {when} ago, which is past the \"\n"
                   "                    f\"{self.interval_days} day interval. The next hourly \"\n"
                   "                    f\"check will run one.\")",
        },
        "expect_failed": [
            "the note describes the cadence it really keeps",
        ],
    },
    {
        "name": "C14 -- retirement files a row about a dismissed device again "
                "(RVP-12)",
        "file": "tools/probe.py",
        "patch": {
            "old": "            if me.is_dismissed(\"ip\", device[\"ip\"]):\n"
                   "                logger.info(\n"
                   "                    f\"{device['ip']} retired after {streak} consecutive \"\n"
                   "                    f\"misses; its finding was not filed, because the operator \"\n"
                   "                    f\"has dismissed this address.\")\n"
                   "                retired += 1\n"
                   "                continue",
            "new": "            if False:\n"
                   "                retired += 1\n"
                   "                continue",
        },
        "expect_failed": [
            "but no row was filed about a dismissed device",
        ],
    },
    {
        "name": "C15 -- the packet stamp reads status() per frame again (RVP-13)",
        "file": "adapters.py",
        "patch": {
            "old": "        now = time.monotonic()\n"
                   "        stamp, value = self._vpn_cache\n"
                   "        if now - stamp < self.VPN_STAMP_TTL:\n"
                   "            return value",
            "new": "        now = time.monotonic()\n"
                   "        stamp, value = self._vpn_cache\n"
                   "        if False:  # noqa: SIM223 - reverted cache\n"
                   "            return value",
        },
        "expect_failed": [
            "fifty frames are stamped from ONE read",
        ],
    },
]


def main() -> int:
    work = Path(tempfile.mkdtemp(prefix="s17_control_"))
    print("negative control for register section 17 (router_monitor + "
          "vpn_state + probe)")
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
