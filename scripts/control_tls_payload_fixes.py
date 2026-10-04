#!/usr/bin/env python3
"""
scripts/control_tls_payload_fixes.py -- the negative control for register
section 14, the tls_hello / payload_ring round (2026-09-26).

WHAT A CONTROL IS FOR. tests/test_tls_payload_fixes.py passing proves the NEW
code works. It does NOT prove the test can SEE the defects it was written
for -- a check that cannot see a defect keeps passing after the fix is
reverted. So this harness puts the OLD bodies back, one at a time, runs the
round's own test file in a copy of the tree, and requires the checks written
for that defect to go RED. A control that stays green means the check is
broken, not that the code is fine.

IT ALSO READS BACK WHAT IT WROTE. A patch that silently did not land -- an
anchor that changed shape since the reversion was authored -- produces a
"GREEN" that means nothing and looks exactly like a check that cannot see
the defect. Every reversion here is verified by reading the file off disk; a
reversion that did not change the bytes exits HARNESS BROKEN with its own
code, which is never confused with a defect.

AND IT REQUIRES THE SUBJECT'S OWN TWO ENDINGS. A subject that CRASHES prints
no closing line at all, and a missing line is not a green one: the harness
fails a control on a crash (its own code), distinguishing that from the
outcome it wants (checks red, rc 1, closing line present).

METHOD. Textual replacements against the CURRENT source, each anchored on a
unique snippet, each verified by re-reading. The subject is copied with
`diff -q` compared against the original before any run is quoted, because a
harness that ran against a stale copy measures the wrong bytes.

Run: python3 scripts/control_tls_payload_fixes.py
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SUBJECT = "tests/test_tls_payload_fixes.py"

HARNESS_BROKEN = 3
SUBJECT_CRASHED = 4


def die(msg: str) -> None:
    print(f"\nHARNESS BROKEN: {msg}")
    sys.exit(HARNESS_BROKEN)


def copy_tree(dst: Path) -> None:
    """A working copy, symlinks preserved, caches and the big database left
    out. The database because it is 1.4 GB and no check here needs it."""
    def ignore(_dir, names):
        skip = {"__pycache__", ".git", "logs", ".pytest_cache"}
        return [n for n in names
                if n in skip or n.endswith(".db") or n.startswith("agental_sec.db")
                or n.endswith(".db-wal") or n.endswith(".db-shm")]
    shutil.copytree(ROOT, dst, symlinks=True, ignore=ignore)


def run_subject(tree: Path) -> tuple:
    """Run the round's test file in the copy. Returns (rc, stdout+stderr)."""
    proc = subprocess.run([sys.executable, SUBJECT], cwd=str(tree),
                          capture_output=True, text=True, timeout=900)
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def failed_labels(out: str) -> set:
    """Every label the subject printed as FAIL, read OUT of its own output."""
    return {m.group(1).strip()
            for m in re.finditer(r"^  FAIL  \[(.*?)\]: ", out, re.M)}


def completed(out: str) -> bool:
    """The subject reached one of its OWN two endings."""
    return ("ALL CHECKS PASSED" in out) or ("FAILURES: [" in out)


def apply_reversion(tree: Path, rel: str, old: str, new: str, label: str) -> None:
    """One textual replacement, verified by reading the file back off disk."""
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
    print(f"    patched {rel} ({label}, {len(old)} chars -> {len(new)})")


# THE REVERSIONS. Each names the defect it restores and the checks that must
# go red because of it. The old bodies are QUOTED from the pre-round source.

CONTROLS = [
    {
        "name": "C1 -- the SNI is decoded with IDNA again (the homograph)",
        "file": "tools/tls_hello.py",
        "patch": {
            "old": """            name = r.need(name_len)
            if name_type == 0:                       # host_name
                if not _is_ascii(name):
                    # Not decoded, refused. See the docstring.
                    return None
                try:
                    text = name.decode("ascii", errors="strict")
                except Exception:
                    return None""",
            "new": """            name = r.need(name_len)
            if name_type == 0:                       # host_name
                # REVERTED FOR THE CONTROL: the IDNA decode that turned an
                # A-label into a Cyrillic homograph.
                text = name.decode("idna" if _is_ascii(name) else "utf-8",
                                   errors="strict")""",
        },
        "expect_failed": [
            "the A-label is stored AS THE WIRE CARRIED IT",
            "the stored name is NOT the Cyrillic homograph",
            "a feed listing the A-label MATCHES the stored name",
        ],
    },
    {
        "name": "C2 -- a name longer than its extension is served in part",
        "file": "tools/tls_hello.py",
        "patch": {
            "old": """            if r.i + name_len > end:
                return None
            name = r.need(name_len)""",
            "new": """            # REVERTED FOR THE CONTROL: the overrun check removed.
            name = r.need(name_len)""",
        },
        "expect_failed": [
            "a name whose length overruns the extension is REFUSED",
        ],
    },
    {
        "name": "C3 -- ALPN collapses 'could not read' into 'none offered'",
        "file": "tools/tls_hello.py",
        "patch": {
            "old": """        declared = r.u16()                           # list length
        end = r.i + declared
        if end > len(body):
            # The list length overruns the extension it lives in. Not "none
            # offered": unreadable.
            return None""",
            "new": """        declared = r.u16()                           # list length
        end = r.i + declared
        if end > len(body):
            # REVERTED FOR THE CONTROL: collapse to "none offered".
            return []""",
        },
        "expect_failed": [
            "a present but UNREADABLE ALPN is None, not []",
        ],
    },
    {
        "name": "C4 -- the ring stops counting the bytes it never held",
        "file": "tools/payload_ring.py",
        "patch": {
            "old": """            unheld = max(0, len(data) - len(chunk))

            with self._lock:
                self.frames_seen += 1
                self.bytes_unheld += unheld""",
            "new": """            unheld = 0    # REVERTED FOR THE CONTROL: the door count gone

            with self._lock:
                self.frames_seen += 1""",
        },
        "expect_failed": [
            "the bytes never held are PUBLISHED",
            "the note NAMES the untaken bytes",
            "and carries how much was never held",
            "status publishes the ring-wide figure",
        ],
    },
    {
        "name": "C5 -- search() answers an empty needle again",
        "file": "tools/payload_ring.py",
        "patch": {
            "old": """        if not needle:
            return {
                "searched": False, "matched": None,
                "reason": ("An empty search string was given, so nothing \"""",
            "new": """        if False:    # REVERTED FOR THE CONTROL: empty needle accepted
            return {
                "searched": False, "matched": None,
                "reason": ("An empty search string was given, so nothing \"""",
        },
        "expect_failed": [
            "an empty needle is REFUSED, not answered",
            "matched is None, never False or True",
        ],
    },
    {
        "name": "C6 -- flush writes the caller's port again",
        "file": "tools/payload_ring.py",
        "patch": {
            "old": """            rows = self._write_frames(
                frames, src_ip, dst_ip, flow_port, protocol,
                trigger_detection_id, trigger_entity, was_armed)""",
            "new": """            rows = self._write_frames(
                frames, src_ip, dst_ip, dst_port, protocol,
                trigger_detection_id, trigger_entity, was_armed)""",
        },
        "expect_failed": [
            "the row carries the FLOW's service port, not the caller's",
        ],
    },
    {
        "name": "C7 -- arm() accepts any non-empty string again",
        "file": "tools/payload_ring.py",
        "patch": {
            "old": """        if not _looks_like_address(d):
            return {"armed": False, "destination": d,""",
            "new": """        if False:    # REVERTED FOR THE CONTROL: no destination check
            return {"armed": False, "destination": d,""",
        },
        "expect_failed": [
            "a hostname is REFUSED",
            "an impossible v4 is refused",
            "a CIDR range is refused",
        ],
    },
    {
        "name": "C8 -- the adapter builds the ring without its config",
        "file": "adapters.py",
        "patch": {
            "old": """            self._payload = payload_ring.PayloadRing(
                self.session_id,
                (self.config or {}).get("payload_capture"))""",
            "new": """            # REVERTED FOR THE CONTROL: no config reaches the ring.
            self._payload = payload_ring.PayloadRing(self.session_id)""",
        },
        "expect_failed": [
            "and the ADAPTER supplies it (the wiring, in running code)",
        ],
    },
    {
        "name": "C9 -- the eviction branch drops the name with no row again",
        "file": "adapters.py",
        "patch": {
            "old": """            if evicted is not None:
                (e_src, _e_sport, e_dst, e_dport) = oldest
                self._record_tls(
                    e_src, e_dst, e_dport,
                    evicted["proc"][0], evicted["proc"][1],
                    _unreadable(
                        f"evicted from the pending table to make room: more "
                        f"than {self.MAX_PENDING_HELLOS} half-read "
                        f"ClientHellos were being held at once"))""",
            "new": """            # REVERTED FOR THE CONTROL: the row write removed.
            pass""",
        },
        "expect_failed": [
            "making room WROTE A ROW rather than only counting",
        ],
    },
    {
        "name": "C10 -- stop() drops half-read hellos with no row again",
        "file": "adapters.py",
        "patch": {
            "old": """        try:
            self._reap_pending_tls(
                force=True,
                reason=("the sensor stopped before the rest of this hello "
                        "arrived, so this handshake was never read"))""",
            "new": """        try:
            pass    # REVERTED FOR THE CONTROL: no reap at stop""",
        },
        "expect_failed": [
            "stop() reaped it",
        ],
    },
    {
        "name": "C11 -- the arm card is a bare tool name again",
        "file": "core/tool_registry.py",
        "patch": {
            "old": """    if name == "arm_payload_capture":
        # ,,,, ADDED 2026-09-26. There was NO branch here, so this function's
        # fallback `return name` shipped, and the approval card an operator""",
            "new": """    if False:    # REVERTED FOR THE CONTROL: no card branch
        # ,,,, ADDED 2026-09-26. There was NO branch here, so this function's
        # fallback `return name` shipped, and the approval card an operator""",
        },
        "expect_failed": [
            "the card is no longer the bare tool name",
        ],
    },
    {
        "name": "C12 -- the disarm text promises a clear path again",
        "file": "core/tool_registry.py",
        "patch": {
            "old": """            "the payload retention window, which is pruned at boot and at "
            "shutdown. CORRECTED 2026-09-26 (register section 14): this "
            "sentence used to end '... or the user can clear them', and "
            "MEASURED there is no such path anywhere in this app -- no route "
            "serves payload rows for clearing and the only DELETE against "
            "payload_capture is the retention prune itself. Do not tell the "
            "user they can clear them.\"""",
            "new": """            "the payload retention window, or the user can clear them.\"""",
        },
        "expect_failed": [
            "the old disarm advice sentence is gone",
            "the operative sentence now names the prune schedule",
        ],
    },
    {
        "name": "C13 -- the armed status note claims own flushing again",
        "file": "tools/payload_ring.py",
        "patch": {
            "old": """                f"{self.ring_bytes // 1024} KB. It does NOT write anything by "
                f"itself: an armed flow still waits for a detection to flush "
                f"it.")""",
            "new": """                f"{self.ring_bytes // 1024} KB. It does NOT write anything by "
                f"itself: an armed flow flushes on its own.")""",
        },
        "expect_failed": [
            "status() says an armed flow still waits for a detection",
            "the false claim is gone from the running code",
        ],
    },
    {
        "name": "C14 -- the arm description says the traffic is being written",
        "file": "core/tool_registry.py",
        "patch": {
            "old": """            "flow. If nothing fires, arming produces no rows at all -- so do "
            "not tell the user their traffic is being recorded.""",
            "new": """            "flow. Full payload to and from this address is now written to "
            "disk.""",
        },
        "expect_failed": [
            "the arm tool text tells the model NOT to say it records",
        ],
    },
    {
        "name": "C15 -- the payload note promises a clock that is not running",
        "file": "core/tool_registry.py",
        "patch": {
            "old": """            "Rows already written to the database are returned by flow and "
            "by the detection that flushed them. Payload ages out on a "
            "seven day window by default, and the prune that enforces it "
            "runs at BOOT and at SHUTDOWN: a run that is never restarted "
            "keeps its payload until the next restart, so do not describe "
            "the window as a clock that is always running. It is the only "
            "table in this app with a lifetime that short, because it is the "
            "only one that can contain the user's own plaintext. "
            "CORRECTED 2026-09-26 (register section 14): this used to read "
            "'Payload is deleted after seven days by default', which is true "
            "of the prune schedule only, not of any running process.""",
            "new": """            "Rows already written to the database are returned by flow and "
            "by the detection that flushed them. Payload is deleted after "
            "seven days by default: it is the only table in this app with a "
            "lifetime that short, because it is the only one that can "
            "contain the user's own plaintext.""",
        },
        "expect_failed": [
            "the old payload-note advice sentence is gone",
            "the operative note now names boot and shutdown",
            "the payload note carries its correction",
        ],
    },
    {
        "name": "C16 -- the schema prose claims a second way rows arrive",
        "file": "core/migrations.py",
        "patch": {
            "old": """    ROWS ARRIVE ONE WAY: a detector fired and flushed the flow that caused
    it. CORRECTED 2026-09-26 (register section 14): this sentence used to
    say "a detector fired and flushed the flow that caused it, or the user
    armed that destination by name", and MEASURED that second way does not
    exist -- arming gives an address a bigger memory buffer and writes
    nothing; there is no flush anywhere in either tree that runs because a
    destination was armed. The always-on part of 113.6 is a MEMORY ring
    that is never written to disk at all, and the sentence that used to end
    this paragraph ("If this table is large, something armed was left
    armed") was a conclusion drawn from the claim that was not true.""",
            "new": """    ROWS ARRIVE ONLY TWO WAYS, and neither is "always on": a detector fired
    and flushed the flow that caused it, or the user armed that destination
    by name. The always-on part of 113.6 is a MEMORY ring that is never
    written to disk at all. If this table is large, something armed was left
    armed.""",
        },
        "expect_failed": [
            "'ROWS ARRIVE ONLY TWO WAYS' is gone from the running code",
            "the migration note carries its correction and says ONE way",
        ],
    },
]


def main() -> int:
    work = Path(tempfile.mkdtemp(prefix="s14_control_"))
    print("negative control for register section 14 (tls_hello / payload_ring)")
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
        print(f"\n{len(bad)} control(s) did not red their own checks. A control "
              f"that agrees with the fix is broken, or the check is blind.")
        shutil.rmtree(work, ignore_errors=True)
        return 1
    print(f"\nAll {len(summary)} controls held: each defect's checks go red "
          f"when the defect is put back.")
    shutil.rmtree(work, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
