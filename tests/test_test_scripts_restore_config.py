#!/usr/bin/env python3
"""
tests/test_test_scripts_restore_config.py -- the LA-4 fix, held by a test.

WHAT THIS IS ABOUT. On 2026-09-25 the operator's config.json was found on a
test harness's scratch port (5298, auto_open_browser false), left there by a
run that was interrupted before its restore line. Two defects' worth of
history later (LA-1, LA-3 in toolaudit.md), the six verifier scripts that swap
the owner's config in and out now restore it IN THE TRAP and PROVE the restore, on
every exit path. This file holds that property so it cannot quietly rot.

IT IS NOT A GREP TEST, and the difference matters here. A text search for
"trap cleanup EXIT" passes against a script whose trap does nothing. So this
file:

  * takes each script's OWN LA-4 head out of the REAL file (everything through
    the link checks) and puts its ROOT on a SANDBOX holding a byte copy of the
    operator's config. The real config.json is never written by anything here;
    the sandbox is asserted byte-identical to it at the end.
  * drives the head with a three-line body that SWAPS the sandbox config --
    the same thing the script's real body does -- under a child whose signal
    disposition is reset, because an INT trap cannot be installed in a child
    that inherited SIGINT ignored. MEASURED: arms launched with `&` from a
    non-interactive shell read 137; the same arm through subprocess reads 130.
  * asserts the exit codes a hand-run script reports for Ctrl+C (130),
    SIGTERM (143) and SIGHUP (129) -- the codes LA-3's matrix measured -- and
    that the trap NAMED the put-back it did.
  * asserts the LINK REFUSAL is real: with a second name for the sandbox file
    in place (ln), the run must exit 2 and must NOT swap anything.
  * asserts the FAILED-PROOF branch: with the trap's put-back simulated as
    failing, the exit must be 1, the message loud, and the copy KEPT.

WHY THE SANDBOX. The operator's app runs as root on this host and the owner's config
is live. A test that exercises restore logic must be able to swap something;
the only safe something is a copy of the owner's file at a path this test owns.

DO NOT RUN THIS BESIDE ANOTHER HARNESS THAT GLOBS /tmp/agental_*. The six
verifiers create their scratch dirs as /tmp/agental_<name>_live.XXXX, and a
harness that sweeps those globs (as /tmp/agental_la4/six_restore_control.sh
does, deliberately) will delete THIS test's scratch dir mid-run and the trap
will find no copy to put back. MEASURED 2026-09-25: that produced a run of
nine failures that all disappeared in isolation.
"""
import json
import os
import pathlib
import shutil
import signal
import subprocess
import sys
import _skip
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
LIVE = ROOT / "config.json"
SCRIPTS = ROOT / "scripts"

# the six that swap the owner's config, plus the two this round fixed earlier
SWAPPERS = ["verify_auditd", "verify_case_memory", "verify_ebpf_events",
            "verify_feeds", "verify_local_integrity", "verify_t9_live",
            "verify_duty_live", "verify_launchers_live"]

fails = []


def _default_signals():
    """preexec_fn for children: undo any inherited SIG_IGN disposition.

    A signal ignored on entry cannot be trapped by bash (POSIX), so an arm
    that inherits SIGINT ignored cannot install its INT trap and its body runs
    to completion. Measured 2026-09-25: that reads as rc 0 where a real Ctrl+C
    reports 130.
    """
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    signal.signal(signal.SIGTERM, signal.SIG_DFL)
    signal.signal(signal.SIGHUP, signal.SIG_DFL)
    signal.signal(signal.SIGQUIT, signal.SIG_DFL)


def check(label, got, want):
    ok = got == want
    print("  %s  %s: %r" % ("PASS" if ok else "FAIL", label, got)
          + ("" if ok else "  (want %r)" % (want,)))
    if not ok:
        fails.append(label)


# The scripts derive ROOT and refuse one without main.py, so a sandbox gets
# the ROOT line replaced and an empty main.py.
DERIVED_ROOT = ('ROOT="${AGENTAL_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." '
                '&& pwd)}"')


def point_at(head: str, sandbox) -> str:
    assert DERIVED_ROOT in head, "the script's ROOT line has changed shape"
    (sandbox / "main.py").touch()
    return head.replace(DERIVED_ROOT, "ROOT=%s" % sandbox, 1)


def head_of(name: str) -> str:
    """The real script's LA-4 head: through the end of the link checks."""
    text = (SCRIPTS / (name + ".sh")).read_text()
    lines = text.splitlines(keepends=True)
    last = None
    for i, ln in enumerate(lines):
        if "find / -xdev -samefile" in ln:
            last = i
    assert last is not None, "no LA-4 block in %s.sh" % name
    return "".join(lines[:last + 3])


def run_head(name, work, body, sig=None, sig_target="group", wait_s=15.0):
    """Run a script's own head + body in a scratch dir, optionally signalled.

    The child is started with the signal dispositions RESET TO DEFAULT, and
    that is measured rather than tidy: this test file may itself be run as a
    background job (or by a runner that pipes its output), in which case
    SIGINT arrives at this process as IGNORED and a child would inherit that.
    A signal ignored on entry cannot be trapped by bash (POSIX), so the arm's
    own INT trap would never install, the body would run to completion and the
    exit would read 0 -- an interrupted run reading green, which is the exact
    defect this file exists to catch. Measured 2026-09-25 on the control
    harness: both INT arms failed for this reason alone.

    Returns (returncode, output, sandbox_is_reference, timed_out).
    """
    sandbox = work / "sandbox"
    sandbox.mkdir(exist_ok=True)
    shutil.copyfile(LIVE, sandbox / "config.json")

    variant = work / (name + ".run.sh")
    head = point_at(head_of(name), sandbox)
    head = head.replace('pkill -f "agental_', ': pkill -f "agental_')
    variant.write_text(head + "\n" + body + "\n")

    out_path = work / (name + ".out")
    with open(out_path, "wb") as fh:
        p = subprocess.Popen(["bash", str(variant)], stdout=fh,
                             stderr=subprocess.STDOUT, start_new_session=True,
                             preexec_fn=_default_signals)
    deadline = time.time() + wait_s
    if sig is not None:
        # wait for the swap to land, then signal
        for _ in range(200):
            if not (sandbox / "config.json").read_bytes() == LIVE.read_bytes():
                break
            time.sleep(0.05)
        if sig_target == "group":
            os.killpg(os.getpgid(p.pid), sig)
        else:
            os.kill(p.pid, sig)
    try:
        rc = p.wait(timeout=wait_s + 10)
    except subprocess.TimeoutExpired:
        p.kill()
        p.wait()
        rc = "TIMEOUT"

    out = out_path.read_text(errors="replace")
    restored = (sandbox / "config.json").read_bytes() == LIVE.read_bytes()
    return rc, out, restored


def _finish(live_before):
    """The residue section and the summary, in one place: the normal end and
    the early exit after a missing LA-4 head both go through it."""
    print("\nE. this file's own residue")
    check("the operator's config.json is byte-identical to entry",
          LIVE.read_bytes() == live_before, True)
    check("the owner's file still has exactly one name",
          os.stat(LIVE).st_nlink, 1)

    print()
    if fails:
        print("FAILED: %d check(s):" % len(fails))
        for f in fails:
            print("  - %s" % f)
        return 1
    print("all checks passed")
    return 0


def main():
    print("test_test_scripts_restore_config.py -- LA-4 held by a test")
    print("the owner's config.json sha256 (never written by this file):")
    if not LIVE.exists():
        _skip.skip("needs a config.json, the scripts it checks swap that file")
    live_before = LIVE.read_bytes()
    print("  %s" % __import__("hashlib").sha256(live_before).hexdigest())

    # A. every swapper carries the four pieces of LA-4
    print("\nA. the four pieces, in the REAL files")
    for name in SWAPPERS:
        text = (SCRIPTS / (name + ".sh")).read_text()
        if name in ("verify_duty_live", "verify_launchers_live"):
            check("%s: refuses while the owner's file has more than one name" % name,
                  "has $LIVE_LINKS links" in text
                  and "-xdev -samefile" in text, True)
            check("%s: traps the signals a verifier meets" % name,
                  all(("exit %d'" % n) in text for n in (130, 143, 129)), True)
            continue
        check("%s: the restore lives in the trap" % name,
              'if ! cmp -s "$ROOT/config.json" "$TMP/config.orig.json"; then' in text
              and 'cp "$TMP/config.orig.json" "$ROOT/config.json"' in text, True)
        check("%s: the put-back is PROVEN inside the trap" % name,
              'echo "  *** THE OPERATOR\'S config.json COULD NOT BE RESTORED ***"' in text, True)
        check("%s: a failed proof keeps the copy and exits non-zero" % name,
              "exit 1" in text and "KEPT for a manual put-back" in text, True)
        check("%s: the signals a verifier meets are trapped (130/143/129)" % name,
              all(("exit %d'" % n) in text for n in (130, 143, 129)), True)
        check("%s: a linked scratch copy is refused" % name,
              '-ef "$TMP/config.orig.json"' in text
              and "has $LIVE_LINKS links" in text, True)

    # B. the trap puts it back under a real signal, three doors
    print("\nB. interrupted at three doors: put back, PROVEN, right exit code")
    work = pathlib.Path(tempfile.mkdtemp(prefix="agental_la4_test_"))
    body_sleep = ('echo "{\\"arm\\": \\"scratch\\"}" > "$ROOT/config.json"\n'
                  "sleep 15")
    try:
        try:
            head_of("verify_t9_live")
        except AssertionError as e:
            # A SCRIPT WITH NO LA-4 BLOCK CANNOT BE DRIVEN, and that is a
            # result, not a crash: report it as the named failure it is and
            # skip the driven sections rather than dying with a traceback the
            # reader has to decode.
            check("verify_t9_live carries an LA-4 head to drive", False, True)
            raise SystemExit(_finish(live_before))
        for label, sig in (("Ctrl+C", signal.SIGINT),
                           ("SIGTERM", signal.SIGTERM),
                           ("SIGHUP", signal.SIGHUP)):
            rc, out, restored = run_head("verify_t9_live", work, body_sleep,
                                         sig=sig)
            want = {signal.SIGINT: 130, signal.SIGTERM: 143,
                    signal.SIGHUP: 129}[sig]
            check("%s: exit code is the shell's own %d" % (label, want), rc, want)
            check("%s: the sandbox config is byte-identical again" % label,
                  restored, True)
            check("%s: the trap NAMED the put-back" % label,
                  "put back by this script" in out, True)
        rc, out, restored = run_head("verify_t9_live", work, body_sleep,
                                     sig=signal.SIGINT, sig_target="shell")
        check("Ctrl+C to the shell ALONE still exits 130, not 0", rc, 130)
        check("  and still restores", restored, True)

        # C. the link refusal is real
        print("\nC. the link refusal, driven")
        sandbox = work / "sandbox"
        sandbox.mkdir(exist_ok=True)
        shutil.copyfile(LIVE, sandbox / "config.json")
        linkdir = work / "linktree"
        linkdir.mkdir(exist_ok=True)
        link = linkdir / "config.json"
        if link.exists():
            link.unlink()
        os.link(sandbox / "config.json", link)   # a second name for the file
        variant = work / "inode.run.sh"
        head = point_at(head_of("verify_t9_live"), sandbox)
        variant.write_text(head + "\necho SHOULD-NOT-REACH-THE-BODY\n")
        p = subprocess.run(["bash", str(variant)], capture_output=True,
                           text=True, timeout=60)
        check("a second name for the file: exit code 2", p.returncode, 2)
        check("  and the refusal says why", "REFUSING TO RUN" in p.stdout, True)
        check("  and the body never ran", "SHOULD-NOT-REACH-THE-BODY" not in p.stdout, True)
        link.unlink()

        # D. the failed proof is not green
        print("\nD. a put-back that cannot land")
        sandbox = work / "sandbox2"
        sandbox.mkdir(exist_ok=True)
        shutil.copyfile(LIVE, sandbox / "config.json")
        head = point_at(head_of("verify_t9_live"), sandbox)
        head = head.replace('cp "$TMP/config.orig.json" "$ROOT/config.json"',
                            ": simulated-failed-put-back")
        variant = work / "fail.run.sh"
        variant.write_text(head + '\necho "{\\"arm\\": \\"scratch\\"}" > "$ROOT/config.json"\n')
        p = subprocess.run(["bash", str(variant)], capture_output=True,
                           text=True, timeout=60)
        check("the exit is non-zero (1)", p.returncode, 1)
        check("  the message is loud", "COULD NOT BE RESTORED" in p.stdout, True)
        check("  and the copy was KEPT for a manual put-back",
              "KEPT for a manual put-back" in p.stdout, True)
        # THE KEEP IS THE BEHAVIOUR UNDER TEST; THE CLEANUP IS THIS FILE'S OWN.
        # The failed-proof arm deliberately leaves its scratch dir (that is what
        # the kept copy is), so this file removes what it just created rather
        # than leaving a directory behind on every run.
        for d in pathlib.Path("/tmp").glob("agental_t9_live.*"):
            if d.is_dir() and (d / "config.orig.json").exists():
                shutil.rmtree(d, ignore_errors=True)
    finally:
        shutil.rmtree(work, ignore_errors=True)

    # E. this file's own residue
    return _finish(live_before)


if __name__ == "__main__":
    sys.exit(main())
