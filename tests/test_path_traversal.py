"""
tests/test_path_traversal.py, a path from outside cannot reach past its fence.

The cases tests/test_restore_containment.py and test_remediation_fixes.py do
not already cover: a NUL byte, a symlink that leads out of the allowed area,
and files that never end (a FIFO, /dev/zero) or are not files at all. Every
call must answer with a refusal, quickly, and never raise or hang. Quarantine,
restore, the pcap reader and the virus scan, which is what the model and the
dashboard can hand a path to.
"""
import os
import pathlib
import sys
import tempfile
import threading

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import _isolate_db  # noqa: E402

sys.path.insert(0, str(ROOT))
_isolate_db.isolate()

import logging  # noqa: E402
logging.disable(logging.CRITICAL)   # the refusals log the hostile paths whole

from tools import remediation_linux as rem  # noqa: E402

fails = []


def check(label, ok, detail=""):
    print(f"  {'PASS' if ok else 'FAIL'}  {label}")
    if not ok:
        fails.append(label)
        if detail:
            print(f"        {str(detail)[:400]}")


def call(fn, *args, limit=5.0):
    """(result, error, finished) of fn(*args) within limit seconds."""
    box = {}

    def run():
        try:
            box["out"] = fn(*args)
        except Exception as e:                              # noqa: BLE001
            box["err"] = f"{type(e).__name__}: {e}"

    t = threading.Thread(target=run, daemon=True)
    t.start()
    t.join(limit)
    return box.get("out"), box.get("err"), not t.is_alive()


def refused(label, fn, *args):
    out, err, done = call(fn, *args)
    ok = done and err is None and isinstance(out, dict) and not out.get("success")
    check(label, ok, err or ("still running after 5 s" if not done else out))


tmp = pathlib.Path(tempfile.mkdtemp(prefix="agentalsec_paths_"))
rem.STAGING_ROOT = tmp / "quarantine"
rem.STAGING_ROOT.mkdir()
fifo = tmp / "pipe"
os.mkfifo(fifo)
to_etc = tmp / "innocent.txt"
to_etc.symlink_to("/etc/hostname")

print("[1] quarantine")
refused("a NUL byte is refused, not raised", rem.quarantine_file,
        str(tmp / "a\x00/etc/passwd"))
refused("a symlink into /etc is followed and refused", rem.quarantine_file,
        str(to_etc))
refused("a FIFO is refused without opening it", rem.quarantine_file, str(fifo))
refused("a device is refused", rem.quarantine_file, "/dev/zero")
refused("a 5000 character path is refused", rem.quarantine_file,
        "/tmp/" + "a" * 5000)

print("\n[2] restore")
refused("a NUL byte is refused, not raised", rem.restore_file,
        str(rem.STAGING_ROOT / "x\x00y"))
escape = rem.STAGING_ROOT / "2026-10-15-escape"
escape.symlink_to("/etc")
refused("a vault folder that is a symlink out is refused", rem.restore_file,
        str(escape))
refused("dot-dots out of the vault are refused", rem.restore_file,
        str(rem.STAGING_ROOT / ".." / ".." / "etc"))
check("and nothing was written to /etc", not pathlib.Path(
    "/etc/2026-10-15-escape").exists())

print("\n[3] the pcap reader")
from tools.pcap_analyzer import PcapAnalyzer  # noqa: E402
pa = PcapAnalyzer("test-paths")


def analyze(path):
    out = pa.analyze(path)
    # The reader answers with an error key rather than a success flag.
    return {"success": "error" not in out, **out}


for label, path in (("a NUL byte", str(tmp / "c\x00.pcap")),
                    ("a FIFO", str(fifo)),
                    ("/dev/zero", "/dev/zero"),
                    ("a directory", str(tmp)),
                    ("a file it may not read", "/etc/shadow"),
                    ("a symlink to a text file", str(to_etc))):
    refused(f"{label} is refused, quickly", analyze, path)

print("\n[4] the virus scan")
from tools import av_scanner  # noqa: E402
out, err, done = call(av_scanner.scan_paths, [str(tmp / "d\x00e")],
                      limit=10.0)
check("a NUL byte comes back as an answer, not an exception",
      done and err is None and isinstance(out, dict), err or out)

import shutil  # noqa: E402
shutil.rmtree(tmp, ignore_errors=True)
print(f"\n{'ALL PASSED' if not fails else str(len(fails)) + ' FAILED'}")
sys.exit(1 if fails else 0)
