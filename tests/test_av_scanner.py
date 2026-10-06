# tests/test_av_scanner.py
# ClamAV scanning, with a stand-in clamscan that prints ClamAV's own output
# for files holding the EICAR test string. A hit is raised once as AV-1001,
# a file is scanned once until it changes, not installed is a state rather
# than a clean answer, and a scanner error is never read as clean.

import os
import pathlib
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import _isolate_db                                    # noqa: E402
_isolate_db.isolate()

from core import memory_engine as me                  # noqa: E402
from core import migrations                           # noqa: E402
migrations.run_migrations(me.DB_PATH)

from tools import av_scanner as av                    # noqa: E402

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}" + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


tmp = pathlib.Path(tempfile.mkdtemp())
fakebin = tmp / "bin"
fakebin.mkdir()
calls = tmp / "calls"
(fakebin / "clamscan").write_text(f"""#!/bin/sh
echo "$@" >> {calls}
found=0
for f in "$@"; do
  case "$f" in --*) continue ;; esac
  [ -f "$f" ] || continue
  if grep -q EICAR-STANDARD-ANTIVIRUS-TEST-FILE "$f"; then
    echo "$f: Eicar-Test-Signature FOUND"; found=1
  fi
done
exit $found
""")
(fakebin / "clamscan").chmod(0o755)
db = tmp / "clamav"
db.mkdir()
(db / "daily.cvd").write_text("x")
av.DATABASE_DIR = str(db)
av.CLAMD_SOCKETS = (str(tmp / "no-socket"),)
drop = tmp / "drop"
drop.mkdir()
av.WATCH_DIRS = (str(drop),)
av.HOME_WATCH = ()
av.running_programs = lambda: {}
REAL_PATH = os.environ["PATH"]
EICAR = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

print("[1] not installed is a state, not a clean answer")
os.environ["PATH"] = str(tmp / "empty")
check("the engine says not installed", av.engine()["installed"], False)
r = av.scan_paths([str(drop)])
check("a scan refuses with the install command",
      (r["ok"], "apt install clamav" in r["error"]), (False, True))
st = av.Scanner().status()
check("the status says not installed, with the command, and is not blind",
      (st["installed"], st["blind"], "sudo apt install clamav" in st["headline"]), (False, False, True))

print("[2] a signature match is found, a clean file is not")
os.environ["PATH"] = f"{fakebin}:{REAL_PATH}"
(drop / "clean.txt").write_text("hello")
bad = drop / "invoice.pdf.sh"
bad.write_text(EICAR)
r = av.scan_paths([str(drop / "clean.txt"), str(bad)])
check("the infected file and its signature",
      (r["ok"], r["infected"]), (True, [{"path": str(bad), "signature": "Eicar-Test-Signature"}]))
check("the engine is clamscan without the daemon", av.engine()["tool"], "clamscan")

print("[3] a scanner error is never clean")
(fakebin / "clamscan").write_text("#!/bin/sh\necho 'LibClamAV Error: cannot load database' >&2\nexit 2\n")
r = av.scan_paths([str(drop / "clean.txt")])
check("ok is False with the reason", (r["ok"], "cannot load" in r["error"]), (False, True))
(fakebin / "clamscan").write_text((fakebin / "clamscan").read_text())

print("[4] the pass, the adapter and the finding")
(fakebin / "clamscan").write_text(f"""#!/bin/sh
echo "$@" >> {calls}
found=0
for f in "$@"; do
  case "$f" in --*) continue ;; esac
  [ -f "$f" ] || continue
  if grep -q EICAR-STANDARD-ANTIVIRUS-TEST-FILE "$f"; then
    echo "$f: Eicar-Test-Signature FOUND"; found=1
  fi
done
exit $found
""")
import adapters                                       # noqa: E402
a = adapters.LinuxAVScanner("t", {})
a.poll()
with me._get_conn() as conn:
    rows = conn.execute("SELECT detection_id, severity, entity_value FROM findings "
                        "WHERE source = 'av_scanner'").fetchall()
check("AV-1001 is raised at high for the file", [tuple(r) for r in rows],
      [("AV-1001", "high", str(bad))])
calls.write_text("")
a.poll()
check("a second pass scans nothing that did not change", calls.read_text(), "")
with me._get_conn() as conn:
    n = conn.execute("SELECT COUNT(*) FROM findings WHERE source = 'av_scanner'").fetchone()[0]
check("and raises nothing again", n, 1)
bad.write_text(EICAR + "\nchanged")
a.poll()
check("a changed file is scanned again", str(bad) in calls.read_text(), True)
check("the status counts it", a.status()["infected"] >= 1, True)

print("[5] the agent's tool")
from core import tool_registry as tr                  # noqa: E402
tr.init_registry("t", {"av_scanner": a})
out = tr.execute_tool("scan_with_antivirus", {"paths": [str(bad), str(drop / "clean.txt")]})
body = (out or {}).get("result") or {}
check("and marks the answer untrusted", (out or {}).get("untrusted"), True)
check("the tool returns the hit", [h["path"] for h in (body.get("infected") or [])], [str(bad)])

print("[6] a ClamAV hit is checked against MalwareBazaar")
from core import enrichment                           # noqa: E402
from tools import process_monitor_linux as pm         # noqa: E402
asked = []


def fake_bazaar(sha):
    asked.append(sha)
    return ({"known_malware": True, "malware_family": "EICAR",
             "first_seen": "2020-01-01"}, "https://bazaar.example/", None)


enrichment.src_malwarebazaar = fake_bazaar
second = drop / "second.bin"
second.write_text(EICAR + "\nanother")
a.poll()
with me._get_conn() as conn:
    raw = conn.execute("SELECT raw_data, description FROM findings WHERE source = 'av_scanner' "
                       "AND entity_value = ?", (str(second),)).fetchone()
import json                                           # noqa: E402
data = json.loads(raw[0]) if raw else {}
check("the hash was looked up", asked[-1:] == [pm.hash_file(str(second))], True)
check("both sources agree", (data.get("corroboration"), (data.get("malwarebazaar") or {}).get("family")),
      ("corroborated", "EICAR"))
check("and the finding says so", "MalwareBazaar also lists this file as EICAR" in (raw[1] if raw else ""), True)
calls.write_text("")
a.poll()
check("storing that answer does not start a scan loop", calls.read_text(), "")

from tools import av_scanner as _av                    # noqa: E402
enrichment.src_malwarebazaar = lambda sha: (None, "u", "no key set. Put AGENTAL_ABUSECH_KEY in .env")
check("no key is 'could not be asked', never 'no record'",
      _av.bazaar(str(second)) | {"sha256": None}, {"asked": False, "sha256": None,
                                                    "why": "no key set. Put AGENTAL_ABUSECH_KEY in .env"})
enrichment.src_malwarebazaar = lambda sha: (None, "u", None)
check("a real miss is 'no record'", (_av.bazaar(str(drop / "clean.txt"))["asked"],
                                     _av.bazaar(str(drop / "clean.txt"))["known"]), (True, False))
r = a.scan(["/", str(drop), str(bad)])
check("the agent cannot scan a folder", (r["not_scanned"]["paths"], [h["path"] for h in r["infected"]]),
      (["/", str(drop)], [str(bad)]))

print("[7] a MalwareBazaar hit has ClamAV scan the file and its folder now")
other = tmp / "elsewhere"
other.mkdir()
prog = other / "helper"
prog.write_text("benign program")
sibling = other / "payload.so"
sibling.write_text(EICAR + "\nsibling")
sha = pm.hash_file(str(prog))
check("the shared cache maps the hash back to the file", pm.paths_for_hash(sha), [str(prog)])
av.wake.clear()
enrichment.store({"indicator": sha, "kind": "hash", "status": "resolved", "confidence": "high",
                  "fields": {"known_malware": True, "malware_family": "Test"},
                  "sources": [], "tried": [], "gap": None})
check("the scanner is woken", av.wake.is_set(), True)
calls.write_text("")
a.poll()
check("the file and the one beside it were scanned",
      (str(prog) in calls.read_text(), str(sibling) in calls.read_text()), (True, True))
with me._get_conn() as conn:
    n = conn.execute("SELECT COUNT(*) FROM findings WHERE source = 'av_scanner' AND entity_value = ?",
                     (str(sibling),)).fetchone()[0]
check("and the infected neighbour raised AV-1001", n, 1)

print()
print("ALL CHECKS PASSED" if not fails else f"FAILED: {fails}")
sys.exit(1 if fails else 0)
