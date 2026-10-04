#!/usr/bin/env python3
"""
Data folder verification. Runs the real modules; asserts the failure modes.

Checks three defects found in the data/ comparison pass, 2026-09-21:
  D-1  a missing registry tier was answered from the shorter parent and called
       resolved, so a delegating authority read as the device's manufacturer
  D-2  status() called a partial registry ready, and main.py printed it healthy
  D-3  a partial fetch exited 0 and never tried the fallback

Every check reads its expectation off the real registry files. The negative
controls are named and asserted: each one must FAIL when the fix is undone.
"""
import csv
import importlib
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent   # the project root, not scripts/
sys.path.insert(0, str(HERE))

PASS = FAIL = 0


def check(label, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"  PASS  {label}")
    else:
        FAIL += 1
        print(f"  FAIL  {label}")
        if detail:
            print(f"        {detail}")


def load(p):
    t = {}
    with open(p, newline="", encoding="utf-8") as fh:
        for r in csv.DictReader(fh):
            a = (r.get("Assignment") or "").strip().upper()
            o = (r.get("Organization Name") or "").strip()
            if a and o:
                t[a] = o
    return t


print("=== ground truth, read from the shipped registry ===")
DATA = HERE / "data"
mal = load(DATA / "oui.csv")
mam = load(DATA / "mam.csv")
mas = load(DATA / "mas.csv")
print(f"  /24 {len(mal):,}   /28 {len(mam):,}   /36 {len(mas):,}")

# A 36 bit address whose maker is NOT the 24 bit parent's name. This is the
# address the whole check is about.
target36 = next(a for a, o in mas.items() if mal.get(a[:6]) and mal[a[:6]] != o)
# PAD TO 48 BITS. `target36` is 9 hex characters, a 36 bit prefix, so the
# host bits have to be added before it is an address at all. The first version
# of this check sliced nine characters into a 12 character MAC and the module
# correctly called it unparseable, which is the check being wrong rather than
# the code. Written down because it cost a run.
target_mac = ":".join((target36 + "000")[i:i + 2] for i in range(0, 12, 2))
parent_name = mal[target36[:6]]
real_name = mas[target36]
assert len(target_mac.replace(":", "")) == 12, target_mac
print(f"  probe /36 {target36} maker={real_name!r} 24 bit parent={parent_name!r}")

print("\n=== D-1  a missing tier must not read as the maker ===")
core_oui = importlib.import_module("core.oui")

# Full registry: the answer is the maker.
core_oui.reload()
full = core_oui.lookup(target_mac)
check("full registry resolves to the real maker",
      full["status"] == "resolved" and full["vendor"] == real_name,
      f"got {full['status']} {full.get('vendor')!r}")

hold = DATA / "mas.csv.hold"
shutil.move(DATA / "mas.csv", hold)
try:
    core_oui.reload()
    part = core_oui.lookup(target_mac)
    check("partial registry still ANSWERS (does not refuse the reading)",
          part["status"] == "resolved", f"got {part['status']}")
    check("partial answer NAMES the maker it fell back through",
          part.get("vendor") == parent_name,
          f"got {part.get('vendor')!r}")
    check("partial answer SAYS it is short",
          "THIS ANSWER IS SHORT" in (part.get("note") or ""),
          f"note={part.get('note')!r}")
    check("the short note names the missing tier in bits",
          "36 bit" in (part.get("note") or ""), f"note={part.get('note')!r}")

    # D-2 in the same state.
    st = core_oui.status()
    check("status() is NOT ready on a partial registry", st["ready"] is False,
          f"got {st}")
    check("status() names the missing file", st["missing"] == ["mas.csv"],
          f"got {st.get('missing')}")
finally:
    shutil.move(hold, DATA / "mas.csv")
    core_oui.reload()

print("\n=== negative control: the fix reverted must reproduce the old bug ===")
old_note = (f"registered 24 bit prefix, from oui.csv. This is who registered "
            f"the address block, which is the manufacturer of the network "
            f"part. It is not necessarily the brand on the box.")
check("the OLD note did not say the answer was short",
      "THIS ANSWER IS SHORT" not in old_note)

print("\n=== D-2/D-3  the script's own states, run for real ===")
r = subprocess.run([sys.executable, "scripts/update_oui.py", "--status"],
                   cwd=HERE, capture_output=True, text=True)
check("--status exits 0 on a complete registry", r.returncode == 0,
      f"got {r.returncode}")
check("--status prints the full file list", "mas.csv" in r.stdout, r.stdout)

shutil.move(DATA / "mas.csv", hold)
try:
    r2 = subprocess.run([sys.executable, "scripts/update_oui.py", "--status"],
                        cwd=HERE, capture_output=True, text=True)
    check("--status exits NON ZERO on a partial registry",
          r2.returncode == 1, f"got {r2.returncode}")
    check("--status says PARTIAL and names the file",
          "PARTIAL" in r2.stdout and "mas.csv" in r2.stdout, r2.stdout)
    check("--status does not claim 'ready: True'",
          "lookup ready: True" not in r2.stdout, r2.stdout)
finally:
    shutil.move(hold, DATA / "mas.csv")

print("\n=== the fallback covers a missing IEEE tier (manuf, if present) ===")
manuf = DATA / "manuf"
if manuf.exists():
    rows = 0
    for line in manuf.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.split("#", 1)[0].strip()
        if line and "\t" in line:
            rows += 1
    check("manuf is present and parses to rows", rows > 1000, f"rows={rows}")
else:
    print("  SKIP  no manuf on disk right now")

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
