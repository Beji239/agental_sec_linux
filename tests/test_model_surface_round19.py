"""
tests/test_model_surface_round19.py, register section 19: the model surface.

MS-1 an empty unattended allowlist, MS-2 card ids across turns, MS-3 the log
search bound.

Run it directly: python3 tests/test_model_surface_round19.py
"""
import asyncio
import json
import pathlib
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core import agent_loop as al                       # noqa: E402
from tools import event_monitor_linux as em             # noqa: E402

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}"
          + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


SRC = (ROOT / "core" / "agent_loop.py").read_text()

print("\n[MS-1] an empty allowlist allows nothing")
check("the check is 'is not None', not truthiness",
      "if allowlist is not None and name not in set(allowlist):" in SRC, True)
check("the truthy form is gone", "if allowlist and name not in set(allowlist):" in SRC, False)

print("\n[MS-2] a card id is unique across turns")
body = SRC.split("seen_ids.add(call_id)")[0].rsplit("for idx, tc in", 1)[1]
check("a missing id is random, not call_<n>", 'f"call_{secrets.token_hex(6)}"' in body, True)
check("an id held by another turn's open card is renamed", "call_id in _open_cards" in body, True)

print("\n[MS-3] grep stops at the requested number of lines")
d = pathlib.Path(tempfile.mkdtemp())
log = d / "big.log"
log.write_text("".join(f"Sep 28 10:00:{i % 60:02d} host app[1]: line {i}\n"
                       for i in range(20000)))
real = em._get_log_file_paths
em._get_log_file_paths = lambda: {"big": log}
try:
    rows = em.search_logs("line", lines=7)
finally:
    em._get_log_file_paths = real
check("seven rows back", len(rows), 7)
src = (ROOT / "tools" / "event_monitor_linux.py").read_text()
check("grep is given -m", '"-m", str(lines)' in src, True)

print("\n" + "=" * 62)
if fails:
    print(f"{len(fails)} FAILED: " + ", ".join(fails))
    sys.exit(1)
print("ALL CHECKS PASSED")
