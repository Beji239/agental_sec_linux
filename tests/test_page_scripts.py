"""
tests/test_page_scripts.py, the console page checks in scripts/verify_*.js.

Each one runs the page's own functions under node against made-up payloads or
the database rows, so it needs no running app. Without node this is a skip.
"""
import os
import pathlib
import shutil
import subprocess
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import _skip  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent
PAGE_TESTS = sorted((ROOT / "scripts").glob("verify_*.js"))

node = shutil.which("node")
if not node:
    _skip.skip("needs node")
if not PAGE_TESTS:
    print("no scripts/verify_*.js found")
    sys.exit(1)

failed = []
for f in PAGE_TESTS:
    try:
        p = subprocess.run([node, str(f)], cwd=str(ROOT), capture_output=True,
                           text=True, timeout=300, env=dict(os.environ))
        code, out = p.returncode, (p.stdout or "") + (p.stderr or "")
    except subprocess.TimeoutExpired:
        code, out = "timeout", ""
    ok = code == 0
    print(f"  [{'PASS' if ok else 'FAIL'}] {f.name}")
    if not ok:
        failed.append(f.name)
        for line in out.rstrip().splitlines()[-30:]:
            print(f"        {line}")

print(f"\n{len(PAGE_TESTS) - len(failed)} passed, {len(failed)} failed")
sys.exit(1 if failed else 0)
