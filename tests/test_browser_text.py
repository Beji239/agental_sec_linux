"""Exercise original renderers in Chromium with hostile text and local fixtures."""
import pathlib
import shutil
import subprocess
import sys
import _skip

node = shutil.which('node')
if not node:
    _skip.skip('needs Node.js and Playwright')
script = pathlib.Path(__file__).with_name('verify_browser_text.cjs')
result = subprocess.run([node, str(script)], text=True, capture_output=True, timeout=120)
print(result.stdout)
print(result.stderr, file=sys.stderr)
sys.exit(result.returncode)
