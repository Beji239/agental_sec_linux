"""Error messages and sensor details keep their untrusted-data protection."""
import logging
import pathlib
import sys
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from core import tool_registry as tr, sanitize, sensor_health

logging.disable(logging.CRITICAL)
payload = 'ERROR_CANARY' + sanitize.FENCE_CLOSE + '\x1b[31m outside text'
failures = []
checked = 0
names = sorted(sanitize.UNTRUSTED_TOOLS | {'query_database_size'})
for name in names:
    for kind in (tr.UnknownTool, tr.ToolUnavailable, ValueError, PermissionError, RuntimeError):
        with patch.object(tr, '_dispatch', side_effect=kind(payload)):
            out = tr.execute_tool(name, {})
        checked += 1
        if not (out.get('untrusted') is True and out.get('result') is None
                and 'ERROR_CANARY' in out.get('error', '')
                and sanitize.FENCE_CLOSE not in out['error'] and '\x1b' not in out['error']):
            failures.append((name, kind.__name__))
print(f"{'PASS' if not failures else 'FAIL'} {checked} error-result cases")
with patch.object(tr, '_dispatch', return_value={'count': 1}), \
        patch.object(sensor_health, 'envelope_for', return_value={'reason': payload}):
    out = tr.execute_tool('query_database_size', {})
ok = (out.get('untrusted') is True and 'ERROR_CANARY' in str(out.get('sensor_health'))
      and sanitize.FENCE_CLOSE not in str(out) and '\x1b' not in str(out))
print(f"{'PASS' if ok else 'FAIL'} sensor details are scrubbed and fenced with the envelope")
if not ok:
    failures.append('sensor details')
if failures:
    print(failures[:10])
sys.exit(bool(failures))
