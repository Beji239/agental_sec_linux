"""Approvals stay bound to the process instance shown to the person."""
import json
import pathlib
import sqlite3
import subprocess
import sys
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import _isolate_db
db = _isolate_db.isolate()
from core import migrations, actions, agent_loop, tool_registry
from tools import remediation_linux as rl, action_helper as ah
import adapters
import psutil

migrations.run_migrations(db)
fails = []


def check(label, ok):
    print(f"{'PASS' if ok else 'FAIL'} {label}")
    if not ok:
        fails.append(label)


victim = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(120)'])
try:
    started = psutil.Process(victim.pid).create_time()
    filed = actions.write_request('kill_process',
                                  {'pid': victim.pid, 'expected_started': 1},
                                  'Check process identity')
    check('queue records the real start time',
          filed['params'].get('expected_started') == started)
    with sqlite3.connect(db) as conn:
        stored = json.loads(conn.execute(
            'SELECT params_json FROM action_request WHERE id = ?',
            (filed['request_id'],)).fetchone()[0])
    check('the start time survives database storage',
          stored.get('expected_started') == started)
    params = {'pid': victim.pid, 'expected_name': 'caller chosen',
              'expected_started': 1}
    agent_loop._build_permission_card('kill_process', params, 'identity-test')
    check('chat replaces caller supplied identity',
          params.get('expected_started') == started
          and params.get('expected_name') == psutil.Process(victim.pid).name())

    remediation = adapters.LinuxRemediation('identity-test')
    no_signal = {'success': False, 'error': 'recording backend'}
    with patch.object(rl, 'kill_process', return_value=no_signal) as signal:
        out = remediation.kill_process(victim.pid, reason='Check stale approval',
                                       expected_name=psutil.Process(victim.pid).name(),
                                       expected_started=started - 100)
        check('same name with a different start time is refused',
              out.get('refused') and not signal.called)
    with patch.object(rl, 'kill_process', return_value=no_signal) as signal:
        out = remediation.kill_process(victim.pid, reason='Check old approval')
        check('old approvals without a start time are refused',
              out.get('refused') and not signal.called)
    with patch.object(rl, '_kill_pinned', return_value=no_signal) as signal:
        out = rl.kill_process(victim.pid, expected_started=started - 100)
        check('the signal layer checks the original start time',
              out.get('refused') and not signal.called)
    with patch.object(rl, 'kill_process', return_value=no_signal) as signal:
        remediation.kill_process(victim.pid, reason='Check valid approval',
                                 expected_name=psutil.Process(victim.pid).name(),
                                 expected_started=started)
        check('a valid identity reaches the signal layer unchanged',
              signal.call_args.kwargs.get('expected_started') == started)
    real_process = psutil.Process
    kernel_fields = ah._stat_fields(victim.pid)
    changed = []

    def read_fields(pid):
        changed.append(True)
        return kernel_fields

    def current_process(pid):
        if changed:
            raise psutil.NoSuchProcess(pid)
        return real_process(pid)

    with patch.object(rl, 'kill_process', return_value={
            'success': False, 'needs_root': True}), \
            patch.object(adapters, '_unelevated', return_value=True), \
            patch.object(ah, '_stat_fields', side_effect=read_fields), \
            patch.object(psutil, 'Process', side_effect=current_process), \
            patch.object(adapters, '_via_helper') as helper:
        out = remediation.kill_process(victim.pid, reason='Check helper race',
                                       expected_name=real_process(victim.pid).name(),
                                       expected_started=started)
        check('a process lost during the helper handoff is refused',
              out.get('refused') and not helper.called)
    missing = {'pid': 2 ** 31 - 1, 'expected_name': 'old name',
               'expected_started': started}
    agent_loop._build_permission_card('kill_process', missing, 'missing-test')
    check('an unreadable target does not retain caller supplied identity',
          'expected_name' not in missing and 'expected_started' not in missing)
    check('the test target was never signalled', victim.poll() is None)
finally:
    victim.terminate()
    victim.wait(timeout=5)

sys.exit(bool(fails))
