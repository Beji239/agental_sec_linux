"""Live process controls keep current execution and next-start choices separate."""
import json
import os
import pathlib
import sqlite3
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import _isolate_db
DB = _isolate_db.isolate()
from core import migrations, settings, sensor_watch
from core.feature_controls import FeatureControls
from adapters import LinuxProcessMonitor
from api.server import create_app
from api import dashboard_session as ds

migrations.run_migrations(DB)


class FeatureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = pathlib.Path(self.temp.name) / 'config.json'
        self.config = {'sensors': {'process_monitor': {'enabled': False}},
                       'flask': {'host': '127.0.0.1'}, 'example': {'keep': True}}
        self.path.write_text(json.dumps(self.config))
        self.path.chmod(0o600)
        self.path_patch = patch.object(settings, 'CONFIG_PATH', self.path)
        self.path_patch.start()
        self.addCleanup(self.path_patch.stop)
        self.monitor = LinuxProcessMonitor('fixture', self.config)
        self.called = threading.Event()
        self.monitor.poll = self.called.set
        self.addCleanup(self.monitor.stop)
        self.controls = FeatureControls(self.config, {'process_monitor': self.monitor})
        self.controls.prepare_startup()
        self.app = create_app(self.config, {'process_monitor': self.monitor}, 'fixture',
                              api_key='read-fixture', dashboard_key='f' * 64)
        self.app.config['AGENTAL_FEATURE_CONTROLS'] = self.controls
        self.client = self.app.test_client()
        self.private = {ds.HEADER: ds.new_session('f' * 64)}
        self.read = {'X-API-Key': 'read-fixture'}

    def post(self, action, body, headers=None, name='process_monitor'):
        return self.client.post('/api/features/' + name + '/' + action,
                                json=body, headers=headers or self.private)

    def test_read_only_status_does_not_start_or_write(self):
        before = self.path.read_bytes()
        reply = self.client.get('/api/features', headers=self.read)
        self.assertEqual(reply.status_code, 200)
        self.assertEqual(reply.json['features'][0]['state'], 'off')
        self.assertIsNone(self.monitor._thread)
        self.assertEqual(self.path.read_bytes(), before)

    def test_unauthenticated_reads_and_changes_are_refused(self):
        self.assertEqual(self.client.get('/api/features').status_code, 401)
        self.assertEqual(self.client.post('/api/features/process_monitor/run',
                                         json={'running': True}).status_code, 401)

    def test_integration_cannot_change_execution_or_preferences(self):
        before = self.path.read_bytes()
        self.assertEqual(self.post('run', {'running': True}, self.read).status_code, 403)
        self.assertEqual(self.post('startup', {'enabled': True}, self.read).status_code, 403)
        self.assertIsNone(self.monitor._thread)
        self.assertEqual(self.path.read_bytes(), before)

    def test_run_now_does_not_change_startup(self):
        before = self.path.read_bytes()
        self.assertEqual(self.post('run', {'running': True}).status_code, 200)
        self.assertTrue(self.called.wait(1))
        row = self.controls.snapshot()['features'][0]
        self.assertTrue(row['running'])
        self.assertFalse(row['automatic_start'])
        self.assertEqual(self.path.read_bytes(), before)

    def test_startup_save_does_not_start_collection(self):
        self.assertEqual(self.post('startup', {'enabled': True}).status_code, 200)
        self.assertIsNone(self.monitor._thread)
        saved = json.loads(self.path.read_text())
        self.assertTrue(saved['feature_startup']['process_monitor'])
        self.assertTrue(saved['example']['keep'])
        self.assertEqual(os.stat(self.path).st_mode & 0o777, 0o600)
        self.assertFalse(saved['sensors']['process_monitor']['enabled'])

    def test_next_start_uses_saved_preference_without_changing_legacy_flag(self):
        self.post('startup', {'enabled': True})
        saved = json.loads(self.path.read_text())
        other = LinuxProcessMonitor('next', saved)
        self.addCleanup(other.stop)
        controls = FeatureControls(saved, {'process_monitor': other})
        controls.prepare_startup()
        other.poll = lambda: None
        self.assertTrue(other.start())
        self.assertFalse(saved['sensors']['process_monitor']['enabled'])

    def test_stop_keeps_history_and_startup_preference(self):
        self.post('startup', {'enabled': True})
        self.post('run', {'running': True})
        self.assertTrue(self.called.wait(1))
        self.monitor._last_result = {'process_count': 17}
        self.assertEqual(self.post('run', {'running': False}).status_code, 200)
        self.assertTrue(self.monitor.stop())
        self.assertEqual(self.monitor.status()['process_count'], 17)
        self.assertTrue(self.controls.snapshot()['features'][0]['automatic_start'])
        self.assertFalse(self.monitor._collection_enabled())

    def test_inflight_stop_is_visible_and_prevents_duplicate_restart(self):
        release = threading.Event()
        self.addCleanup(release.set)
        def poll():
            self.called.set()
            release.wait(2)
        self.monitor.poll = poll
        self.post('run', {'running': True})
        self.assertTrue(self.called.wait(1))
        self.post('run', {'running': False})
        self.assertEqual(self.controls.snapshot()['features'][0]['state'], 'stopping')
        self.assertEqual(self.post('run', {'running': True}).status_code, 409)
        release.set()
        self.assertTrue(self.monitor.stop())

    def test_bad_input_cannot_become_a_true_flag(self):
        for action, field in [('run', 'running'), ('startup', 'enabled')]:
            for value in ['true', 1, None, {}, []]:
                with self.subTest(action=action, value=value):
                    self.assertEqual(self.post(action, {field: value}).status_code, 400)
        self.assertEqual(self.post('run', []).status_code, 400)
        self.assertEqual(self.post('run', {'running': True}, name='unknown').status_code, 404)

    def test_save_failure_keeps_both_choices_unchanged(self):
        before = self.path.read_bytes()
        with patch.object(settings, 'persist_config_value', return_value='fixture failure'):
            self.assertEqual(self.post('startup', {'enabled': True}).status_code, 500)
        self.assertFalse(self.controls.snapshot()['features'][0]['automatic_start'])
        self.assertIsNone(self.monitor._thread)
        self.assertEqual(self.path.read_bytes(), before)

    def test_bad_config_file_is_not_overwritten(self):
        self.path.write_text('[]')
        self.assertEqual(self.post('startup', {'enabled': True}).status_code, 500)
        self.assertEqual(self.path.read_text(), '[]')

    def test_invalid_startup_configuration_does_not_enable_collection(self):
        for saved in [False, [], 'invalid', {'process_monitor': None}]:
            config = {'sensors': {'process_monitor': {'enabled': True}},
                      'feature_startup': saved}
            self.path.write_text(json.dumps(config))
            controls = FeatureControls(config, {'process_monitor': self.monitor})
            controls.prepare_startup()
            row = controls.snapshot()['features'][0]
            self.assertFalse(row['automatic_start'])
            self.assertTrue(row['startup_error'])
            self.assertFalse(self.monitor.start())

    def test_external_startup_edit_is_read_without_changing_current_collection(self):
        config = json.loads(self.path.read_text())
        config['feature_startup'] = {'process_monitor': True}
        self.path.write_text(json.dumps(config))
        row = self.client.get('/api/features', headers=self.read).json['features'][0]
        self.assertTrue(row['automatic_start'])
        self.assertEqual(row['state'], 'off')
        self.assertIsNone(self.monitor._thread)

    def test_history_failure_does_not_prevent_stopping(self):
        self.post('run', {'running': True})
        with patch.object(sensor_watch, 'record_control_choice', return_value=False):
            reply = self.post('run', {'running': False})
        self.assertEqual(reply.status_code, 200)
        self.assertIn('warning', reply.json)
        self.assertTrue(self.monitor.stop())

    def test_start_failure_is_reported_without_saving(self):
        with patch.object(self.monitor, 'start', side_effect=RuntimeError('fixture')):
            self.assertEqual(self.post('run', {'running': True}).status_code, 503)
        self.assertFalse(self.monitor._collection_enabled())
        self.assertFalse(self.controls.snapshot()['features'][0]['automatic_start'])

    def test_shutdown_refuses_later_changes(self):
        self.controls.shutdown()
        self.assertEqual(self.post('run', {'running': True}).status_code, 503)
        self.assertEqual(self.post('startup', {'enabled': True}).status_code, 503)

    def test_missing_collector_is_unavailable(self):
        self.app.config['AGENTAL_FEATURE_CONTROLS'] = FeatureControls(self.config, {})
        reply = self.client.get('/api/features', headers=self.read)
        self.assertEqual(reply.json['features'][0]['state'], 'unavailable')
        self.assertEqual(self.post('run', {'running': True}).status_code, 503)

    def test_watchdog_and_control_change_cannot_write_stale_gap_state(self):
        watch = sensor_watch.SensorWatch({'process_monitor': self.monitor}, save=lambda **row: None)
        entered, release, finished = threading.Event(), threading.Event(), threading.Event()
        self.addCleanup(release.set)
        real_assess = sensor_watch.assess
        def slow_assess(*args, **kwargs):
            row = real_assess(*args, **kwargs)
            entered.set()
            release.wait(2)
            return row
        def start_collection():
            self.controls.change_running('process_monitor', True)
            finished.set()
        with patch.object(sensor_watch, 'assess', side_effect=slow_assess):
            checking = threading.Thread(target=watch.check_once)
            checking.start()
            self.assertTrue(entered.wait(1))
            changing = threading.Thread(target=start_collection)
            changing.start()
            self.assertFalse(finished.wait(0.05))
            release.set()
            checking.join(2)
            changing.join(2)
        self.assertTrue(finished.is_set())
        with sqlite3.connect(DB) as conn:
            count = conn.execute("SELECT COUNT(*) FROM sensor_gaps WHERE sensor=? "
                                 "AND ended_at IS NULL", ('process_monitor',)).fetchone()[0]
        self.assertEqual(count, 0)

    def test_short_pause_is_recorded_without_waiting_for_watchdog(self):
        self.post('run', {'running': False})
        self.post('run', {'running': True})
        with sqlite3.connect(DB) as conn:
            row = conn.execute("SELECT ended_at FROM sensor_gaps WHERE sensor=? "
                               "AND reason=? ORDER BY id DESC LIMIT 1",
                               ('process_monitor', 'Paused from monitoring controls.')).fetchone()
        self.assertIsNotNone(row)
        self.assertIsNotNone(row[0])

    def test_pausing_a_failed_collector_keeps_its_gap_open(self):
        watch = sensor_watch.SensorWatch({'process_monitor': self.monitor}, save=lambda **row: None)
        self.post('run', {'running': True})
        self.assertTrue(self.called.wait(1))
        now = time.time()
        watch.check_once(now)
        self.monitor._consecutive_failures = 5
        self.monitor._last_error = 'fixture failure'
        self.assertEqual(watch.check_once(now + 1)['sensors'][0]['state'], 'quiet')
        self.post('run', {'running': False})
        self.monitor.stop()
        watch.check_once(now + 2)
        with sqlite3.connect(DB) as conn:
            count = conn.execute("SELECT COUNT(*) FROM sensor_gaps WHERE sensor=? "
                                 "AND ended_at IS NULL", ('process_monitor',)).fetchone()[0]
        self.assertEqual(count, 1)

    def test_intentional_pause_records_gap_without_failure_alert(self):
        raised = []
        watch = sensor_watch.SensorWatch({'process_monitor': self.monitor},
                                        save=lambda **row: raised.append(row))
        self.post('run', {'running': True})
        self.assertTrue(self.called.wait(1))
        now = time.time()
        watch.check_once(now)
        self.post('run', {'running': False})
        self.monitor.stop()
        row = watch.check_once(now + 1)['sensors'][0]
        self.assertEqual(row['state'], 'off')
        self.assertTrue(row['coverage_gap'])
        with sqlite3.connect(DB) as conn:
            open_before = conn.execute("SELECT COUNT(*) FROM sensor_gaps WHERE sensor=? "
                                       "AND ended_at IS NULL", ('process_monitor',)).fetchone()[0]
        self.assertEqual(open_before, 1)
        self.post('run', {'running': True})
        watch.check_once(now + 2)
        with sqlite3.connect(DB) as conn:
            open_after = conn.execute("SELECT COUNT(*) FROM sensor_gaps WHERE sensor=? "
                                      "AND ended_at IS NULL", ('process_monitor',)).fetchone()[0]
        self.assertEqual(open_after, 0)
        self.assertFalse(any(row['detection_id'] == 'SYS-1001' for row in raised))


if __name__ == '__main__':
    unittest.main()
