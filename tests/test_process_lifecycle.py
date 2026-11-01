"""Process collection can be off, stopped and restarted without duplicate workers."""
import pathlib
import sys
import threading
import time
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from adapters import LinuxProcessMonitor


class ProcessLifecycle(unittest.TestCase):
    def make(self, enabled=True):
        monitor = LinuxProcessMonitor('fixture', {'sensors': {
            'process_monitor': {'enabled': enabled, 'poll_interval': 3600}}})
        self.addCleanup(monitor.stop)
        return monitor

    def test_off_prevents_start_and_direct_collection(self):
        monitor = self.make(False)
        with patch.dict(sys.modules, {'tools.process_monitor_linux': None}):
            self.assertFalse(monitor.start())
            monitor.poll()
        self.assertIsNone(monitor._thread)
        self.assertEqual(monitor.status()['state'], 'off')
        self.assertFalse(monitor.status()['running'])
        self.assertIn('off in configuration', monitor.status()['reason'])

    def test_invalid_flags_do_not_start_collection(self):
        for value in ['false', 'true', 1, None, []]:
            with self.subTest(value=value):
                monitor = self.make(value)
                self.assertFalse(monitor.start())
                self.assertIsNone(monitor._thread)

    def test_default_remains_enabled(self):
        monitor = LinuxProcessMonitor('fixture', {})
        self.addCleanup(monitor.stop)
        monitor.poll = lambda: None
        self.assertTrue(monitor.start())
        self.assertTrue(monitor.stop())

    def test_stop_interrupts_long_sleep(self):
        monitor = self.make()
        called = threading.Event()
        monitor.poll = called.set
        self.assertTrue(monitor.start())
        self.assertTrue(called.wait(1))
        before = time.monotonic()
        self.assertTrue(monitor.stop())
        self.assertLess(time.monotonic() - before, 1)
        self.assertFalse(monitor._thread.is_alive())
        self.assertEqual(monitor.status()['state'], 'stopped')

    def test_repeated_start_keeps_one_worker(self):
        monitor = self.make()
        called = threading.Event()
        monitor.poll = called.set
        monitor.start()
        self.assertTrue(called.wait(1))
        worker = monitor._thread
        callers = [threading.Thread(target=monitor.start) for _ in range(16)]
        for caller in callers:
            caller.start()
        for caller in callers:
            caller.join(1)
        self.assertIs(monitor._thread, worker)
        self.assertTrue(monitor.stop())

    def test_inflight_poll_must_finish_before_restart(self):
        monitor = self.make()
        entered, release = threading.Event(), threading.Event()
        self.addCleanup(release.set)

        def poll():
            entered.set()
            release.wait(2)

        monitor.poll = poll
        monitor.start()
        self.assertTrue(entered.wait(1))
        original = monitor._thread
        self.assertFalse(monitor.stop(wait_seconds=0))
        self.assertEqual(monitor.status()['state'], 'stopping')
        self.assertFalse(monitor.start())
        self.assertIs(monitor._thread, original)
        release.set()
        self.assertTrue(monitor.stop())
        self.assertTrue(monitor.start())
        self.assertIsNot(monitor._thread, original)
        self.assertTrue(monitor.stop())

    def test_stop_and_restart_can_repeat(self):
        monitor = self.make()
        for _ in range(10):
            called = threading.Event()
            monitor.poll = called.set
            self.assertTrue(monitor.start())
            self.assertTrue(called.wait(1))
            self.assertTrue(monitor.stop())
            self.assertFalse(monitor.liveness()['thread_alive'])

    def test_failed_poll_can_be_stopped_and_restarted(self):
        monitor = self.make()
        called = threading.Event()

        def fail():
            called.set()
            raise RuntimeError('fixture failure')

        monitor.poll = fail
        monitor.start()
        self.assertTrue(called.wait(1))
        self.assertTrue(monitor.stop())
        self.assertEqual(monitor.status()['consecutive_failures'], 1)
        recovered = threading.Event()
        monitor.poll = recovered.set
        monitor.start()
        self.assertTrue(recovered.wait(1))
        self.assertTrue(monitor.stop())
        self.assertEqual(monitor.status()['consecutive_failures'], 0)

    def test_failed_thread_start_can_be_stopped_and_retried(self):
        monitor = self.make()
        monitor.poll = lambda: None
        with patch.object(threading.Thread, 'start', side_effect=RuntimeError('fixture')):
            with self.assertRaises(RuntimeError):
                monitor.start()
        self.assertFalse(monitor.status()['running'])
        self.assertTrue(monitor.stop())
        self.assertTrue(monitor.start())
        self.assertTrue(monitor.stop())

    def test_history_survives_stop(self):
        monitor = self.make()
        monitor._last_result = {'process_count': 7, 'finding_count': 0}
        monitor.poll = lambda: None
        monitor.start()
        monitor.stop()
        self.assertEqual(monitor.status()['process_count'], 7)


if __name__ == '__main__':
    unittest.main()
