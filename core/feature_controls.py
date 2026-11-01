"""Live collector choices are separate from saved startup preferences."""
import json
import logging
import threading

logger = logging.getLogger(__name__)


class FeatureControls:
    NAME = 'process_monitor'

    def __init__(self, config, modules, persist=None):
        self._config = config
        self._modules = modules
        self._persist = persist
        self._lock = threading.RLock()
        self._closed = False
        self._automatic, self._startup_error = self._startup_choice(config)

    def _startup_choice(self, config):
        raw_startup = config.get('feature_startup')
        startup = raw_startup if isinstance(raw_startup, dict) else {}
        legacy = ((config.get('sensors') or {}).get(self.NAME) or {}).get('enabled', True)
        preferred = startup[self.NAME] if self.NAME in startup else legacy
        invalid = (raw_startup is not None and not isinstance(raw_startup, dict))
        invalid = invalid or type(preferred) is not bool
        error = ('Invalid startup preference. Automatic collection is off. '
                 'Check feature_startup in config.json.' if invalid else None)
        return preferred is True and not invalid, error

    def prepare_startup(self):
        with self._lock:
            monitor = self._modules.get(self.NAME)
            if monitor is not None:
                monitor.set_runtime_enabled(self._automatic)

    def snapshot(self):
        with self._lock:
            monitor = self._modules.get(self.NAME)
            detail = monitor.status() if monitor is not None else {}
            live = monitor.liveness() if monitor is not None else {}
            state = detail.get('state', 'unavailable')
            automatic, startup_error = self._automatic, self._startup_error
            try:
                from core.settings import CONFIG_PATH
                saved = json.loads(CONFIG_PATH.read_text(encoding='utf-8'))
                automatic, startup_error = self._startup_choice(saved)
            except Exception:
                startup_error = 'Saved startup preference could not be read. The shown choice may be out of date.'
            row = {
                'id': self.NAME, 'title': 'Process observation',
                'state': state, 'running': detail.get('running', False),
                'worker_alive': bool(live.get('thread_alive')),
                'automatic_start': automatic,
                'startup_error': startup_error,
                'available': monitor is not None,
                'last_success_at': live.get('last_ok_at'),
                'last_error': detail.get('last_error'),
                'reason': detail.get('reason') or (
                    'Observing processes on this computer.' if state == 'running'
                    else 'Collector unavailable. Check the startup log.'),
                'scope': 'This watches running programs on this computer. '
                         'Other monitoring features have separate controls.',
                'effect_when_stopped': 'Stops repeated process checks. A check already running '
                                       'may finish. Stored findings remain available.',
            }
            return {'features': [row], 'shutting_down': self._closed}

    def change_running(self, name, running):
        if name != self.NAME:
            return {'ok': False, 'error': 'Unknown feature'}, 404
        if type(running) is not bool:
            return {'ok': False, 'error': 'running must be true or false'}, 400
        from core.sensor_watch import CONTROL_GUARD
        with self._lock, CONTROL_GUARD:
            if self._closed:
                return {'ok': False, 'error': 'The app is shutting down'}, 503
            monitor = self._modules.get(name)
            if monitor is None:
                return {'ok': False, 'error': 'Collector unavailable. Check the startup log.'}, 503
            if running:
                if monitor.status().get('state') == 'stopping':
                    return {'ok': False, 'error': 'The previous pass is still finishing.'}, 409
                monitor.set_runtime_enabled(True)
                try:
                    started = monitor.start()
                except Exception as error:
                    logger.warning("Process collector start failed (%s)", type(error).__name__)
                    monitor.set_runtime_enabled(False)
                    monitor.stop(wait_seconds=0)
                    return {'ok': False, 'error': 'The collector could not start. Check the log.'}, 503
                if not started:
                    return {'ok': False, 'error': 'The collector is not ready to restart.'}, 409
            else:
                monitor.set_runtime_enabled(False)
                monitor.stop(wait_seconds=0)
            from core import sensor_watch, memory_engine
            recorded = sensor_watch.record_control_choice(name, running, monitor.session_id)
            memory_engine._journal('feature_run_changed', 'feature', name,
                                   {'running': running, 'source': 'dashboard'})
            result = dict(self.snapshot(), ok=True)
            if not recorded:
                result['warning'] = 'Collector choice applied, but coverage history could not be recorded.'
            return result, 200

    def change_startup(self, name, enabled):
        if name != self.NAME:
            return {'ok': False, 'error': 'Unknown feature'}, 404
        if type(enabled) is not bool:
            return {'ok': False, 'error': 'enabled must be true or false'}, 400
        with self._lock:
            if self._closed:
                return {'ok': False, 'error': 'The app is shutting down'}, 503
            persist = self._persist
            if persist is None:
                from core.settings import persist_config_value
                persist = persist_config_value
            try:
                error = persist('feature_startup', name, enabled)
            except Exception:
                error = 'The preference writer failed.'
            if error:
                return {'ok': False, 'error': 'Startup preference could not be saved.'}, 500
            self._automatic = enabled
            self._startup_error = None
            from core import memory_engine
            memory_engine._journal('feature_startup_changed', 'feature', name,
                                   {'enabled': enabled, 'source': 'dashboard'})
            return dict(self.snapshot(), ok=True), 200

    def shutdown(self):
        from core.sensor_watch import CONTROL_GUARD
        with self._lock, CONTROL_GUARD:
            self._closed = True
            monitor = self._modules.get(self.NAME)
            if monitor is not None:
                monitor.set_runtime_enabled(False)
                monitor.stop(wait_seconds=0)
