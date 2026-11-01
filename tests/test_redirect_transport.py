"""Redirects cannot downgrade transport or leave refused responses open."""
import pathlib
import sys
from unittest.mock import Mock, patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from core import safe_http

failures = []


def check(label, ok):
    print(f"{'PASS' if ok else 'FAIL'} {label}")
    if not ok:
        failures.append(label)


def reply(target, status=307):
    return Mock(is_redirect=True, status_code=status, headers={'location': target})


for method in ('get', 'post'):
    response = reply('http://service.example/next')
    with patch.object(safe_http, 'is_local', return_value=False), \
            patch.object(safe_http.requests, method, side_effect=[
                response, Mock(is_redirect=False)]) as call:
        refused = False
        try:
            getattr(safe_http, method)(
                'https://service.example/start', same_host=True,
                headers={'X-API-Key': 'test-placeholder'})
        except safe_http.RedirectRefused:
            refused = True
        check(method + ' refuses HTTPS downgrade before the next request',
              refused and call.call_count == 1)
        check(method + ' closes the refused response', response.close.called)

for target, reason in [('https://127.0.0.1/next', 'local destination'),
                       ('https://other.example/next', 'key leaving its host')]:
    response = reply(target)
    with patch.object(safe_http, 'is_local', return_value=True), \
            patch.object(safe_http.requests, 'get', return_value=response) as call:
        try:
            safe_http.get('https://service.example/start', same_host=True)
        except safe_http.RedirectRefused:
            pass
        check(reason + ' closes the response and makes no second request',
              response.close.called and call.call_count == 1)

for start, target in [('https://service.example/start', 'https://service.example/next'),
                      ('http://service.example/start', 'https://service.example/next')]:
    response, final = reply(target), Mock(is_redirect=False)
    with patch.object(safe_http, 'is_local', return_value=False), \
            patch.object(safe_http.requests, 'get', side_effect=[response, final]):
        check('secure redirects and HTTP upgrades still work',
              safe_http.get(start) is final and response.close.called)

sys.exit(bool(failures))
