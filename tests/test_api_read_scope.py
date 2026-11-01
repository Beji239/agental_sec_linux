"""Integration credentials cannot become dashboard or approval credentials."""
import json
import pathlib
import sys
import os
import tempfile
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import _isolate_db
db = _isolate_db.isolate()
from core import actions, migrations, memory_engine as me, module_feed, agent_loop
from api.server import create_app
from api import dashboard_session as ds
from core import secret_store

migrations.run_migrations(db)
READ = 'test-read-credential'
PRIVATE = 'test-dashboard-credential'
app = create_app({'flask': {'host': '127.0.0.1'}}, {}, 'scope-test',
                 api_key=READ, dashboard_key=PRIVATE)
client = app.test_client()
read = {'X-API-Key': READ}
dashboard = {ds.HEADER: ds.new_session(PRIVATE)}
request = actions.write_request('block_port', {'port': 43821, 'direction': 'inbound'},
                                'Temporary test request')
rid = request['request_id']
failures = []


def check(label, ok):
    print(f"{'PASS' if ok else 'FAIL'} {label}")
    if not ok:
        failures.append(label)


check('read key can read findings', client.get('/api/findings', headers=read).status_code == 200)
with patch.object(actions, 'decide') as decide, \
        patch.object(agent_loop, 'set_permission_decision') as live:
    for url, body in [(f'/api/actions/{rid}/approve', {}),
                      (f'/api/actions/{rid}/deny', {}),
                      ('/api/permissions/approve', {'call_id': 'scope-test'}),
                      ('/api/permissions/deny', {'call_id': 'scope-test'}),
                      ('/api/settings/config', {'path': 'flask.port', 'value': 5999}),
                      ('/api/settings/key', {'env': 'AGENTAL_DASHBOARD_KEY', 'value': 'x' * 64}),
                      ('/api/module-host/remote/switch', {'on': True})]:
        check('read key refused before writing ' + url,
              client.post(url, json=body, headers=read).status_code == 403)
    check('no approval backend was reached', not decide.called and not live.called)
check('read key cannot be exchanged for a dashboard session',
      client.post('/open', json={'key': READ}).status_code == 401)
check('read key cannot sign a browser session',
      client.get('/api/findings', headers={ds.HEADER: ds.new_session(READ)}).status_code == 401)
forged = ds.open_link_token(READ)
check('read key cannot sign a one-time dashboard link',
      ds.STORAGE_KEY not in client.get('/open?t=' + forged).get_data(as_text=True))
check('dashboard key does not authenticate as a read API key',
      client.get('/api/findings', headers={'X-API-Key': PRIVATE}).status_code == 401)
with patch.object(actions, 'execute_pending') as execute:
    answer = client.post(f'/api/actions/{rid}/approve', json={}, headers=dashboard)
    check('dashboard can approve without executing inside the request',
          answer.status_code == 200 and not execute.called)
row = actions.query_requests(request_id=rid)[0]
check('dashboard decision source is persisted', 'Decision from dashboard' in row['decision_note'])
check('request body cannot choose decision source',
      answer.get_json().get('decision_source') == 'dashboard')
request = actions.write_request('block_port', {'port': 43822, 'direction': 'inbound'},
                                'Phone source test')
out = module_feed.decide('action', request['request_id'], 'deny', 'Example Person')
check('paired phone decision has its own source',
      out['result'].get('decision_source') == 'phone')
row = actions.query_requests(request_id=request['request_id'])[0]
check('phone source and person are persisted',
      'Decision from phone' in row['decision_note'] and 'Example Person' in row['decision_note'])
check('private dashboard key can sign in',
      client.post('/open', json={'key': PRIVATE}).status_code == 200)
try:
    create_app({}, {}, 'bad', api_key=READ, dashboard_key=READ)
    check('equal credentials are refused', False)
except ValueError:
    check('equal credentials are refused', True)
try:
    create_app({}, {}, 'bad-case', api_key=READ, dashboard_key=READ.upper())
    check('case changes cannot disguise a reused key', False)
except ValueError:
    check('case changes cannot disguise a reused key', True)
with tempfile.TemporaryDirectory() as folder, patch.dict(os.environ, {}, clear=True):
    first = secret_store.resolve({}, pathlib.Path(folder))
    check('first start creates distinct credentials',
          first['dashboard_key_created'] and first['dashboard_key'] != first['app_api_key'])
    second = secret_store.resolve({}, pathlib.Path(folder))
    check('a later start keeps the signing key and existing sessions',
          not second['dashboard_key_created'] and first['dashboard_key'] == second['dashboard_key'])
sys.exit(bool(failures))
