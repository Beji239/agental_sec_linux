// scripts/verify_expectations_page.js, the Expectations page's own rendering.
// Runs the page's functions against made-up payloads and reads what they drew:
// the mood word, one dot per device, the 24 hour clock, one card per
// expectation, the "I have seen this" button only on an unseen break, and
// names from outside escaped. Needs node and no running app.
//
//   node scripts/verify_expectations_page.js

'use strict';

const fs = require('fs');
const path = require('path');

const PAGE = path.join(path.resolve(__dirname, '..'), 'ui', 'index.html');
const FAIL = [];
let passed = 0;

function ok(cond, msg, detail) {
  if (cond) passed++; else FAIL.push(msg);
  console.log(`  [${cond ? 'PASS' : 'FAIL'}] ${msg}`);
  if (detail && !cond) console.log(`         ${String(detail).slice(0, 400)}`);
}

function pageScript() {
  const html = fs.readFileSync(PAGE, 'utf8');
  const start = html.indexOf('<script>\n', html.indexOf('<script src=')) + '<script>\n'.length;
  const end = html.lastIndexOf('</script>');
  return html.slice(start, end);
}

function grab(src, name) {
  const i = src.indexOf('function ' + name + '(');
  if (i < 0) throw new Error('missing function ' + name + ' in the page');
  let depth = 0, started = false;
  for (let j = i; j < src.length; j++) {
    if (src[j] === '{') { depth++; started = true; }
    else if (src[j] === '}') { depth--; if (started && depth === 0) {
      const before = src.slice(Math.max(0, i - 8), i);
      return (/async\s+$/.test(before) ? 'async ' : '') + src.slice(i, j + 1);
    } }
  }
  throw new Error('unterminated function ' + name);
}

const els = {};
global.document = {
  getElementById(id) {
    els[id] = els[id] || { innerHTML: '', textContent: '', style: {}, disabled: false };
    return els[id];
  },
};

function load() {
  const src = pageScript();
  const consts = src.slice(src.indexOf('const EXP_COLOR'), src.indexOf('async function loadExpectations('));
  const body = [
    consts,
    grab(src, 'esc'), grab(src, 'fmtTime'), grab(src, 'parseUtc'),
    grab(src, 'renderExpectations'), grab(src, 'drawMoodRing'), grab(src, '_arc'),
    grab(src, 'drawWatchClock'), grab(src, '_expFill'), grab(src, 'renderExpTickets'),
    'let EXP_PICKED = null;',
    grab(src, '_expBytes'), grab(src, 'drawDeviceOrbit'), grab(src, 'renderExpDevice'),
    src.slice(src.indexOf('const FA_FAMILY'), src.indexOf('function _faColour(')),
    grab(src, '_faColour'), grab(src, '_faDot'), grab(src, 'renderFalseAlarms'), grab(src, 'resetFalseAlarms'),
    'function _setFA(d) { FA_DATA = d; }',
    'return { renderExpectations, renderExpDevice, renderFalseAlarms, resetFalseAlarms, _setFA };',
  ].join('\n');
  return new Function(body)();
}

const now = new Date();
const iso = d => d.toISOString().replace('.000Z', '+00:00');
const hours = Array.from({ length: 24 }, (_, i) => ({
  hour: iso(new Date(now.getTime() - (23 - i) * 3600e3)), router: 1, capture: i > 20 ? 0.5 : 0,
}));
const exp = (over) => Object.assign({
  id: 1, kind: 'head_count', subject: '', title: 'The same devices stay on the network',
  state: 'holding', detail: 'No new device.', since: iso(now), broken_at: null,
  acknowledged_at: null, history: [], evidence: {},
}, over);
const HOSTILE = '<img src=x onerror=alert(1)>';

const page = load();

console.log('A calm network');
page.renderExpectations({
  mood: 'calm', sentence: 'Nothing new, nothing broken.', checked_at: iso(now), coverage: 1,
  router: { ok: true, agent_version: 9, firewall: 'nft', blocks: [], reasons: [] },
  devices: [{ ip: '172.21.0.10', name: 'tv', state: 'holding' },
            { ip: '172.21.0.11', name: HOSTILE, state: 'new' },
            { ip: '172.21.0.12', name: 'cam', state: 'blocked' }],
  watch_24h: hours,
  expectations: [exp({}), exp({ id: 2, kind: 'quiet_nights', state: 'unknown', title: 'Quiet nights' })],
});
ok(els['exp-mood-word'].textContent === 'Calm', 'the mood word is Calm', els['exp-mood-word'].textContent);
ok(els['exp-mood-word'].style.color === 'var(--green)', 'and green');
const ring = els['exp-ring-wrap'].innerHTML;
ok((ring.match(/class="exp-dot/g) || []).length === 3, 'one dot per device');
ok(ring.includes('exp-mood-calm'), 'the ring carries the calm motion class');
ok(!ring.includes('<img') && ring.includes('&lt;img'), 'a device name from outside is escaped', ring);
ok((els['exp-clock-wrap'].innerHTML.match(/<path /g) || []).length === 48,
   'the clock has 24 hours on two rings');
const cards = els['exp-tickets'].innerHTML;
ok((cards.match(/class="exp-ticket /g) || []).length === 2, 'one card per expectation');
ok(cards.includes('Could not check'), 'an unknown check says so in words');
ok(!cards.includes('I have seen this'), 'no seen button without a break');
ok(els['exp-router-note'].textContent.includes('version 9'), 'the router note names the agent version');

console.log('\nA broken block');
page.renderExpectations({
  mood: 'alarmed', sentence: 'A block leaked.', checked_at: iso(now), coverage: 1,
  router: { ok: true, agent_version: 9, firewall: 'nft', blocks: ['198.51.100.7'], reasons: [] },
  devices: [{ ip: '172.21.0.10', name: 'pc', state: 'broken' }], watch_24h: hours,
  expectations: [
    exp({ id: 7, kind: 'block_holds', state: 'broken', title: 'No traffic to or from ' + HOSTILE,
          detail: 'The block leaked.', broken_at: iso(now) }),
    exp({ id: 8, kind: 'block_holds', state: 'holding', broken_at: iso(new Date(now - 7200e3)),
          acknowledged_at: iso(now) }),
  ],
});
ok(els['exp-mood-word'].textContent === 'Alarmed', 'the mood word is Alarmed');
ok(els['exp-ring-wrap'].innerHTML.includes('exp-dot-broken'), 'the breaking device blinks');
const c2 = els['exp-tickets'].innerHTML;
ok((c2.match(/I have seen this/g) || []).length === 1,
   'the seen button shows on the unseen break only', c2);
ok(c2.includes('ackExpectation(7)'), 'and acts on that expectation');
ok(!c2.includes('<img'), 'a title from outside is escaped in the card');

console.log('\nA router that cannot back the checks');
page.renderExpectations({
  mood: 'uneasy', sentence: 'Not everything could be checked.', checked_at: null,
  router: { ok: false, reasons: ['Could not read the router'] },
  devices: [], watch_24h: [], expectations: [],
});
ok(els['exp-mood-word'].textContent === 'Uncertain', 'the mood word is Uncertain');
ok(els['exp-router-note'].textContent.includes('cannot back'), 'the router note says why');
ok(els['exp-ring-wrap'].innerHTML.includes('no device list'), 'an empty ring says there is no list');
ok(els['exp-tickets'].innerHTML.includes('No expectation has been set'), 'no cards says so');
ok(els['exp-checked'].textContent === 'Not checked yet.', 'not checked yet is said');

console.log('\nOne device');
const dot = els['exp-ring-wrap'].innerHTML;
page.renderExpectations({
  mood: 'calm', sentence: '', checked_at: null, router: { ok: true, blocks: [] },
  devices: [{ ip: '172.21.0.30', name: 'tv', state: 'holding' }], watch_24h: [], expectations: [],
});
ok(els['exp-ring-wrap'].innerHTML.includes('data-ip="172.21.0.30"'), 'a device dot carries its address to click');
ok(typeof els['exp-ring-wrap'].onclick === 'function', 'the ring listens for clicks');
page.renderExpDevice({
  ip: '172.21.0.30', mac: 'aa:aa:aa:aa:aa:30', name: HOSTILE, blocked: true, apps_blocked: [],
  learning: false, usual_total: 20,
  usual: Array.from({ length: 16 }, (_, i) => ({ contact: 'svc' + i + '.example', connections: 3, bytes: 2048, first: iso(now) })),
  new: [{ contact: '<b>odd.example</b>', connections: 1, bytes: 20, first: iso(now) }], new_total: 1,
  countries: [{ label: 'Iceland', hits: 2, new: true }],
  expectations: [{ id: 7, kind: 'block_holds', title: 'No traffic to or from x', state: 'holding', detail: 'Held.' }],
});
const dev = els['exp-device'].innerHTML;
ok((dev.match(/<circle cx="[^"]*" cy="[^"]*" r="5"/g) || []).length === 16, 'usual contacts on the inner ring');
ok((dev.match(/class="exp-orbit-new"/g) || []).length === 1, 'the new contact dashed on the outer ring');
ok(dev.includes('4 more not shown'), 'a capped list says how many it left out');
ok(dev.includes('blocked on the router'), 'the block is named');
ok(dev.includes('Iceland, new today'), 'a new country is marked');
ok(!dev.includes('<b>odd') && !dev.includes('<img'), 'names from outside are escaped', dev);
page.renderExpDevice({ ip: '172.21.0.31', name: 'new', learning: true, usual: [], new: [], countries: [], expectations: [] });
ok(els['exp-device'].innerHTML.includes('less than a day'), 'a device watched under a day says so');
page.renderExpDevice({ error: 'not an address' });
ok(els['exp-device'].innerHTML.includes('not an address'), 'a refused address says so');

console.log('\nFalse alarms per day');
const dotA = (id, rule, verdict, by) => ({ id, rule, entity: '203.0.113.70', title: HOSTILE, verdict, verdict_by: by });
page._setFA({
  days: [{ day: '2026-10-11', false_alarms: 1, dots: [dotA(1, 'FED-1002', 'false_alarm', 'owner')] },
         { day: '2026-10-12', false_alarms: 1, dots: [dotA(1, 'FED-1002', 'false_alarm', 'owner'),
            dotA(2, 'LNX-2007', null, null), dotA(3, 'LAN-1008', 'real', 'model'), dotA(4, 'DNS-1001', 'not_sure', 'dismissal')] },
         { day: '2026-10-13', false_alarms: 0, dots: [] }],
  rules: [{ rule: 'FED-1002', false_alarm: 2, real: 0, not_sure: 0, unlabelled: 0, days: 2 }],
  unlabelled: [dotA(2, 'LNX-2007', null, null)], unlabelled_total: 5,
});
page.renderFalseAlarms();
const fa = els['fa-days'].innerHTML;
ok((fa.match(/<svg width="14"/g) || []).length === 5, 'one dot per incident per day');
ok(fa.indexOf('Oct') > -1 && fa.indexOf('nothing fired') > -1, 'a quiet day says nothing fired');
ok(fa.indexOf('stroke="var(--red)"') > -1, 'a real incident has a red ring');
ok(fa.indexOf('stroke-dasharray="2 2"') > -1, 'not sure is dashed');
ok(fa.indexOf('fill="var(--amber)"') > -1, 'a FED false alarm is a filled amber dot');
ok(fa.indexOf('the model, on your word') > -1 && fa.indexOf('from a dismissal') > -1, 'who gave the verdict is in the tip');
ok(!fa.includes('<img'), 'titles from outside are escaped in the dots', fa);
const todo = els['fa-todo'].innerHTML;
ok(todo.includes('data-incident="2"') && (todo.match(/data-verdict=/g) || []).length === 3, 'three verdict buttons per open incident');
ok(todo.includes('4 more without a verdict'), 'the open list says how many it left out');
ok(!todo.includes('<img'), 'titles from outside are escaped in the list');
ok(els['fa-rules'].innerHTML.includes('FED-1002: 2 false'), 'the rule totals are shown');
ok(typeof els['fa-rules'].onclick === 'function' && typeof els['fa-todo'].onclick === 'function', 'rules and buttons listen for clicks');
ok(els['fa-showing'].textContent === 'Showing every rule.' && els['fa-reset'].disabled, 'nothing picked, Show all is off');
const chip = { closest: () => ({ getAttribute: () => 'FED-1002' }) };
els['fa-rules'].onclick({ target: chip });
const picked = els['fa-days'].innerHTML;
ok((picked.match(/class="fa-dim"/g) || []).length === 3, 'picking a rule fades the other dots');
ok(els['fa-showing'].textContent.includes('FED-1002 only') && !els['fa-reset'].disabled, 'a pick says which rule, and Show all is on');
page.resetFalseAlarms();
ok(!els['fa-days'].innerHTML.includes('fa-dim') && els['fa-reset'].disabled, 'Show all brings every dot back');

console.log(`\n${passed} passed, ${FAIL.length} failed`);
if (FAIL.length) { console.log('FAILURES:', JSON.stringify(FAIL, null, 2)); process.exit(1); }
