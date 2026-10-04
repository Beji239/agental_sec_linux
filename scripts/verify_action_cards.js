#!/usr/bin/env node
// scripts/verify_action_cards.js — T3's UI evidence, and the counterpart to the
// browser-driving checks the orca task used.
//
// WHY THIS EXISTS, AND WHY IT IS NOT A PYTHON CHECK.
//
// scripts/verify_actions.py asserts what the QUEUE does. This asserts what the
// PAGE DRAWS, and those are different failures. T3's own live verification
// found a defect that was invisible on both sides: the queue held the address,
// the API served the address, and the card on screen printed "Block ? at this
// host's firewall", because _decode() pops params_json before card_for() reads
// it. Nothing in the Python suite could have caught that, and nothing here can
// catch it either unless it runs THE PAGE'S OWN FUNCTIONS against REAL ROWS.
//
// So that is what this does. It reads ui/index.html, extracts the actual
// renderers out of the shipping page (never a copy of them — a copy is how a
// check and the code it checks drift apart), and runs them on rows that came
// from the real API.
//
// THE TWO MODES:
//
//   node scripts/verify_action_cards.js
//       Reads the rows through core.actions from the real database, read-only,
//       and composes them in the same shape the /api/actions route returns.
//       No server, no key, safe to run any time.
//
//   node scripts/verify_action_cards.js --api http://127.0.0.1:5000 --key HEX
//       Fetches the SAME shape over real HTTP from a running app. Strictly the
//       higher-fidelity mode, because it is the response the browser receives.
//
// Requires node. It is a check of the page, and the page is JavaScript.

'use strict';

const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const PAGE = path.join(ROOT, 'ui', 'index.html');

// plumbing

const PASS = [], FAIL = [];
function ok(cond, msg, detail) {
  (cond ? PASS : FAIL).push(msg);
  console.log(`  [${cond ? 'PASS' : 'FAIL'}] ${msg}`);
  if (detail && !cond) console.log(`         ${detail}`);
}
function section(title) {
  console.log('\n— ' + title + ' ' + '-'.repeat(Math.max(0, 66 - title.length)));
}

// The page's whole <script> body, between the vendor tag and the last close.
function pageScript() {
  const html = fs.readFileSync(PAGE, 'utf8');
  const start = html.indexOf('<script>\n', html.indexOf('<script src='))
              + '<script>\n'.length;
  const end = html.lastIndexOf('</script>');
  if (start < 0 || end < 0 || end <= start) {
    throw new Error('could not find the page script block in ' + PAGE);
  }
  return html.slice(start, end);
}

// Extract one function VERBATIM by brace matching. If the page renames or
// drops it, this throws rather than silently checking nothing — a check that
// quietly stops running is the exact failure this project is organised against.
function grab(src, name) {
  const i = src.indexOf('function ' + name + '(');
  if (i < 0) throw new Error('missing function ' + name + ' in the page');
  let depth = 0, started = false;
  for (let j = i; j < src.length; j++) {
    const c = src[j];
    if (c === '{') { depth++; started = true; }
    else if (c === '}') { depth--; if (started && depth === 0) return src.slice(i, j + 1); }
  }
  throw new Error('unterminated function ' + name);
}

// A template-literal constant. Returned as a `var` so eval leaks it into the
// scope the renderers see (const in eval is scoped to the eval itself).
function grabConst(src, name) {
  const i = src.indexOf('const ' + name + ' = `');
  if (i < 0) throw new Error('missing const ' + name + ' in the page');
  const start = src.indexOf('`', i);
  const end = src.indexOf('`', start + 1);
  return 'var ' + name + ' = ' + src.slice(start, end + 1) + ';';
}

// A DOM stub with exactly what renderQueueCard touches, so the card renderer
// runs unmodified. Anything it needs beyond this throws loudly.
function makeEl(tag) {
  return {
    tagName: tag, className: '', innerHTML: '', children: [],
    appendChild(el) { this.children.push(el); },
  };
}
global.document = { createElement: makeEl };

// the data

function rowsFromDatabase() {
  const py = `
import json, sys
sys.path.insert(0, ${JSON.stringify(ROOT)})
from core import actions
out = {
    "summary":      actions.summary(),
    "executor":     actions.status(),
    "requests":     actions.query_requests(limit=200),
    "notification": actions.last_notification_status(),
}
print(json.dumps(out))
`;
  const raw = execFileSync('python3', ['-c', py],
                           { cwd: ROOT, encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 });
  return JSON.parse(raw);
}

function rowsFromApi(base, key) {
  const out = execFileSync('curl', ['-s', '-f',
    '-H', 'X-API-Key: ' + key,
    base.replace(/\/$/, '') + '/api/actions?limit=200'],
    { encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 });
  return JSON.parse(out);
}

// the run

function main() {
  const argv = process.argv.slice(2);
  const apiIx = argv.indexOf('--api');
  const keyIx = argv.indexOf('--key');

  let data, source;
  if (apiIx >= 0) {
    const base = argv[apiIx + 1];
    const key = keyIx >= 0 ? argv[keyIx + 1] : '';
    if (!base || !key) {
      console.error('--api needs a URL AND --key HEX. Refusing to guess a key.');
      process.exit(2);
    }
    data = rowsFromApi(base, key);
    source = 'live HTTP ' + base;
  } else {
    data = rowsFromDatabase();
    source = 'the real database via core.actions (read-only)';
  }

  const src = pageScript();

  // ONE Function BODY, not a series of evals. Under 'use strict' (module
  // scope) a function declared inside eval stays inside that eval, so the
  // renderers would vanish between calls. Assembling them into one body and
  // returning them cannot have that problem, and it also means a missing
  // helper throws at load rather than at the first row.
  const body = [
    grabConst(src, 'APPROVAL_WARNING'),
    grab(src, 'esc'),
    grab(src, 'parseUtc'),
    grab(src, 'fmtTime'),
    grab(src, 'actionOutcomeLine'),
    grab(src, 'actionRow'),
    grab(src, 'renderQueueCard'),
    'return { esc, parseUtc, fmtTime, actionOutcomeLine, actionRow,'
      + ' renderQueueCard, APPROVAL_WARNING };',
  ].join('\n');

  const P = new Function(body)();
  const { actionOutcomeLine, actionRow, renderQueueCard } = P;

  // ,, 1. THE REAL ROWS
  section('1. the page\'s own row renderer, on real rows');
  console.log('  source: ' + source);
  const rows = data.requests || [];
  console.log('  rows: ' + rows.length + '   summary: ' + JSON.stringify(
    data.summary && { pending: data.summary.pending, approved: data.summary.approved,
                      denied: data.summary.denied, expired: data.summary.expired,
                      failed: data.summary.failed, executed: data.summary.executed }));
  ok(Array.isArray(rows), 'the payload carries a requests array');
  ok(data.summary && data.summary.available !== false,
     'the queue reports itself available (an empty queue is still readable)');

  for (const r of rows) {
    const [line, colour] = actionOutcomeLine(r);
    const html = actionRow(r);
    const action = (r.card || {}).action || '';
    console.log(`  #${r.id} ${r.state}/${r.outcome || '-'}  action: ${action}`);
    console.log(`     line: ${String(line).slice(0, 108)}`);
    ok(!!line && !!colour, `#${r.id} has an outcome line`);
    ok(!!html && html.length > 40, `#${r.id} renders a row`);
    // THE DEFECT T3 FOUND LIVE, AS A REGRESSION CHECK: a subject that was
    // dropped in the API path printed as a bare '?'.
    ok(!/Block \?|Kill process PID \?|Quarantine file: \?/.test(action)
       && !/\?$/.test(action),
       `#${r.id} card NAMES its subject (no bare "?")`);
  }

  // ,, 2. EVERY STATE, ITS OWN SENTENCE
  section('2. one sentence per state, and none of them collide');
  const shapes = [
    ['executed',          { state: 'executed', outcome: 'success' }],
    ['executed+declined', { state: 'executed', outcome: 'refused', error: 'tool said no' }],
    ['failed+refused',    { state: 'failed', outcome: 'refused', error: 'no root' }],
    ['failed',            { state: 'failed', outcome: 'error', error: 'boom' }],
    ['denied',            { state: 'denied', decision_note: 'not now' }],
    ['expired',           { state: 'expired' }],
    ['approved',          { state: 'approved', decided_at: '2026-09-18 10:00:00' }],
    ['pending',           { state: 'pending' }],
  ];
  const seen = new Map();
  for (const [label, row] of shapes) {
    const [line] = actionOutcomeLine(row);
    console.log('  ' + label.padEnd(17) + ' -> ' + String(line).slice(0, 92));
    ok(!!line && String(line).trim().length > 0, label + ' has a sentence');
    if (seen.has(line)) ok(false, label + ' reads IDENTICALLY to ' + seen.get(line));
    seen.set(line, label);
  }
  const denied  = actionOutcomeLine({ state: 'denied' })[0];
  const expired = actionOutcomeLine({ state: 'expired' })[0];
  ok(denied !== expired, 'denied and expired are DIFFERENT sentences');
  ok(/not run|did NOT run/i.test(expired), 'expired says plainly it did not run');
  ok(/not a denial/i.test(expired), 'expired also says it is NOT a denial');
  ok(/Nothing ran, ever\.$/.test(denied), 'denied says nothing ran, EVER');
  ok(/refused/i.test(actionOutcomeLine(
       { state: 'failed', outcome: 'refused', error: 'x' })[0])
     && !/^Failed/.test(actionOutcomeLine(
       { state: 'failed', outcome: 'refused', error: 'x' })[0]),
     'a REFUSED row is not dressed up as a failure');

  // THE PERIOD-JOIN DEFECT, found 2026-09-18 by rendering a real denied row:
  // the dashboard's own default note already ends in a stop, so the naive
  // concatenation printed "No reason given.. Nothing ran, ever."
  section('3. the denial note is joined, never concatenated');
  const withStop = actionOutcomeLine({ state: 'denied',
    decision_note: 'Denied from the dashboard. No reason given.' })[0];
  const noStop   = actionOutcomeLine({ state: 'denied', decision_note: 'not now' })[0];
  console.log('  note ending in a stop -> ' + withStop);
  console.log('  note with no stop     -> ' + noStop);
  ok(!/\.\./.test(withStop), 'a note that ends in a stop does NOT double it');
  ok(/No reason given\. Nothing ran, ever\.$/.test(withStop),
     'and it joins cleanly after the note');
  ok(/not now\. Nothing ran, ever\.$/.test(noStop),
     'a note with no stop still gets one');
  ok(withStop.indexOf('Denied from the dashboard. No reason given.') >= 0,
     'the note is reproduced VERBATIM (a decision record is not edited)');

  // ,, 4. THE PENDING CARD
  section('4. the pending card, through the real renderer');
  const row = { id: 999, verb: 'block_device', target: '203.0.113.9',
    state: 'pending', proposed_by: 'model', created_at: '2026-09-18 12:00:00',
    reason: 'harness row',
    card: { action: 'Block 203.0.113.9 at this host\u2019s firewall',
            reason: 'harness row',
            evidence: { rule: 'NET-1001', count: 12 },
            warning: 'blocking reduces your own reachability',
            waiting_note: 'Nothing is waiting on this. It sits until you decide.' } };
  const c = makeEl('div');
  renderQueueCard(c, row);
  const html = c.children[0].children[0].innerHTML;
  ok(/waiting on you/i.test(html), 'the card says it was FILED BY THE AGENT');
  ok(/Approve and run/.test(html) && /Deny/.test(html), 'both buttons are present');
  ok(/What this rests on/.test(html), 'the evidence block is rendered');
  ok(/Look it up before you approve or deny it/.test(html),
     'the SAME APPROVAL_WARNING the chat card carries is on it');
  ok(/Block 203\.0\.113\.9/.test(html), 'the card names its subject');

  // Negative control: a request filed with no evidence must SAY SO rather than
  // render a bare card that reads like it had nothing worth showing.
  const bare = { id: 1000, verb: 'kill_process', target: 'pid 42',
    state: 'pending', proposed_by: 'model',
    card: { action: 'Kill process PID 42', reason: 'r' } };
  const c2 = makeEl('div');
  renderQueueCard(c2, bare);
  ok(/No evidence block was attached/.test(c2.children[0].children[0].innerHTML),
     'a card with no evidence says so in words (negative control)');

  // ,, verdict
  console.log('\n' + '='.repeat(70));
  console.log(`  ${PASS.length} passed, ${FAIL.length} failed`);
  console.log('='.repeat(70));
  console.log('\nThis checks the PAGE. The queue itself is scripts/verify_actions.py;');
  console.log('this does not replace it and does not duplicate it.');
  process.exit(FAIL.length ? 1 : 0);
}

main();
