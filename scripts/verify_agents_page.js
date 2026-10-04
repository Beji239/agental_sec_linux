#!/usr/bin/env node
// scripts/verify_agents_page.js — the Agents page's evidence.
//
// WHY THIS EXISTS. The owner's report, 2026-09-18: *"the agent was supposed to
// run only 4 to max 5 times a day, its constantly running now."* The cause was
// in core/duty.py (the schedule was computed and never consulted — see
// _tick_once). The FIX has a failure mode of its own on this page, and it is
// the one every check in this project is organised against: once the loop
// looks at the clock every minute and wakes four times a day, THE PAGE MUST
// NOT DRAW A HEALTHY, CORRECTLY-SCHEDULED LOOP AS A DEAD ONE.
//
// `ticks` alone cannot carry that: most of a session is polls. So polls and
// wake-ups are separate numbers with separate words, "nothing was due" has its
// own line naming the next moment, and this asserts the page draws them
// apart — running THE PAGE'S OWN RENDERERS (never a copy: a copy is how a
// check and the code it checks drift) against the shapes /api/agents returns.
//
// The failure this would have caught, stated as a regression: a renderer that
// printed `ticks` only would show `wake-ups this session: 0` beside a green
// "running" line for most of the day, which reads exactly like the loop the
// owner complained about having stopped.
//
// USE:
//   node scripts/verify_agents_page.js
//       Composes the payload from the real database via core.duty, read-only.
//   node scripts/verify_agents_page.js --api http://127.0.0.1:5000 --key HEX
//       The same shape over real HTTP from a running app.
//
// Requires node. It is a check of the page, and the page is JavaScript.

'use strict';

const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const PAGE = path.join(ROOT, 'ui', 'index.html');

const PASS = [], FAIL = [];
function ok(cond, msg, detail) {
  (cond ? PASS : FAIL).push(msg);
  console.log(`  [${cond ? 'PASS' : 'FAIL'}] ${msg}`);
  if (detail && !cond) console.log(`         ${detail}`);
}
function section(title) {
  console.log('\n— ' + title + ' ' + '-'.repeat(Math.max(0, 66 - title.length)));
}

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

// Extract one function VERBATIM by brace matching. Throws if the page renames
// or drops it, rather than silently checking nothing.
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

// the page

// A DOM stub with exactly what renderDutyState touches, so the renderer runs
// unmodified. `innerHTML` is captured; anything else it needs throws loudly.
function makeEl() {
  return { innerHTML: '', textContent: '' };
}
global.document = {
  getElementById(id) {
    global.__els = global.__els || {};
    global.__els[id] = global.__els[id] || makeEl();
    return global.__els[id];
  },
};

function loadRenderers() {
  const src = pageScript();
  const body = [
    grab(src, 'esc'),
    grab(src, 'parseUtc'),
    grab(src, 'fmtTime'),
    grab(src, 'fmtTokens'),
    grab(src, 'renderDutyState'),
    grab(src, 'runRow'),
    'return { esc, fmtTime, fmtTokens, renderDutyState, runRow };',
  ].join('\n');
  return new Function(body)();
}

// the data

function payloadFromDatabase() {
  const py = `
import json, sys
sys.path.insert(0, ${JSON.stringify(ROOT)})
from core import duty
out = {
    "summary": duty.summary(),
    "status":  duty.status(),
    "reports": duty.query_reports(limit=50),
    "runs":    duty.query_runs(limit=50),
}
print(json.dumps(out, default=str))
`;
  const raw = execFileSync('python3', ['-c', py],
                           { cwd: ROOT, encoding: 'utf8',
                             maxBuffer: 32 * 1024 * 1024 });
  return JSON.parse(raw);
}

function payloadFromApi(base, key) {
  const out = execFileSync('curl', ['-s', '-f',
    '-H', 'X-API-Key: ' + key,
    base.replace(/\/$/, '') + '/api/agents?limit=50'],
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
    data = payloadFromApi(base, key);
    source = 'live HTTP ' + base;
  } else {
    data = payloadFromDatabase();
    source = 'the real database via core.duty (read-only)';
  }

  const P = loadRenderers();
  console.log('source: ' + source);

  // ,, 1. A HEALTHY SCHEDULED LOOP MUST NOT READ AS A STOPPED ONE.
  section('1. polls are drawn apart from wake-ups');
  const healthy = {
    running: true, blind: false, ticks: 0, polls: 37,
    last_poll: '2026-09-19 05:55:00', last_tick: null,
    last_skip: { reason: 'not due', local_hour: 22, next_hour: 9,
                 next_is_tomorrow: true, hours: [9, 13, 17, 21] },
    last_skip_at: '2026-09-19 05:55:00',
    schedule: { hours: [9, 13, 17, 21], next_hour: 9,
                next_is_tomorrow: true, local_hour: 22 },
    budget: { investigations_last_hour: 0, max_per_hour: 3,
              tokens_last_24h: 0, daily_token_ceiling: 2000000 },
  };
  P.renderDutyState(healthy);
  const html = document.getElementById('duty-state').innerHTML;
  console.log('  drawn: ' + html.replace(/<[^>]+>/g, ' ').trim().slice(0, 220));
  ok(/running/.test(html), 'a running loop says running');
  ok(/looked at the clock/.test(html),
     'the poll count is NAMED, not just a bare wake-up count');
  ok(/wake-ups this session: 0/.test(html),
     'and the wake-up count is still shown, as its own sentence');
  ok(/nothing was due/.test(html),
     'a skipped poll says what it was — nothing due, with the next moment');
  ok(/09:00 today|09:00 tomorrow/.test(html) || /next moment at/.test(html),
     'and names when the next wake-up is');
  // THE REGRESSION ITSELF: with ticks=0 and no poll count, "wake-ups this
  // session: 0" beside green "running" is the dead-loop picture.
  ok(!(/wake-ups this session: 0/.test(html) && !/looked at the clock/.test(html)),
     'a zero wake-up count is NEVER shown without the poll count beside it');

  // ,, 2. A LOOP THAT IS NOT RUNNING STILL READS AS NOT RUNNING.
  section('2. blind and stopped still outrank everything');
  P.renderDutyState({ running: true, blind: true, ticks: 0, polls: 9,
                      blind_reason: 'the spend ledger cannot be read' });
  const blindHtml = document.getElementById('duty-state').innerHTML;
  ok(/NOT INVESTIGATING/.test(blindHtml),
     'a blind loop says NOT INVESTIGATING');
  ok(/spend ledger cannot be read/.test(blindHtml),
     'and carries the reason');
  P.renderDutyState({ running: false, blind: true, ticks: 3, polls: 12,
                      blind_reason: 'the duty loop is not running' });
  const stopped = document.getElementById('duty-state').innerHTML;
  ok(/not running/.test(stopped), 'a stopped loop says not running');

  // ,, 3. A WAKE-UP CLEARS THE STALE SKIP.
  section('3. the page cannot describe an old hour beside new work');
  P.renderDutyState(Object.assign({}, healthy, {
    last_skip: null, last_skip_at: null, ticks: 1,
    last_tick: '2026-09-19 06:10:00',
  }));
  const afterWake = document.getElementById('duty-state').innerHTML;
  ok(!/nothing was due/.test(afterWake),
     'no "nothing was due" line survives a wake-up');
  ok(/last wake-up/.test(afterWake), 'the wake-up is the line shown');

  // ,, 4. THE REAL RECORD RENDERS.
  section('4. the page renders the real rows');
  const runs = (data.runs || []).slice(0, 6);
  console.log('  run rows: ' + (data.runs || []).length);
  for (const r of runs) {
    const rowHtml = P.runRow(r);
    console.log(`  #${r.id} ${r.trigger}/${r.outcome} -> `
                + rowHtml.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').slice(0, 90));
    ok(!!rowHtml && rowHtml.length > 30, `#${r.id} renders a row`);
    if (r.outcome === 'budget') {
      ok(/STOPPED BY A BUDGET/.test(rowHtml),
         `#${r.id} a budget refusal is drawn as a LIMIT, not as quiet`);
    }
    if (r.outcome === 'idle') {
      ok(/nothing eligible/.test(rowHtml), `#${r.id} idle says nothing eligible`);
    }
  }
  // AND THE TWO MOST COMMON OUTCOMES NEVER LOOK ALIKE — the rule the whole
  // Agents page is organised around.
  const budgetRow = P.runRow({ outcome: 'budget', trigger: 'regular',
                               ran_at: '2026-09-19 05:00:00' });
  const idleRow = P.runRow({ outcome: 'idle', trigger: 'regular',
                             ran_at: '2026-09-19 05:00:00' });
  ok(budgetRow !== idleRow && /STOPPED BY A BUDGET/.test(budgetRow)
     && /nothing eligible/.test(idleRow),
     'budget and idle are DIFFERENT rows, never the same sentence');

  // ,, 5. THE STATUS THE PAGE READS CARRIES THESE FIELDS.
  section('5. the API carries what the page needs');
  const st = data.status || {};
  ok(st.polls !== undefined,
     'status carries `polls` (the page cannot draw a number it is not sent)',
     JSON.stringify(Object.keys(st)));
  ok(st.schedule && st.schedule.hours,
     'status carries the schedule', JSON.stringify(st.schedule));
  ok(data.summary && data.summary.available !== false,
     'the summary reports itself available — an empty page is still readable');
  console.log(`  polls=${st.polls} ticks=${st.ticks} `
              + `last_poll=${st.last_poll || '-'} `
              + `last_skip=${st.last_skip ? JSON.stringify(st.last_skip) : '-'}`);

  console.log('\n' + '='.repeat(70));
  console.log(`  ${PASS.length} passed, ${FAIL.length} failed`);
  if (FAIL.length) {
    console.log('  FAILED:');
    for (const f of FAIL) console.log('    - ' + f);
  }
  console.log('='.repeat(70));
  return FAIL.length ? 1 : 0;
}

process.exit(main());
