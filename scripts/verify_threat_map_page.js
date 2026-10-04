#!/usr/bin/env node
// scripts/verify_threat_map_page.js — the Threat Map page's own rendering.
//
// WHY THIS EXISTS, 2026-09-23. The page's caveat block and its not-host list
// are written by loadThreatMap from the payload, and a source grep for the
// strings proves only that the strings are in the file. This runs the PAGE'S
// OWN FUNCTION against the shapes the real route returns, so what is checked is
// the rendering that actually happens — the same discipline
// verify_agents_page.js was written for, and for the same reason: once a
// renderer is fed the right dict, the failure mode that matters is the branch
// it does not take.
//
// THE THREE BRANCHES, and the defect each one exists for:
//
//   1. A BLIND CAPTURE. Unelevated on this host the sniffer cannot open a raw
//      socket, so nothing was captured this session and every endpoint is from
//      an earlier elevated run. The stats line said "N conversations this
//      session" over exactly that.
//   2. A SEVERITY THAT COULD NOT BE READ. `unknown` is not a severity; it is
//      the absence of a reading, and a legend built from a fixed key list drops
//      it while the dot keeps a colour. Coloured dot, no key, reader invents a
//      meaning.
//   3. AN ADDRESS THAT IS NOT A HOST. PKT-1017's target is the sender's own
//      malformed header. It must be LISTED (a finding that vanishes is the
//      failure this project is organised against) and NOT drawn.
//
// USE:
//   node scripts/verify_threat_map_page.js
//       Builds each payload by hand; needs no database and no network.
//   node scripts/verify_threat_map_page.js --api http://127.0.0.1:5000 --key HEX
//       Adds a section that calls the REAL route and renders its real payload.
//
// Requires node. It is a check of the page, and the page is JavaScript.

'use strict';

const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const PAGE = path.join(ROOT, 'ui', 'index.html');

const PASS = [], FAIL = [];
// Uncaught exceptions raised by the page after a render returns. A timer that
// dereferences null throws HERE, not inside the await, so a verifier that only
// watches its own control flow would see every check pass and no problem.
const TIMER_THREW = [];
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
  const start = html.indexOf('<script>\n', html.indexOf('<script src=')) + '<script>\n'.length;
  const end = html.lastIndexOf('</script>');
  if (start < 0 || end <= start) throw new Error('could not find the page script block in ' + PAGE);
  return html.slice(start, end);
}

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

// Grab AND keep the declaration keyword. The page has async functions
// (drawBaseMap and loadThreatMap both await a fetch), and an `await` inside a
// body compiled by `new Function` without an `async` declaration is a
// SyntaxError. Keeping the page's own keyword means this file cannot disagree
// with the page about which functions are async.
function grabDecl(src, name) {
  const i = src.indexOf('function ' + name + '(');
  if (i < 0) throw new Error('missing function ' + name + ' in the page');
  const before = src.slice(Math.max(0, i - 8), i);
  const isAsync = /async\s+$/.test(before);
  return (isAsync ? 'async ' : '') + grab(src, name);
}

// the DOM

// Exactly what loadThreatMap touches: three elements by id, plus the map. The
// Leaflet calls are stubbed as no-ops so the drawing code runs without a
// browser, and the marker count is captured so "not drawn" can be asserted as
// a NUMBER rather than inferred from prose.
const els = {};
function makeEl() { return { innerHTML: '', textContent: '' }; }
global.document = {
  getElementById(id) { els[id] = els[id] || makeEl(); return els[id]; },
};

let MARKERS = [];
global.L = {
  // setView RETURNS THE MAP, as Leaflet does. The page writes
  // `map = L.map(...).setView(...)`, so a stub returning undefined sets the
  // page's own `map` variable to undefined and the next line throws
  // "Cannot read properties of undefined". That is exactly how this file failed
  // the second time, and the fix is to imitate the library rather than the page.
  map: () => {
    const m = {
      remove() {}, fitBounds() {}, invalidateSize() {},
      setView() { return m; },
    };
    return m;
  },
  layerGroup: () => ({ addTo() { return this; }, remove() {} }),
  polyline: (pts) => { MARKERS.push({ kind: 'arc', pts }); return { addTo() { return this; } }; },
  circleMarker: (ll) => { MARKERS.push({ kind: 'dot', ll }); return { addTo() { return this; }, bindPopup() { return this; } }; },
  geoJSON: () => ({ addTo() {} }),
};

// The page's state, injected: loadThreatMap reads and writes these globals.
//
// loadThreatMap is `async function` in the page, so the wrapper it is built in
// must be async too -- a Function body containing `await` outside an async
// function is a SyntaxError, which is how this file failed on its first run.
function loadPage() {
  const src = pageScript();
  const body = [
    'let map = null; let mapLayer = null; let baseMapDrawn = true;',
    grabDecl(src, 'esc'),
    grabDecl(src, 'drawBaseMap'),
    grabDecl(src, 'loadThreatMap'),
    grabDecl(src, 'shortLon'),
    grabDecl(src, 'arcPoints'),
    grabDecl(src, 'fmtBytes'),
    // SEV_COLOR / SEV_RANK are consts in the page, not functions: lift them
    // verbatim so the colours under test are the page's.
    src.slice(src.indexOf('const SEV_COLOR'), src.indexOf('let mapLayer = null;')),
    'return { loadThreatMap, SEV_COLOR, SEV_RANK };',
  ].join('\n');
  return new Function('fetch', 'authHeaders', body)(stubFetch, () => ({}));
}

let RESPONSE = null;
function stubFetch() { return Promise.resolve({ json: async () => RESPONSE, ok: true }); }

// payloads

function basePayload(over) {
  return Object.assign({
    home: { lat: 1, lon: 2, label: 'home', ips: ['192.0.2.207'] },
    endpoints: [
      { ip: '9.9.9.9', lat: 10, lon: 20, place: 'Somewhere', country: 'US', cc: 'US',
        packets: 10, bytes: 100, ports: ['443'], protocols: ['tcp'],
        peers: ['192.0.2.207'], severity: 'none', reason: '' },
    ],
    geoip: { ready: true, status: 'ready' },
    pairs_read: 5,
    without_geo: 0,
    severity_read: true,
    severity_read_error: null,
    not_hosts: [],
    not_hosts_count: 0,
    capture: { blind: false, blind_reason: null, running: true, interface: 'wlp1s0' },
  }, over || {});
}

// the run

async function main() {
  const argv = process.argv.slice(2);
  const apiIx = argv.indexOf('--api');
  const keyIx = argv.indexOf('--key');

  section('the page renders, and none of the branches is dead');
  const page = loadPage();

  // THE HOME PIN IS TWO MARKERS, not one: a soft halo at radius 17 plus the
  // dot at radius 7, drawn so the pin sits above the arcs converging on it.
  // Asserted as a count WITH the home markers named, so this check cannot
  // quietly pass because a renderer stopped drawing something.
  function dotCount() { return MARKERS.filter(m => m.kind === 'dot').length; }

  // 1. a healthy run: no caveat is invented
  RESPONSE = basePayload();
  MARKERS = [];
  await page.loadThreatMap();
  ok(els['map-caveats'].innerHTML === '',
     'a healthy run draws no caveat at all',
     els['map-caveats'].innerHTML);
  ok(/1 external endpoint/.test(els['map-stats'].textContent),
     'the stats line counts the endpoints', els['map-stats'].textContent);
  ok(/conversations this session/.test(els['map-stats'].textContent),
     'and may say "this session" when capture is running',
     els['map-stats'].textContent);
  ok(dotCount() === 3,
     'one endpoint dot plus the two home-pin markers', `${dotCount()} dots: `
     + JSON.stringify(MARKERS.map(m => m.kind + (m.ll ? JSON.stringify(m.ll) : ''))));
  ok(MARKERS.filter(m => m.kind === 'arc').length === 1,
     'and one arc from home to the endpoint', String(MARKERS.length));

  // 2. a BLIND capture
  RESPONSE = basePayload({ capture: { blind: true, blind_reason: 'No raw socket access.', running: false } });
  await page.loadThreatMap();
  const caveats = els['map-caveats'].innerHTML;
  ok(/NOTHING IS BEING CAPTURED/.test(caveats),
     'a blind capture is stated on the card', caveats);
  ok(/No raw socket access\./.test(caveats),
     'and it carries the sensor\'s own reason', caveats);
  ok(/NOT from this session/.test(caveats),
     'and says the endpoints are not from this session', caveats);
  ok(!/conversations this session/.test(els['map-stats'].textContent),
     'AND THE STATS LINE STOPS CLAIMING THIS SESSION',
     els['map-stats'].textContent);

  // A null capture block must not crash the renderer: a build with no sniffer
  // module reports null, and null is not "healthy".
  RESPONSE = basePayload({ capture: null });
  await page.loadThreatMap();
  ok(true, 'a null capture block does not throw');
  ok(els['map-caveats'].innerHTML === '',
     'and with nothing known, no claim is made either way');

  // 3. an unreadable findings table
  RESPONSE = basePayload({
    endpoints: [{ ip: '9.9.9.9', lat: 1, lon: 2, place: 'x', cc: 'US', packets: 3, bytes: 3,
                  ports: [], protocols: [], peers: [], severity: 'unknown', reason: '' }],
    severity_read: false, severity_read_error: 'no such table: findings',
  });
  await page.loadThreatMap();
  const caveats2 = els['map-caveats'].innerHTML;
  ok(/read 'unknown'/.test(caveats2),
     'an unread findings table is stated in words', caveats2);
  ok(/nothing on this map was checked/i.test(caveats2),
     'and says that nothing was checked', caveats2);
  ok(/Unknown is not the same as "no findings"/.test(caveats2),
     'and separates the two meanings of the grey', caveats2);
  ok(/COULD NOT BE READ/.test(els['map-legend'].innerHTML),
     'THE LEGEND HAS A WORD FOR IT, so a grey dot is not a mystery',
     els['map-legend'].innerHTML);

  // 4. an address that is not a host
  RESPONSE = basePayload({
    not_hosts: [{ ip: '1.0.0.10', packets: 3, bytes: 150, severity: 'low',
                  reason: 'Routing ICMP whose source contradicts its own body',
                  detection_id: 'PKT-1017',
                  note: 'The address in this finding is the sender\'s own malformed header, not a host.' }],
    not_hosts_count: 1,
  });
  MARKERS = [];
  await page.loadThreatMap();
  const caveats3 = els['map-caveats'].innerHTML;
  ok(/1 address\(es\) are not drawn/.test(caveats3),
     'the not-host list is ON THE CARD, not silently dropped', caveats3);
  ok(/1\.0\.0\.10/.test(caveats3), 'and names the address', caveats3);
  ok(/PKT-1017/.test(caveats3), 'and names the rule that raised it', caveats3);
  ok(/not a fact about anything that talked to this machine/.test(caveats3),
     'and refuses to give it a country', caveats3);
  // NOT DRAWN, AND SAID SO. Three dots here would mean the address was plotted
  // anyway -- a page that lists it as unplottable and draws it regardless has
  // moved the lie rather than fixed it.
  ok(dotCount() === 3,
     'AND IT IS NOT DRAWN: one endpoint dot plus the two home-pin markers only',
     `${dotCount()} dots`);

  // 5. both at once, which is the live case
  RESPONSE = basePayload({
    capture: { blind: true, blind_reason: 'No raw socket access.', running: false },
    not_hosts: [{ ip: '1.0.0.10', packets: 3, bytes: 150, severity: 'low',
                  reason: 'r', detection_id: 'PKT-1017', note: 'n' },
                { ip: '11.22.37.169', packets: 3, bytes: 150, severity: 'low',
                  reason: 'r', detection_id: 'PKT-1017', note: 'n' }],
    not_hosts_count: 2,
  });
  await page.loadThreatMap();
  const caveats4 = els['map-caveats'].innerHTML;
  ok(/2 address\(es\) are not drawn/.test(caveats4), 'both cases render together', caveats4);
  ok(/NOTHING IS BEING CAPTURED/.test(caveats4), 'both caveats, not one', caveats4);
  ok(/2 not a host, listed below/.test(els['map-stats'].textContent),
     'and the stats line points at the list', els['map-stats'].textContent);

  // 6. the geo database missing: the page's own notice
  RESPONSE = basePayload({ geoip: { ready: false, status: 'maxminddb not installed' } });
  await page.loadThreatMap();
  ok(/Geolocation database not loaded/.test(els['threat-map'].innerHTML),
     'a missing geo database still says exactly what is missing',
     els['threat-map'].innerHTML.slice(0, 120));

  // 6b. A MAP REMOVED BETWEEN RENDERS, WHICH IS A PAGE BUG
  //
  // Found by this file: 24 checks passed and then the process died at
  // `setTimeout(() => map.invalidateSize(), 60)`. The no-geo branch above does
  // `map.remove(); map = null`, and `map` is a module-level variable, so the
  // sequence "render with a geodatabase, then re-render without one inside
  // 60 ms" dereferences null. Reproduced against the pre-fix line: one uncaught
  // "Cannot read properties of null (reading 'invalidateSize')".
  //
  // Checked here rather than only in the scratch repro, because a fixed bug
  // that nothing asserts is a bug waiting to come back -- and this one is a
  // timer, so it fires after the code that caused it has returned.
  process.on('uncaughtException', e => { TIMER_THREW.push(String(e && e.message)); });
  RESPONSE = basePayload();
  await page.loadThreatMap();
  RESPONSE = basePayload({ geoip: { ready: false, status: 'gone' } });
  await page.loadThreatMap();
  await new Promise(r => setTimeout(r, 250));    // past the 60 ms timer
  ok(TIMER_THREW.length === 0,
     'a map removed between two renders does not crash the page afterwards',
     JSON.stringify(TIMER_THREW));
  ok(/Geolocation database not loaded/.test(els['threat-map'].innerHTML),
     'and the no-geo notice is the one that survives', els['threat-map'].innerHTML.slice(0, 80));

  // 7. the live route, if asked
  if (apiIx >= 0) {
    const base = argv[apiIx + 1];
    const key = keyIx >= 0 ? argv[keyIx + 1] : '';
    if (!base || !key) {
      console.error('--api needs a URL AND --key HEX. Refusing to guess a key.');
      process.exit(2);
    }
    section('the LIVE route, rendered by the page');
    const raw = execFileSync('curl', ['-s', '-f', '-H', 'X-API-Key: ' + key,
      base.replace(/\/$/, '') + '/api/threatmap'], { encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 });
    RESPONSE = JSON.parse(raw);
    MARKERS = [];
    await page.loadThreatMap();
    console.log(`    ${RESPONSE.endpoints.length} endpoint(s), ` +
                `${RESPONSE.not_hosts_count} not-a-host, capture blind=` +
                `${RESPONSE.capture ? RESPONSE.capture.blind : 'unknown'}`);
    ok(els['map-stats'].textContent.length > 0, 'the live payload renders');
    const nh = RESPONSE.not_hosts_count || 0;
    ok(nh === 0 || /not drawn/.test(els['map-caveats'].innerHTML),
       'every not-host address on the live map is on the card',
       els['map-caveats'].innerHTML);
  }

  console.log(`\n${PASS.length} passed, ${FAIL.length} failed`);
  if (FAIL.length) { console.log('FAILURES: ' + JSON.stringify(FAIL, null, 2)); process.exit(1); }
}

main().catch(e => { console.error('the page threw: ' + e.stack); process.exit(1); });
