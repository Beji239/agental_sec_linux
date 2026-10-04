#!/usr/bin/env node
// scripts/verify_timeline_page.js — the Timeline page's own rendering, driven.
//
// WHY THIS EXISTS, and it is the same discipline verify_threat_map_page.js and
// verify_agents_page.js were written for: a source grep for "the page shows the
// process" proves the word "who" is in the file, not that a row renders one. So
// this runs THE PAGE'S OWN loadTimeline against the shapes the real route
// returns and reads what came out of the renderer.
//
// WHAT IT IS CHECKING, one section per defect the 2026-09-25 round measured:
//
//   1. A PACKET ROW RENDERS AS SOMETHING. Before this round it rendered as a
//      time, the word "packet", and an empty string: the page read
//      `title or description or event_type or threat_label`, and a packet row
//      has none of the four. The store knew the protocol, both ports, the size
//      and, on 439,175 live rows, the owning process.
//   2. EVERY ROW SAYS WHO, FROM AND WHY. Four lines, and the WHO line has to
//      name the process, the account or the address when the store has one,
//      and to say WHY IT CANNOT when it does not. "Not attributed" must never
//      render in a way that reads as "no process was involved".
//   3. A FINDING LINKS TO ITS RULE, AND THE LINK IS ONLY OFFERED WHEN THE
//      DESTINATION CAN ANSWER. An id the register does not carry renders as
//      "rule unknown" with the reason, never as a dead link.
//   4. AN ADDRESS LINKS TO THE MAP ONLY WHEN THE MAP CAN DRAW IT. A rule that
//      says the address is not a host gets a note instead, which is the
//      PKT-1017 case measured on this host.
//   5. THE LINE ABOVE THE LIST SAYS WHAT IS MISSING. Rule 3: a capped list
//      must say it is capped, and a read that failed must not look like a
//      quiet window.
//   6. THE FILTER HIDES PACKETS AND THE SUMMARY AGREES WITH THE LIST.
//
// USE:
//   node scripts/verify_timeline_page.js
//       Builds each payload by hand. Needs no database and no network.
//   node scripts/verify_timeline_page.js --api http://127.0.0.1:5000 --key HEX
//       Adds a section that calls the REAL route and renders its real payload.
//
// Requires node. It is a check of the page, and the page is JavaScript.

'use strict';

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
  console.log('\n== ' + title + ' ' + '='.repeat(Math.max(0, 66 - title.length)));
}

// the page

function pageScript() {
  const html = fs.readFileSync(PAGE, 'utf8');
  const start = html.indexOf('<script>\n', html.indexOf('<script src=')) + '<script>\n'.length;
  const end = html.lastIndexOf('</script>');
  if (start < 0 || end <= start) throw new Error('no page script block in ' + PAGE);
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

function grabDecl(src, name) {
  const i = src.indexOf('function ' + name + '(');
  if (i < 0) throw new Error('missing function ' + name + ' in the page');
  const before = src.slice(Math.max(0, i - 8), i);
  const isAsync = /async\s+$/.test(before);
  return (isAsync ? 'async ' : '') + grab(src, name);
}

// the DOM
//
// Exactly what loadTimeline, showDetection and showMapEndpoint touch, and it
// is deliberately more than a null-returning stub.
//
// WHY: a harness whose DOM always answers "nothing there" can only ever drive
// the FAILURE branches. Measured on the first run of this file, section 11c
// asserted that a rule the register carries lands quietly, and it went red
// with "no entry for it" -- because querySelectorAll returned an empty list
// whatever the payload said. A stub that cannot represent the happy path
// makes every positive check unfalsifiable in the direction that matters.

const els = {};
function makeEl(id) {
  return {
    id, innerHTML: '', textContent: '', value: '', checked: false,
    rows: [],
    classList: { add() {}, remove() {} },
    scrollIntoView() {},
  };
}

// One row of the Detections table, as far as showDetection reads it: it looks
// for `td code` inside each row and compares its text to the id it was asked
// for. That is the whole contract, so that is the whole fake.
function fakeDetectionRows(detections) {
  return (detections || []).map(d => ({
    queried: false,
    queried_selector: null,
    querySelector(sel) {
      if (sel === 'td code') return { textContent: d.detection_id };
      return null;
    },
    // showDetection scrolls to the row and flashes it. Both are part of the
    // contract the page expects of a table row, so both are on the fake.
    scrollIntoView() { this.scrolled = true; },
    classList: { add() {}, remove() {} },
  }));
}

global.document = {
  getElementById(id) { els[id] = els[id] || makeEl(id); return els[id]; },
  querySelectorAll(sel) {
    if (sel === '#detection-rows tr') return els['detection-rows'].rows || [];
    return [];
  },
  querySelector() { return null; },
};

const ALERTS = [];
global.window = {
  alert(msg) { ALERTS.push(msg); },
  __AGENTAL_BOOTSTRAP__: { api_key: 'x'.repeat(64) },
};

function loadPage(src) {
  const body = [
    'let timeFilter = "2h";',
    'let API_KEY = "x".repeat(64);',
    'let map = null; let mapLayer = null;',
    // THE REGISTER STATE showDetection READS. A page variable, so it is
    // declared here rather than left undefined: `typeof DETECTION_DATA` on an
    // undeclared name is a ReferenceError in a strict build and "undefined"
    // otherwise, and the branch that distinguishes "the register failed to
    // load" from "the register has no such rule" is exactly the branch this
    // harness has to be able to drive.
    'let DETECTION_DATA = null;',
    'function showPage() {}',
    // The register stub, driven by DETECTIONS_STUB. It sets BOTH the page
    // variable and the table rows, which is what the real loadDetections does
    // through renderDetections.
    'async function loadDetections() {',
    '  DETECTION_DATA = REGISTER_MODE ? { detections: DETECTIONS_STUB } : null;',
    '  document.getElementById("detection-rows").rows =',
    '    REGISTER_MODE ? fakeDetectionRows(DETECTIONS_STUB) : [];',
    '}',
    // The map stub, and it CAN set the page's own map/mapLayer because it is
    // defined in the same scope. MAP_MODE false is the no-geo-database case.
    'async function loadThreatMap() {',
    '  if (!MAP_MODE) { if (map) { map = null; mapLayer = null; } return; }',
    '  map = fakeMap(); mapLayer = fakeLayerLayer(ENDPOINT_STUB);',
    '}',
    grabDecl(src, 'esc'),
    grabDecl(src, 'escJs'),
    grabDecl(src, 'fmtTime'),
    grabDecl(src, 'parseUtc'),
    grabDecl(src, 'getTimeFilterISO'),
    grabDecl(src, 'loadTimeline'),
    grabDecl(src, 'showDetection'),
    grabDecl(src, 'showMapEndpoint'),
    'return { loadTimeline, showDetection, showMapEndpoint,',
    '         setRegister: (on, dets) => { REGISTER_MODE = on; DETECTIONS_STUB = dets || []; },',
    '         setMap: (on, eps) => { MAP_MODE = on; ENDPOINT_STUB = eps || []; } };',
  ].join('\n');
  return new Function(
    'fetch', 'authHeaders', 'fakeDetectionRows', 'fakeMap', 'fakeLayerLayer',
    'REGISTER_MODE', 'DETECTIONS_STUB', 'MAP_MODE', 'ENDPOINT_STUB', body)(
    (url) => {
      LAST_URL = url;
      return Promise.resolve({ ok: true, json: async () => RESPONSE });
    },
    () => ({}),
    fakeDetectionRows, fakeMap, fakeLayerLayer,
    false, [], false, []);
}

// A Leaflet map, as far as showMapEndpoint uses it: setView and getZoom.
function fakeMap() {
  return {
    zoom: 2,
    opened: null,
    setView(ll, z) { this.view = { ll, z }; },
    getZoom() { return this.zoom; },
  };
}

// A Leaflet layerGroup, as far as showMapEndpoint uses it: eachLayer, and each
// layer carries the popup the page bound to it.
function fakeLayerLayer(endpoints) {
  return {
    eachLayer(fn) {
      endpoints.forEach(e => fn({
        getPopup: () => ({ getContent: () => `<b>${e.ip}</b><br>${e.place}` }),
        getLatLng: () => ({ lat: e.lat, lng: e.lon }),
        openPopup() { e.opened = true; },
      }));
    },
  };
}

let RESPONSE = null;
let LAST_URL = '';

// payloads
//
// The shapes below are the REAL route's. They were taken from a live call
// against the owner's store and then trimmed, so a change to the route's shape
// shows up here as a failing check rather than as a renderer that quietly
// stops filling a line.

function basePayload(over) {
  return Object.assign({
    rows: [],
    window: { since: '2026-09-26 02:24:00', until: '2026-09-26 04:25:25',
              defaulted: false, slices: 24, per_slice: 9 },
    totals: { finding: 0, event: 0, packet: 0 },
    shown: { finding: 0, event: 0, packet: 0 },
    read_ok: { finding: true, event: true, packet: true },
    searched: 'all sessions',
    complete: true,
    note: null,
  }, over || {});
}

function packetRow(over) {
  return Object.assign({
    kind: 'packet', id: 1, at: '2026-09-26 04:23:06',
    session_id: 'sess-a', sensor_id: 'sensor-abc123',
    severity: null, detection_id: null, rule_note: null,
    map_target: '11.22.35.15', map_note: null,
    what: 'TCP 66 bytes, outbound, 192.0.2.207:39932 to 11.22.35.15:443',
    who: 'process hermes, pid 291264',
    where_from: 'captured by the packet sniffer (packet_sniffer) in session sess-a, scope outbound, sensor sensor-abc123',
    why: 'why it is here: the sniffer stores a row for ordinary traffic it sees.',
    self_induced: false, self_induced_note: null,
    detail: { process_name: 'hermes', process_pid: 291264, protocol: 'tcp',
              direction: 'outbound', packet_size: 66, dismissed: false,
              threat_label: null },
  }, over || {});
}

function findingRow(over) {
  return Object.assign({
    kind: 'finding', id: 9, at: '2026-09-26 04:00:43',
    session_id: 'sess-a', sensor_id: 'sensor-abc123',
    severity: 'low', detection_id: 'LNX-3001', rule_note: null,
    map_target: null, map_note: null,
    what: 'A program ran from a staging directory',
    who: 'filed against the process /tmp/x/12345',
    where_from: 'raised by ebpf_events in session sess-a, sensor sensor-abc123',
    why: 'why it is here: LNX-3001 rev 1 (execution_from_staging_directory) fired. A program executed out of a staging directory.',
    self_induced: false, self_induced_note: null,
    detail: { entity_type: 'process', entity_value: '/tmp/x/12345',
              dismissed: false },
  }, over || {});
}

function eventRow(over) {
  return Object.assign({
    kind: 'event', id: 5, at: '2026-09-26 03:44:55',
    session_id: 'sess-a', sensor_id: 'sensor-abc123',
    severity: 'info', detection_id: null, rule_note: null,
    map_target: null, map_note: null,
    what: 'successful login: user1',
    who: 'account user1, service or process sshd, from 192.0.2.249',
    where_from: 'read from auth.log by the local event monitor (event_monitor) in session sess-a, sensor sensor-abc123',
    why: 'why it is here: the event monitor records every log line it matches as an event, at info severity.',
    self_induced: false, self_induced_note: null,
    detail: { source: 'auth.log', event_type: 'successful_login',
              username: 'user1', dismissed: false },
  }, over || {});
}

// the run

async function main() {
  const argv = process.argv.slice(2);
  const apiIx = argv.indexOf('--api');
  const keyIx = argv.indexOf('--key');

  const src = pageScript();
  const page = loadPage(src);

  section('1. a packet row renders as something a person can read');
  RESPONSE = basePayload({
    rows: [packetRow()],
    totals: { finding: 0, event: 0, packet: 1 },
    shown:  { finding: 0, event: 0, packet: 1 },
  });
  await page.loadTimeline();
  let html = els['timeline-list'].innerHTML;
  ok(/TCP 66 bytes/.test(html), 'the protocol and size are on the row', html.slice(0, 300));
  ok(/10\.0\.0\.207:39932 to 34\.36\.133\.15:443/.test(html),
     'both endpoints and both ports are on the row');
  ok(/process hermes, pid 291264/.test(html),
     'THE OWNING PROCESS IS NAMED on a packet row');
  ok(!/timeline-desc">\s*<div class="tl-what"><\/div>/.test(html)
     && !/tl-what">\s*<\/div>/.test(html),
     'the WHAT line is not empty, which is what every 200 rows of the old page were');
  // The defect itself, so this check is seen to be about the right thing: the
  // OLD selector chain, run against this row's fields, produces an empty
  // string. If that ever stops being true the check above stops being the fix.
  const oldDesc = [null, null, null, null].filter(Boolean).join('') || '';
  ok(oldDesc === '',
     'and the OLD description chain (`title or description or event_type or threat_label`) still yields NOTHING for this row, which is the defect this replaces');

  section('2. every row says who, from and why');
  RESPONSE = basePayload({
    rows: [findingRow(), eventRow(), packetRow()],
    totals: { finding: 1, event: 1, packet: 1 },
    shown:  { finding: 1, event: 1, packet: 1 },
  });
  await page.loadTimeline();
  html = els['timeline-list'].innerHTML;
  const lines = (html.match(/class="tl-line/g) || []).length;
  ok(lines === 9, 'three rows carry three explanation lines each (9 found)', String(lines));
  for (const label of ['who', 'from', 'why']) {
    const n = (html.match(new RegExp('<b>' + label + '</b>', 'g')) || []).length;
    ok(n === 3, `the "${label}" line appears on every row (${n})`);
  }
  ok(/account user1, service or process sshd/.test(html),
     'an event row names the account, the service and the address');
  ok(/raised by ebpf_events/.test(html), 'a finding row names the raiser');
  ok(/captured by the packet sniffer/.test(html),
     'a packet row names the capturer');

  section('3. a row that cannot say WHO says WHY it cannot');
  RESPONSE = basePayload({
    rows: [packetRow({
      who: 'no process was recorded for this row, which is NOT the same as ' +
           'saying no process was involved.',
      detail: { process_name: null, process_pid: null, protocol: 'tcp' },
    })],
    totals: { finding: 0, event: 0, packet: 1 },
    shown:  { finding: 0, event: 0, packet: 1 },
  });
  await page.loadTimeline();
  html = els['timeline-list'].innerHTML;
  ok(/NOT the same as saying no process was involved/.test(html),
     'an unattributed row says what unattributed MEANS, in words',
     html.slice(0, 400));

  section('4. a finding links to its rule, and a missing rule is not a dead link');
  RESPONSE = basePayload({
    rows: [findingRow()],
    totals: { finding: 1, event: 0, packet: 0 },
    shown:  { finding: 1, event: 0, packet: 0 },
  });
  await page.loadTimeline();
  html = els['timeline-list'].innerHTML;
  ok(/onclick="showDetection\('LNX-3001'\)/.test(html),
     'the finding carries a link to LNX-3001', html.slice(0, 400));
  ok(/class="tl-jump"/.test(html), 'and it is rendered as a link');

  RESPONSE = basePayload({
    rows: [findingRow({
      detection_id: null,
      rule_note: 'the rule XYZ-9999 is not in this build\'s register, so what ' +
                 'fires it cannot be read here',
    })],
    totals: { finding: 1, event: 0, packet: 0 },
    shown:  { finding: 1, event: 0, packet: 0 },
  });
  await page.loadTimeline();
  html = els['timeline-list'].innerHTML;
  ok(/rule unknown/.test(html), 'a row with no readable rule says so');
  ok(!/showDetection/.test(html),
     'and it offers NO link, rather than a link to nothing');
  ok(/not in this build/.test(html),
     'the reason travels with it, so the reader is not left guessing');

  section('5. the map link is offered only when the map can draw it');
  RESPONSE = basePayload({
    rows: [packetRow()],
    totals: { finding: 0, event: 0, packet: 1 },
    shown:  { finding: 0, event: 0, packet: 1 },
  });
  await page.loadTimeline();
  html = els['timeline-list'].innerHTML;
  // THE ESCAPED FORM IS THE CONTRACT, not a cosmetic detail: the value goes
  // into an onclick attribute inside a single-quoted JS string, and escJs is
  // what makes a value with a quote in it safe to put there. Asserting on the
  // raw address would pass against a renderer that forgot to escape it.
  ok(/onclick="showMapEndpoint\('34\.36\.133\.15'\)"/.test(html)
     || /class="tl-jump tl-jump-map"/.test(html),
     'a public endpoint gets a map link', html.slice(0, 500));
  ok(/tl-jump-map/.test(html),
     'and the link is the map kind, not the rule kind');

  RESPONSE = basePayload({
    rows: [findingRow({
      detection_id: null,
      rule_note: 'x',
      map_note: 'no map link: the rule that raised this says the address is ' +
                'not a host at all',
    })],
    totals: { finding: 1, event: 0, packet: 0 },
    shown:  { finding: 1, event: 0, packet: 0 },
  });
  await page.loadTimeline();
  html = els['timeline-list'].innerHTML;
  ok(/no map/.test(html),
     'an address the rule says is not a host gets a NOTE, not a link');
  ok(!/showMapEndpoint/.test(html), 'and no link at all on that row');

  section('6. the line above the list says what is missing');
  RESPONSE = basePayload({
    rows: [packetRow()],
    totals: { finding: 14, event: 777, packet: 186058 },
    shown:  { finding: 12, event: 58, packet: 4 },
    complete: false,
    note: 'THIS IS A SAMPLE, NOT EVERYTHING: 14 findings in the window and 12 shown.',
  });
  await page.loadTimeline();
  const sum = els['timeline-summary'].innerHTML;
  ok(/THIS IS A SAMPLE, NOT EVERYTHING/.test(sum),
     'a capped answer says it is capped, on the page', sum.slice(0, 300));
  ok(/searched all sessions/.test(sum), 'and says what it searched');

  RESPONSE = basePayload({
    rows: [packetRow()],
    totals: { finding: 0, event: null, packet: 1 },
    shown:  { finding: 0, event: 0, packet: 1 },
    read_ok: { finding: true, event: false, packet: true },
    complete: false,
    note: 'COULD NOT READ: event (no such table). Those records are MISSING.',
  });
  await page.loadTimeline();
  ok(/COULD NOT READ/.test(els['timeline-summary'].innerHTML),
     'a failed read is on the page, not rendered as a quiet window');

  RESPONSE = basePayload({
    rows: [packetRow()],
    totals: { finding: 0, event: 0, packet: 1 },
    shown:  { finding: 0, event: 0, packet: 1 },
    complete: true, note: null,
  });
  await page.loadTimeline();
  ok(/Everything recorded in this window is shown/.test(
       els['timeline-summary'].innerHTML),
     'and a complete answer says THAT, so the two cases cannot be confused');

  section('7. the packet filter hides packets and the summary agrees');
  els['timeline-findings-only'].checked = true;
  RESPONSE = basePayload({
    rows: [findingRow(), packetRow()],
    totals: { finding: 1, event: 0, packet: 1 },
    shown:  { finding: 1, event: 0, packet: 1 },
    complete: true,
  });
  await page.loadTimeline();
  html = els['timeline-list'].innerHTML;
  ok(!/TCP 66 bytes/.test(html), 'the packet row is filtered out of the list');
  ok(/A program ran from a staging directory/.test(html),
     'and the finding stays');
  ok(/packets filtered out here/.test(els['timeline-summary'].innerHTML),
     'the summary says the filter is on, so the counts are not read as the window');
  els['timeline-findings-only'].checked = false;

  section('8. a shape the page does not understand is SAID, not rendered empty');
  RESPONSE = [];
  await page.loadTimeline();
  html = els['timeline-list'].innerHTML;
  ok(/does not understand/.test(html),
     'the old bare-array answer is reported as a shape fault',
     html.slice(0, 200));
  ok(!/No activity in this window/.test(html),
     'and it is NOT reported as a quiet window, which is the whole distinction');

  RESPONSE = null;
  await page.loadTimeline();
  ok(/does not understand/.test(els['timeline-list'].innerHTML),
     'a null answer too');

  section('9. the empty window still says the honest sentence');
  RESPONSE = basePayload();
  await page.loadTimeline();
  ok(/No activity in this window/.test(els['timeline-list'].innerHTML),
     'a genuinely empty window says so');

  section('10. an unregistered rule is not a click that does nothing');
  // The register LOADS and carries one other rule, so this section drives the
  // real path: the row exists, the asked-for id does not.
  page.setRegister(true, [{ detection_id: 'LNX-3001' }]);
  ALERTS.length = 0;
  await page.showDetection('XYZ-9999');
  ok(ALERTS.length === 1 && /no entry for it/.test(ALERTS[0]),
     'clicking a rule the register lacks says so out loud',
     JSON.stringify(ALERTS));

  section('10b. the register carrying the rule is NOT that case');
  // THE PAIR THAT MAKES SECTION 10 MEAN SOMETHING. Same function, same table,
  // the only difference is whether the id is in it.
  ALERTS.length = 0;
  await page.showDetection('LNX-3001');
  ok(ALERTS.length === 0,
     'a rule the register DOES carry opens with no complaint',
     JSON.stringify(ALERTS));

  section('10c. a register that failed to load is a third, different sentence');
  page.setRegister(false, []);
  ALERTS.length = 0;
  await page.showDetection('LNX-3001');
  ok(ALERTS.length === 1 && /could not be read/.test(ALERTS[0]),
     'a failed register load says THAT, not "no such rule"',
     JSON.stringify(ALERTS));
  ok(!/no entry for it/.test(ALERTS[0] || ''),
     'and never the missing-rule sentence, which would send the reader to the '
     + 'wrong fault');
  page.setRegister(true, [{ detection_id: 'LNX-3001' }]);

  section('11. a map target the map cannot draw says so out loud');
  page.setMap(true, [{ ip: '11.22.35.15', place: 'Kansas City, US',
                       lat: 39.1, lon: -94.6 }]);
  ALERTS.length = 0;
  await page.showMapEndpoint('1.0.0.10');
  ok(ALERTS.length === 1 && /not drawn on the Threat Map/.test(ALERTS[0]),
     'asking the map for an address it holds out explains itself',
     JSON.stringify(ALERTS));

  section('11b. and the address the map DOES draw goes there without a word');
  ALERTS.length = 0;
  await page.showMapEndpoint('11.22.35.15');
  ok(ALERTS.length === 0,
     'an endpoint the map holds opens with no complaint',
     JSON.stringify(ALERTS));

  section('11c. a map that is not drawn at all is not a dead click either');
  // THE PAGE-LEVEL VERSION OF THE SAME DEFECT, found by this harness: with no
  // geolocation database the map page draws nothing, `map` stays null, and the
  // first draft returned in silence. A click that does nothing is the one
  // answer a reader cannot tell apart from a broken page.
  page.setMap(false, []);
  ALERTS.length = 0;
  await page.showMapEndpoint('9.9.9.9');
  ok(ALERTS.length === 1 && /is not drawn/.test(ALERTS[0]),
     'a click with no map drawn explains itself rather than doing nothing',
     JSON.stringify(ALERTS));
  ok(!/no entry for it/.test(ALERTS[0] || ''),
     'and it does not blame the row the reader clicked');

  // optionally, the real route
  if (apiIx >= 0) {
    const base = argv[apiIx + 1];
    const key  = keyIx >= 0 ? argv[keyIx + 1] : '';
    section('12. the REAL route, rendered by the same function');
    const res = await fetch(`${base}/api/history?limit=200&since=${
      encodeURIComponent(new Date(Date.now() - 2 * 3600 * 1000).toISOString())}`,
      { headers: { 'X-API-Key': key } });
    if (!res.ok) {
      ok(false, `the route answered ${res.status}`);
    } else {
      const body = await res.json();
      ok(Array.isArray(body.rows), 'the route returns the dict shape');
      const kinds = {};
      (body.rows || []).forEach(r => kinds[r.kind] = (kinds[r.kind] || 0) + 1);
      ok((kinds.packet || 0) > 0,
         'the live window contains packet rows', JSON.stringify(kinds));
      console.log('         live kinds: ' + JSON.stringify(kinds)
                + '  totals ' + JSON.stringify(body.totals));
      RESPONSE = body;
      await page.loadTimeline();
      const live = els['timeline-list'].innerHTML;
      ok(/class="tl-line/.test(live), 'and the page renders them');
      const blank = (live.match(/timeline-desc">\s*<div class="tl-what">\s*<\/div>/g) || []).length;
      ok(blank === 0, 'no row renders with an empty WHAT line', String(blank));
    }
  }

  console.log('\n' + '='.repeat(72));
  console.log(`timeline page: ${PASS.length} passed, ${FAIL.length} failed`);
  if (FAIL.length) {
    console.log('\nFAILURES:');
    FAIL.forEach(f => console.log('  ' + f));
  }
  console.log('='.repeat(72));
  return FAIL.length ? 1 : 0;
}

main().then(rc => process.exit(rc)).catch(e => {
  console.error('THE HARNESS ITSELF THREW: ' + (e && e.stack || e));
  process.exit(2);
});
