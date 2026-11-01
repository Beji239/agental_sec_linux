const fs = require('fs');
const path = require('path');
let chromium;
try {
  ({chromium} = require(process.env.AGENTAL_PLAYWRIGHT_MODULE || 'playwright'));
} catch (e) {
  console.error('SKIP: needs Playwright, set AGENTAL_PLAYWRIGHT_MODULE when installed elsewhere');
  process.exit(77);
}
const source = fs.readFileSync(path.join(__dirname, '..', 'ui', 'index.html'), 'utf8');
function grab(name) {
  const start = source.indexOf('function ' + name + '(');
  const end = source.indexOf('\n}\n', start);
  if (start < 0 || end < 0) throw new Error('Missing renderer ' + name);
  return source.slice(start, end + 3);
}
const names = ['esc', 'escJs', 'renderPermissionCard', 'renderQueueCard', 'reportCard',
  'runRow', 'runDetailText', 'toolSummary', 'fmtTokens', 'renderUpdates',
  'renderUpdateJob', 'updHeadline', 'updAgo'];
const code = names.map(grab).join('\n') + `
const APPROVAL_WARNING = '';
const AGENT_TICKED = new Set();
const RUN_TICKED = new Set();
const RUN_VERDICT_WORDS = {real:'a real problem'};
const UPD_KIND = {patch:'a patch update'};
let _updRestart = false;
function fmtTime(value) { return String(value || ''); }
function scrollChat() {}
`;
const payloads = [
  '<img src=x onerror="window.__audit=1">',
  '<svg onload="window.__audit=1"></svg>',
  '</div><script>window.__audit=1</script>',
  '"><img src=x onerror="window.__audit=1">',
  "');window.__audit=1;//",
  '<iframe srcdoc="<script>parent.__audit=1</script>"></iframe>',
  '<math><mtext><img src=x onerror="window.__audit=1"></mtext></math>',
  '<style>body{display:none}</style>',
  '<base href="https://example.invalid/">',
  '<input autofocus onfocus="window.__audit=1">',
  'javascript:window.__audit=1',
  '${window.__audit=1}',
  '__proto__', 'constructor', 'toString'
];
(async () => {
  const browser = await chromium.launch({headless:true,
    ...(process.env.AGENTAL_BROWSER ? {executablePath:process.env.AGENTAL_BROWSER} : {})});
  try {
    const page = await browser.newPage();
    let requests = 0;
    await page.route('**/*', route => { requests++; return route.abort(); });
    await page.setContent('<div id="target"></div>' +
      ['upd-summary','upd-release','upd-title','upd-notes','upd-link','upd-run',
       'upd-helpers','upd-daily','upd-why','upd-job','upd-step','upd-log','upd-todo']
      .map(id => '<div id="'+id+'"></div>').join(''));
    const harness = await page.addScriptTag({content:code});
    await harness.evaluate(el => { el.dataset.testHarness = 'true'; });
    let checked = 0;
    for (const value of payloads) {
      for (const renderer of ['permission','queue','report','run','updates']) {
        const result = await page.evaluate(({value, renderer}) => {
          const target = document.getElementById('target');
          target.replaceChildren();
          window.__audit = 0;
          const card = {call_id:value, action:value, reason:value, warning:value,
            alternative:value, evidence:{name:value}, waiting_note:value};
          if (renderer === 'permission') renderPermissionCard(target, card, false);
          if (renderer === 'queue') renderQueueCard(target, {id:1, card});
          if (renderer === 'report') target.innerHTML = reportCard({id:1, verdict:value,
            hypothesis:value, evidence:value, saw:value, body:value, trigger:value,
            action_taken:value, dismissed_at:value, dismissed_by:value,
            coverage:{complete:false}, coverage_note:value});
          if (renderer === 'run') target.innerHTML = runRow({id:1, trigger:value,
            outcome:value, detail:value, tools:[value], tokens_spent:1}, false);
          if (renderer === 'updates') renderUpdates({current:{label:value}, available:true,
            release:{version:'2.8.2', title:value, notes:value,
              url:'https://example.invalid/release'}, check_ok:false, check_error:value,
            can_update:{ok:false,reason:value}, helpers_behind:[value], job:{}});
          const active = [...document.querySelectorAll('body :not(script[data-test-harness])')].filter(el =>
            ['SCRIPT','IFRAME','STYLE','BASE','IMG','MATH','SVG','FORM'].includes(el.tagName) ||
            (el.tagName === 'INPUT' && !el.matches('input.agent-tick[type=checkbox],input.run-tick[type=checkbox]')) ||
            [...el.attributes].some(a => /^on/i.test(a.name)));
          return {active:active.map(el => el.outerHTML), marker:window.__audit};
        }, {value,renderer});
        if (result.marker || result.active.length) throw new Error(JSON.stringify({renderer,value,result}));
        checked++;
      }
    }
    if (requests) throw new Error('Unexpected browser requests: ' + requests);
    console.log('PASS, ' + checked + ' actual Chromium renderer cases, no active injected nodes or network requests');
  } finally {
    await browser.close();
  }
})().catch(e => {console.error(e);process.exit(1);});
