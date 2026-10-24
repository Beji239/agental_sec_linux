// modules/remote/ui.js
// The Remote tab below the switch. Loaded by the page only while the module
// is on; everything it shows comes from the module's own routes.
(function () {
  const KIND = {
    started: 'Started', stopped: 'Stopped', connected: 'Connected',
    telegram_error: 'Telegram problem', person_added: 'Person added',
    code_made: 'New code', code_used: 'Code used', code_refused: 'Code refused',
    phone_refused: 'Number refused', paired: 'Paired', removed: 'Removed',
    stranger: 'Stranger ignored', alert_sent: 'Alert sent',
    alert_held: 'Alert not sent', send_failed: 'Send failed',
    test_sent: 'Test message', settings: 'Alert choices', revoked: 'Revoked',
    error: 'Error', enrol_started: 'Setup started', enrolled: 'Control set up',
    control_removed: 'Control removed', control_on: 'Control on',
    control_off: 'Control off', control_refused: 'Wrong PIN or code',
    locked: 'Locked', unlocked: 'Unlocked', panic: 'Panic word',
    resumed: 'Control back on', decision: 'Decision',
    decision_refused: 'Decision refused',
  };
  const TOKEN_ENV = 'AGENTAL_REMOTE_BOT_TOKEN';
  let timer = null;

  function when(ts) {
    if (!ts) return 'never';
    const d = new Date(ts * 1000);
    return d.toLocaleString([], { month: 'short', day: 'numeric',
                                  hour: '2-digit', minute: '2-digit' });
  }

  function ago(ts) {
    if (!ts) return 'never';
    const s = Math.max(0, Math.round(Date.now() / 1000 - ts));
    if (s < 90) return s + ' s ago';
    if (s < 5400) return Math.round(s / 60) + ' min ago';
    return when(ts);
  }

  async function render(root, h) {
    const esc = h.esc;
    if (timer) { clearInterval(timer); timer = null; }

    const st = await h.call('GET', '/state');
    const ev = await h.call('GET', '/events?limit=100');
    if (!st.ok) {
      root.innerHTML = `<div class="card"><div class="card-note" style="color:var(--amber);">
        ${esc((st.data && (st.data.detail || st.data.error)) || 'The module did not answer.')}
        </div></div>`;
      if (st.status === 503) setTimeout(() => h.visible() && render(root, h), 1500);
      return;
    }
    const s = st.data, bot = s.bot || {}, set = s.settings || {};
    const secret = (h.module.secrets || []).find(x => x.env === TOKEN_ENV) || {};
    const people = s.people || [];
    const paired = people.filter(p => p.state === 'paired').length;
    const ctl = s.control || {};

    function controlLine(p) {
      if (p.state !== 'paired') return '';
      let text;
      if (p.locked) text = '<span style="color:var(--red);">Control locked after wrong tries</span>';
      else if (p.session_until) text = `<span style="color:var(--green);">In control from the phone until ${esc(when(p.session_until))}</span>`;
      else if (p.enrolled) text = '<span style="color:var(--green);">Can take control</span> with PIN and authenticator';
      else if (p.enrolling) text = '<span style="color:var(--amber);">Control setup not finished</span>';
      else text = '<span style="color:var(--text-dim);">Alerts only; no control set up</span>';
      return `<div style="font-size:12px;margin-top:3px;">${text}</div>`;
    }

    function controlButtons(p) {
      if (p.state !== 'paired') return '';
      let out = `<button class="btn" data-remote-setup="${p.id}">${p.enrolled ? 'Set up control again' : 'Set up control'}</button>`;
      if (p.locked) out += `<button class="btn" data-remote-unlock="${p.id}">Unlock</button>`;
      if (p.enrolled || p.enrolling) out += `<button class="btn" data-remote-uncontrol="${p.id}">Remove control</button>`;
      return out;
    }

    let botLine;
    if (!secret.present) {
      botLine = `<span style="color:var(--amber);">No bot token yet. Add one below.</span>`;
    } else if (bot.connected) {
      botLine = `<span style="color:var(--green);">Connected to Telegram</span> as
        <b>@${esc(bot.username || '')}</b>, last answer ${esc(ago(bot.last_ok_at))}.`;
    } else {
      botLine = `<span style="color:var(--red);">Not connected.</span>
        ${esc(bot.last_error || 'Trying to reach Telegram.')}`;
    }
    const feedLine = bot.feed_error
      ? `<div class="card-note" style="color:var(--red);">${esc(bot.feed_error)}</div>` : '';
    const al = s.alerts || {};

    const peopleRows = people.length ? people.map(p => `
      <div class="row" style="justify-content:space-between;align-items:center;padding:8px 0;border-bottom:1px solid var(--border);">
        <div>
          <b>${esc(p.name)}</b>
          <span style="color:var(--text-dim);font-family:var(--mono);font-size:11px;margin-left:8px;">${esc(p.phone)}</span>
          <div style="font-size:12px;margin-top:3px;">${p.state === 'paired'
            ? `<span style="color:var(--green);">Paired</span>${p.tg_username ? ' as @' + esc(p.tg_username) : ''}, since ${esc(when(p.paired_at))}`
            : (p.code_live
                ? '<span style="color:var(--amber);">Waiting for the code</span>'
                : '<span style="color:var(--text-dim);">Not paired; the code ran out or was spent</span>')}</div>
          ${controlLine(p)}
        </div>
        <div class="row" style="gap:6px;flex-wrap:wrap;justify-content:flex-end;">
          ${controlButtons(p)}
          <button class="btn" data-remote-code="${p.id}">${p.state === 'paired' ? 'Pair again' : 'New code'}</button>
          <button class="btn" data-remote-remove="${p.id}">Remove</button>
        </div>
      </div>`).join('')
      : `<div class="card-note">Nobody yet. Add yourself first, then anyone else who should get the alerts.</div>`;

    const events = (ev.ok && ev.data.events) || [];
    const eventRows = events.length ? events.map(e => `
      <div style="display:flex;gap:10px;padding:5px 0;border-bottom:1px solid var(--border);font-size:12px;">
        <span style="font-family:var(--mono);color:var(--text-dim);white-space:nowrap;min-width:110px;">${esc(when(e.at))}</span>
        <span style="min-width:120px;color:${/refused|stranger|failed|error|problem|held|revoked|locked|panic/.test(e.kind) ? 'var(--amber)' : 'var(--text)'};">${esc(KIND[e.kind] || e.kind)}</span>
        <span>${e.person ? '<b>' + esc(e.person) + '</b> ' : ''}${esc(e.detail || '')}</span>
      </div>`).join('')
      : `<div class="card-note">Nothing has happened yet.</div>`;

    const panicCard = ctl.panic ? `
      <div class="card" style="border-color:var(--red);">
        <div class="card-title" style="color:var(--red);">Control from the phone is off</div>
        <div class="card-note">
          ${esc(ctl.panic_by || 'Someone')} sent the panic word ${esc(when(ctl.panic_at))}. Nobody can decide from a
          phone until it is turned back on here. Alerts still go out. If a phone may be in the wrong hands,
          revoke it below first.
        </div>
        <button class="btn" id="remote-resume" style="margin-top:10px;">Turn control back on</button>
      </div>` : '';

    root.innerHTML = `${panicCard}
      <div class="card">
        <div class="card-title">Telegram</div>
        <div style="font-size:13px;">${botLine}</div>
        ${feedLine}
        <div class="card-note" style="margin-top:8px;">
          ${paired} of ${people.length} person(s) paired. Alerts sent today: ${esc(String(al.sent_today || 0))},
          last ${esc(ago(al.last_sent_at))}${al.waiting ? `, ${al.waiting} waiting to be grouped` : ''}${al.quiet_now ? ', quiet hours now' : ''}.
        </div>
      </div>

      <div class="card">
        <div class="card-title">Bot token</div>
        <div class="card-note">
          You make the bot yourself, so it belongs to you: in Telegram, open <b>@BotFather</b>,
          send <code>/newbot</code>, pick a name and a username ending in <code>bot</code>,
          and paste the token it gives you here. It is kept in <code>.env</code>, encrypted like the other keys.
        </div>
        <div class="row" style="margin-top:10px;gap:8px;align-items:center;">
          <input class="input" id="remote-token" type="password" autocomplete="off" style="width:360px;"
                 placeholder="${secret.present ? 'saved, ends in ' + esc(secret.last4 || '????') : '123456789:AA...'}">
          <button class="btn" id="remote-token-save">Save</button>
          ${secret.present ? '<button class="btn" id="remote-token-clear">Clear</button>' : ''}
          <span id="remote-token-msg" style="font-family:var(--mono);font-size:11px;color:var(--text-dim);"></span>
        </div>
      </div>

      <div class="card">
        <div class="card-title">People</div>
        <div class="card-note">
          Only people paired here can use the bot. You enter their name and number; they send the
          code to the bot and share their phone number with Telegram's button. The bot checks it is
          the same number and that it is their own. Anyone else who writes to the bot is ignored and
          shows up in the history below.
        </div>
        <div style="margin-top:8px;">${peopleRows}</div>
        <div class="row" style="margin-top:12px;gap:8px;align-items:center;">
          <input class="input" id="remote-name" placeholder="name" maxlength="40" style="width:160px;">
          <input class="input" id="remote-phone" placeholder="phone number" maxlength="24" style="width:180px;">
          <button class="btn" id="remote-add">Add person</button>
        </div>
        <div id="remote-code"></div>
        <div id="remote-setup"></div>
      </div>

      <div class="card">
        <div class="card-title">Control from the phone</div>
        <div class="card-note">
          A paired person can decide from the phone once they set up control here, at this computer: their own
          PIN, an authenticator app (Aegis, Google Authenticator and the like) and a panic word. Telegram never
          carries the authenticator key, so even Telegram cannot fake an approval.
        </div>
        <div class="card-note" style="margin-top:6px;">
          On the phone they press <b>Take control</b> (or send /control), then the PIN and the code from the app.
          For 30 minutes they can approve or deny actions, answer the agent's questions, give verdicts on
          incidents and let held devices in, one tap each. Each code works once. Three wrong PINs or codes
          lock that person's control until you unlock it here, and everyone else enrolled is told. Anything
          that cannot be undone asks for the PIN and a fresh code again. Their panic word, sent to the bot,
          turns control off for everyone until it is turned back on here.
        </div>
        ${ctl.available === false ? `<div class="card-note" style="color:var(--red);margin-top:6px;">
          Control cannot be set up on this computer: the cryptography package that encrypts the keys is missing.</div>` : ''}
      </div>

      <div class="card">
        <div class="card-title">Alerts</div>
        <div class="card-note">
          The same incidents that ring the desktop: new ones at or above the level below, and ones
          raised to it. Several within ${esc(set.gap_minutes || '10')} minutes go out as one message,
          and at most ${esc(set.daily_cap || '20')} messages a day.
        </div>
        <div class="row" style="margin-top:10px;gap:10px;align-items:center;flex-wrap:wrap;">
          <label style="font-size:12px;">Send
            <select class="input" id="remote-floor" style="width:190px;margin-left:6px;">
              <option value="critical" ${set.floor === 'critical' ? 'selected' : ''}>critical only</option>
              <option value="high" ${set.floor === 'high' ? 'selected' : ''}>high and critical</option>
              <option value="medium" ${set.floor === 'medium' ? 'selected' : ''}>medium and up</option>
            </select>
          </label>
          <label style="font-size:12px;"><input type="checkbox" id="remote-quiet" ${set.quiet_on === '1' ? 'checked' : ''}>
            Quiet hours from</label>
          <input class="input" id="remote-qs" value="${esc(set.quiet_start || '23:00')}" style="width:70px;">
          <span style="font-size:12px;">to</span>
          <input class="input" id="remote-qe" value="${esc(set.quiet_end || '07:00')}" style="width:70px;">
          <span style="font-size:12px;color:var(--text-dim);">critical still comes through</span>
        </div>
        <div class="row" style="margin-top:10px;gap:8px;align-items:center;">
          <button class="btn" id="remote-save">Save</button>
          <button class="btn" id="remote-test" ${paired ? '' : 'disabled'}>Send a test message</button>
          <span id="remote-alert-msg" style="font-family:var(--mono);font-size:11px;color:var(--text-dim);"></span>
        </div>
      </div>

      <div class="card">
        <div class="row" style="justify-content:space-between;align-items:center;">
          <span class="card-title" style="margin:0;">History</span>
          <button class="btn" id="remote-refresh">refresh</button>
        </div>
        <div class="card-note">Everything the bot did or refused, newest first, with every decision made from a phone and who made it.</div>
        <div style="margin-top:8px;max-height:420px;overflow-y:auto;">${eventRows}</div>
      </div>

      <div class="card" style="border-color:var(--red);margin-top:28px;">
        <div class="card-title">Revoke remote</div>
        <div class="card-note">
          Removes everyone at once and tells them. Use it if a phone is lost or you are not sure who
          has access. The bot token stays; switch the module off as well if you want the bot silent.
        </div>
        <button class="btn" id="remote-revoke" style="margin-top:10px;color:var(--red);border-color:var(--red);" ${people.length ? '' : 'disabled'}>Revoke remote</button>
      </div>`;

    const $ = id => root.querySelector('#' + id);
    const say = (id, text, bad) => {
      const el = $(id);
      if (el) { el.textContent = text; el.style.color = bad ? 'var(--red)' : 'var(--text-dim)'; }
    };
    const reason = r => (r.data && (r.data.reason || r.data.detail || r.data.error)) || 'Did not work.';

    function showCode(d, name) {
      const link = d.username ? `https://t.me/${d.username}?start=${d.code}` : '';
      $('remote-setup').innerHTML = '';
      $('remote-code').innerHTML = `
        <div class="card" style="margin:12px 0 0;border-color:var(--green);">
          <div style="font-size:13px;">Pairing code for <b>${esc(name)}</b>, valid 15 minutes, works once:</div>
          <div style="font-family:var(--mono);font-size:26px;letter-spacing:4px;margin:8px 0;">${esc(d.code)}</div>
          <div class="card-note">
            ${d.username
              ? `They open <b>@${esc(d.username)}</b> in Telegram and send this code, or open
                 <code>${esc(link)}</code> on their phone. Then they press <b>Share my phone number</b>.`
              : 'The bot is not connected yet, so add the token first; the code still works once it is.'}
          </div>
        </div>`;
    }

    $('remote-token-save').addEventListener('click', async () => {
      const value = $('remote-token').value.trim();
      if (!value) return say('remote-token-msg', 'Paste the token first.', true);
      const r = await h.setSecret(TOKEN_ENV, value);
      if (!r.ok) return say('remote-token-msg', reason(r), true);
      $('remote-token').value = '';
      say('remote-token-msg', 'Saved. Connecting...');
      setTimeout(() => h.reload(), 2500);
    });
    if ($('remote-token-clear')) $('remote-token-clear').addEventListener('click', async () => {
      if (!confirm('Clear the bot token? The bot stops until a new one is saved.')) return;
      const r = await h.setSecret(TOKEN_ENV, '');
      if (!r.ok) return say('remote-token-msg', reason(r), true);
      h.reload();
    });

    $('remote-add').addEventListener('click', async () => {
      const name = $('remote-name').value.trim(), phone = $('remote-phone').value.trim();
      const r = await h.call('POST', '/people/add', { name, phone });
      if (!r.ok) {
        $('remote-code').innerHTML = `<div class="card-note" style="color:var(--red);margin-top:8px;">${esc(reason(r))}</div>`;
        return;
      }
      await render(root, h);
      showCode(r.data, name);
    });

    root.querySelectorAll('[data-remote-code]').forEach(b => b.addEventListener('click', async () => {
      const p = people.find(x => String(x.id) === b.dataset.remoteCode);
      if (p && p.state === 'paired' &&
          !confirm(`Pair ${p.name} again? Alerts to them stop until they use the new code.`)) return;
      const r = await h.call('POST', '/people/new-code', { id: Number(b.dataset.remoteCode) });
      if (!r.ok) return alert(reason(r));
      await render(root, h);
      showCode(r.data, p ? p.name : '');
    }));

    root.querySelectorAll('[data-remote-remove]').forEach(b => b.addEventListener('click', async () => {
      const p = people.find(x => String(x.id) === b.dataset.remoteRemove);
      if (!confirm(`Remove ${p ? p.name : 'this person'}? They are told, and get no more alerts.`)) return;
      const r = await h.call('POST', '/people/remove', { id: Number(b.dataset.remoteRemove) });
      if (!r.ok) return alert(reason(r));
      render(root, h);
    }));

    $('remote-save').addEventListener('click', async () => {
      const r = await h.call('POST', '/settings', {
        floor: $('remote-floor').value, quiet_on: $('remote-quiet').checked,
        quiet_start: $('remote-qs').value.trim(), quiet_end: $('remote-qe').value.trim(),
      });
      if (!r.ok) return say('remote-alert-msg', reason(r), true);
      say('remote-alert-msg', 'Saved.');
    });

    $('remote-test').addEventListener('click', async () => {
      say('remote-alert-msg', 'Sending...');
      const r = await h.call('POST', '/test', {});
      if (!r.ok) return say('remote-alert-msg', reason(r), true);
      say('remote-alert-msg', `Reached ${r.data.reached} of ${r.data.of}.`);
    });

    $('remote-refresh').addEventListener('click', () => render(root, h));

    $('remote-revoke').addEventListener('click', async () => {
      if (!confirm('Revoke remote access for everyone? Each person is told, and has to be paired again.')) return;
      const r = await h.call('POST', '/revoke', {});
      if (!r.ok) return alert(reason(r));
      render(root, h);
    });

    function showSetup(p) {
      $('remote-code').innerHTML = '';
      $('remote-setup').innerHTML = `
        <div class="card" style="margin:12px 0 0;border-color:var(--green);">
          <div style="font-size:13px;">Control for <b>${esc(p.name)}</b>. Let them type these themselves.</div>
          <div class="row" style="margin-top:10px;gap:8px;align-items:center;flex-wrap:wrap;">
            <input class="input" id="remote-pin" type="password" inputmode="numeric" autocomplete="off" placeholder="PIN, 6 to 12 digits" maxlength="12" style="width:170px;">
            <input class="input" id="remote-pin2" type="password" inputmode="numeric" autocomplete="off" placeholder="PIN again" maxlength="12" style="width:130px;">
            <input class="input" id="remote-word" type="password" autocomplete="off" placeholder="panic word" maxlength="40" style="width:160px;">
            <button class="btn" id="remote-setup-next">Next</button>
            <button class="btn" id="remote-setup-cancel">Cancel</button>
          </div>
          <div class="card-note">The panic word needs letters, and should be something they would not type by accident.
            Sent to the bot from their phone, it turns control off for everyone.</div>
          <div id="remote-setup-msg" style="font-family:var(--mono);font-size:11px;margin-top:6px;"></div>
        </div>`;
      $('remote-setup-cancel').addEventListener('click', () => { $('remote-setup').innerHTML = ''; render(root, h); });
      $('remote-setup-next').addEventListener('click', async () => {
        const r = await h.call('POST', '/control/enrol', {
          id: p.id, pin: $('remote-pin').value.trim(), pin2: $('remote-pin2').value.trim(),
          word: $('remote-word').value });
        if (!r.ok) return say('remote-setup-msg', reason(r), true);
        $('remote-setup').innerHTML = `
          <div class="card" style="margin:12px 0 0;border-color:var(--green);">
            <div style="font-size:13px;">Now <b>${esc(p.name)}</b> adds AgentalSec to their authenticator app: scan this code,
              or type the key by hand. It is shown only now.</div>
            <div class="row" style="margin-top:10px;gap:16px;align-items:center;flex-wrap:wrap;">
              <div id="remote-qr" style="background:#fff;padding:6px;border-radius:4px;line-height:0;"></div>
              <div>
                <div class="card-note">Key</div>
                <div style="font-family:var(--mono);font-size:15px;letter-spacing:1px;margin:4px 0 12px;">${esc(r.data.key)}</div>
                <div class="card-note">Then type the 6-digit code the app shows:</div>
                <div class="row" style="gap:8px;margin-top:6px;">
                  <input class="input" id="remote-otp" inputmode="numeric" autocomplete="off" maxlength="6" style="width:110px;">
                  <button class="btn" id="remote-otp-ok">Finish</button>
                  <button class="btn" id="remote-setup-cancel2">Cancel</button>
                </div>
                <div id="remote-setup-msg" style="font-family:var(--mono);font-size:11px;margin-top:6px;"></div>
              </div>
            </div>
          </div>`;
        // The picture comes from the module and holds nothing but squares.
        const img = new Image();
        img.alt = 'QR code for the authenticator app';
        img.src = 'data:image/svg+xml;base64,' + btoa(r.data.svg);
        $('remote-qr').appendChild(img);
        $('remote-setup-cancel2').addEventListener('click', () => { $('remote-setup').innerHTML = ''; render(root, h); });
        $('remote-otp-ok').addEventListener('click', async () => {
          const c = await h.call('POST', '/control/confirm', { id: p.id, code: $('remote-otp').value.trim() });
          if (!c.ok) return say('remote-setup-msg', reason(c), true);
          $('remote-setup').innerHTML = '';
          render(root, h);
        });
      });
    }

    root.querySelectorAll('[data-remote-setup]').forEach(b => b.addEventListener('click', () => {
      const p = people.find(x => String(x.id) === b.dataset.remoteSetup);
      if (!p) return;
      if (p.enrolled && !confirm(`Set up control for ${p.name} again? The old PIN, panic word and authenticator stop working.`)) return;
      showSetup(p);
    }));

    root.querySelectorAll('[data-remote-unlock]').forEach(b => b.addEventListener('click', async () => {
      const r = await h.call('POST', '/control/unlock', { id: Number(b.dataset.remoteUnlock) });
      if (!r.ok) return alert(reason(r));
      render(root, h);
    }));

    root.querySelectorAll('[data-remote-uncontrol]').forEach(b => b.addEventListener('click', async () => {
      const p = people.find(x => String(x.id) === b.dataset.remoteUncontrol);
      if (!confirm(`Remove control for ${p ? p.name : 'this person'}? They keep getting alerts.`)) return;
      const r = await h.call('POST', '/control/remove', { id: Number(b.dataset.remoteUncontrol) });
      if (!r.ok) return alert(reason(r));
      render(root, h);
    }));

    if ($('remote-resume')) $('remote-resume').addEventListener('click', async () => {
      if (!confirm('Turn control from the phone back on? Enrolled people can decide again after PIN and code.')) return;
      const r = await h.call('POST', '/control/resume', {});
      if (!r.ok) return alert(reason(r));
      render(root, h);
    });

    // Refreshes the status card while the tab is open; typing is never lost.
    timer = setInterval(() => {
      if (!h.visible()) { clearInterval(timer); timer = null; return; }
      const busy = root.contains(document.activeElement) &&
                   /INPUT|SELECT/.test(document.activeElement.tagName);
      if (!busy && !$('remote-code').innerHTML && !$('remote-setup').innerHTML) render(root, h);
    }, 20000);
  }

  window.AgentalModuleUI = window.AgentalModuleUI || {};
  window.AgentalModuleUI.remote = {
    render,
    stop() { if (timer) { clearInterval(timer); timer = null; } },
  };
})();
