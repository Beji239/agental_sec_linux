// modules/remote/reader/reader.js
// Opens a private message from AgentalSec on the phone. It talks to Telegram
// through its own small bridge, loads nothing from anywhere and sends
// nothing out; the key stays in the phone's secure storage.
(function () {
  'use strict';
  const KEY_NAME = 'agentalsec_reader_key';
  const QR_PREFIX = 'agentalsec-key:1:';
  const AAD = new TextEncoder().encode('agentalsec-reader-1');
  const CHECK_LABEL = new TextEncoder().encode('agentalsec-reader-check');
  const FLAG_DEFLATE = 1;
  const $ = id => document.getElementById(id);

  const hash = new URLSearchParams(location.hash.slice(1));
  const query = new URLSearchParams(location.search);

  // Telegram's bridge, without its script

  function post(name, params) {
    const data = JSON.stringify(params || {});
    try {
      if (window.TelegramWebviewProxy) return window.TelegramWebviewProxy.postEvent(name, data);
      if (window.external && 'notify' in window.external) {
        return window.external.notify(JSON.stringify({ eventType: name, eventData: params || {} }));
      }
      window.parent.postMessage(JSON.stringify({ eventType: name, eventData: params || {} }),
                                'https://web.telegram.org');
    } catch (e) { /* outside Telegram nothing answers */ }
  }

  const waiting = {};
  let onQr = null;

  function receive(type, data) {
    data = data || {};
    if (type === 'qr_text_received') { if (onQr) onQr(String(data.data || '')); return; }
    if (type === 'theme_changed') { theme(data.theme_params); return; }
    if (String(type).indexOf('secure_storage_') === 0 && waiting[data.req_id]) {
      const done = waiting[data.req_id];
      delete waiting[data.req_id];
      done(type, data);
    }
  }
  window.Telegram = window.Telegram || {};
  window.Telegram.WebView = Object.assign(window.Telegram.WebView || {}, { receiveEvent: receive });
  window.TelegramGameProxy = { receiveEvent: receive };
  window.TelegramGameProxy_receiveEvent = receive;
  window.addEventListener('message', ev => {
    if (ev.origin !== 'https://web.telegram.org' || typeof ev.data !== 'string') return;
    try { const m = JSON.parse(ev.data); receive(m.eventType, m.eventData); } catch (e) { /* not ours */ }
  });

  function secure(method, params) {
    return new Promise((resolve, reject) => {
      const id = 'r' + Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
      const timer = setTimeout(() => {
        delete waiting[id];
        reject(new Error('Telegram did not answer. This Telegram app may have no secure storage.'));
      }, 8000);
      waiting[id] = (type, data) => {
        clearTimeout(timer);
        if (type === 'secure_storage_failed') reject(new Error(data.error || 'secure storage refused'));
        else resolve(data);
      };
      post(method, Object.assign({ req_id: id }, params));
    });
  }

  function atLeast(want) {
    const have = (hash.get('tgWebAppVersion') || '0').split('.').map(Number);
    const need = want.split('.').map(Number);
    for (let i = 0; i < need.length; i++) {
      if ((have[i] || 0) !== need[i]) return (have[i] || 0) > need[i];
    }
    return true;
  }

  function theme(params) {
    const map = { bg_color: '--bg', text_color: '--text', hint_color: '--hint',
                  button_color: '--button', button_text_color: '--button-text',
                  secondary_bg_color: '--card' };
    Object.keys(map).forEach(k => {
      const v = params && params[k];
      if (typeof v === 'string' && /^#[0-9a-fA-F]{6}$/.test(v)) {
        document.documentElement.style.setProperty(map[k], v);
      }
    });
  }

  // Sealed messages

  function unb64(text) {
    const s = text.replace(/-/g, '+').replace(/_/g, '/');
    const bin = atob(s + '='.repeat((4 - s.length % 4) % 4));
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function b64(bytes) {
    let bin = '';
    bytes.forEach(b => { bin += String.fromCharCode(b); });
    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  async function keyId(raw) {
    return new Uint8Array(await crypto.subtle.digest('SHA-256', raw)).slice(0, 4);
  }

  async function checkCode(raw) {
    const k = await crypto.subtle.importKey('raw', raw, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const mac = new Uint8Array(await crypto.subtle.sign('HMAC', k, CHECK_LABEL));
    const abc = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    let bits = 0, value = 0, out = '';
    for (let i = 0; i < mac.length && out.length < 6; i++) {
      value = (value << 8) | mac[i];
      bits += 8;
      while (bits >= 5 && out.length < 6) {
        out += abc[(value >>> (bits - 5)) & 31];
        bits -= 5;
      }
    }
    return out;
  }

  async function inflate(bytes) {
    if (typeof DecompressionStream === 'undefined') {
      throw new Error('This phone\'s web view is too old to unpack the message. Update the phone.');
    }
    const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream('deflate-raw'));
    return new Uint8Array(await new Response(stream).arrayBuffer());
  }

  async function openSealed(raw, blob) {
    const data = unb64(blob);
    const head = data.slice(0, 6), nonce = data.slice(6, 18), sealed = data.slice(18);
    if (head[0] !== 1) throw new Error('This message comes from a newer AgentalSec. Update the reader.');
    const want = await keyId(raw);
    if (want.some((b, i) => b !== head[2 + i])) {
      throw new Error('This message was sealed for a different key. Set up private messages again.');
    }
    const aad = new Uint8Array(AAD.length + head.length);
    aad.set(AAD);
    aad.set(head, AAD.length);
    const key = await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['decrypt']);
    let plain;
    try {
      plain = new Uint8Array(await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: nonce, additionalData: aad }, key, sealed));
    } catch (e) {
      throw new Error('This message could not be opened. It was changed on the way, or the key is not the right one.');
    }
    if (head[1] & FLAG_DEFLATE) plain = await inflate(plain);
    return JSON.parse(new TextDecoder().decode(plain));
  }

  // The page

  function note(text, bad) {
    $('note').textContent = text;
    $('note').className = bad ? 'note bad' : 'note';
  }

  function when(at) {
    const d = new Date(at * 1000);
    return 'Sealed ' + d.toLocaleString([], { month: 'short', day: 'numeric',
                                              hour: '2-digit', minute: '2-digit' });
  }

  async function storedKey() {
    const got = await secure('web_app_secure_storage_get_key', { key: KEY_NAME });
    if (!got.value) return null;
    const raw = unb64(got.value);
    return raw.length === 32 ? raw : null;
  }

  function showEnrol() {
    $('enrol').hidden = false;
    $('scan').onclick = () => {
      onQr = async text => {
        if (text.indexOf(QR_PREFIX) !== 0) return;
        let raw;
        try { raw = unb64(text.slice(QR_PREFIX.length)); } catch (e) { return; }
        if (raw.length !== 32) return;
        onQr = null;
        post('web_app_close_scan_qr_popup');
        try {
          await secure('web_app_secure_storage_save_key', { key: KEY_NAME, value: b64(raw) });
        } catch (e) {
          note('The key could not be saved: ' + e.message, true);
          return;
        }
        $('check').hidden = false;
        $('check').textContent = await checkCode(raw);
        note('Saved in this phone\'s secure storage. Type the code below into the Remote tab at the computer to finish.');
        $('keytools').hidden = false;
      };
      post('web_app_open_scan_qr_popup', { text: 'The code in the Remote tab' });
    };
  }

  async function start() {
    theme((() => { try { return JSON.parse(hash.get('tgWebAppThemeParams') || '{}'); } catch (e) { return {}; } })());
    post('web_app_ready');
    post('web_app_expand');
    if (!hash.get('tgWebAppVersion')) {
      note('Open this page from the Read button in your AgentalSec bot, inside the Telegram app on your phone.');
      return;
    }
    if (typeof crypto === 'undefined' || !crypto.subtle) {
      note('This phone cannot open private messages: its web view has no encryption support.', true);
      return;
    }
    if (!atLeast('9.0')) {
      note('This Telegram app is too old for private messages. Update Telegram and open the message again.', true);
      return;
    }
    let raw = null;
    try {
      raw = await storedKey();
    } catch (e) {
      note(e.message, true);
      return;
    }
    $('forget').onclick = async () => {
      try {
        await secure('web_app_secure_storage_save_key', { key: KEY_NAME, value: null });
        note('The key is removed from this phone. Private messages cannot be opened here any more.');
        $('message').hidden = true;
        $('keytools').hidden = true;
      } catch (e) { note('The key could not be removed: ' + e.message, true); }
    };
    if (raw) $('keytools').hidden = false;

    const blob = query.get('m');
    if (query.has('enrol') || !blob) {
      note(raw ? 'This phone already has a key. Scan a new one only if the Remote tab asks for it.'
               : 'No key on this phone yet.');
      showEnrol();
      return;
    }
    if (!raw) {
      note('No key on this phone yet, so this message cannot be opened.', true);
      showEnrol();
      return;
    }
    try {
      const msg = await openSealed(raw, blob);
      $('msg-title').textContent = String(msg.t || 'Message');
      $('msg-when').textContent = when(Number(msg.at) || 0);
      $('msg-body').textContent = String(msg.b || '');
      $('message').hidden = false;
      note('Opened on this phone. Telegram only carried scrambled text.');
    } catch (e) {
      note(e.message, true);
    }
  }

  start();
})();
