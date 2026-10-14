/*
 * detector.js — isolated-world content script.
 *
 *   - Always: relays ClickFix events from hooks.js to the background and shows
 *     a warning banner (cheap: one event listener).
 *   - URL-less documents only (blob:, data:, framed about:/srcdoc): probes for
 *     traps, scores content, asks the background for navigation context,
 *     decides SCAM / WARN / CLEAN and responds.
 *
 * Also injected late by background.js (scripting.executeScript) into tabs that
 * were already open when the extension was installed or enabled; in that case
 * hooks.js never ran, so probing + content do the work.
 */
(function () {
  'use strict';
  if (window.__lsgDetector) return;
  window.__lsgDetector = true;

  const S = globalThis.LSG;
  if (!S) return;

  function send(msg) {
    try { return chrome.runtime.sendMessage(msg).catch(() => undefined); } catch (_) { return Promise.resolve(); }
  }

  // ---------------------------------------------------------------------------
  // Hook channel (MAIN world -> here)
  // ---------------------------------------------------------------------------
  let lastHookState = null;
  document.addEventListener('__lsg_hook', (e) => {
    let msg;
    try { msg = JSON.parse(e.detail); } catch (_) { return; }
    if (!msg || typeof msg !== 'object') return;
    if (msg.kind === 'state') lastHookState = msg.detail;
    else if (msg.kind === 'trap' && gated) scheduleEvaluate(50);
  });

  // ClickFix: hooks.js asks synchronously whether a clipboard write must be blocked.
  document.addEventListener('__lsg_clip', (e) => {
    let msg;
    try { msg = JSON.parse(e.detail); } catch (_) { return; }
    if (!msg || typeof msg.payload !== 'string') return;
    const pageText = (document.title || '') + ' ' + (document.body ? document.body.innerText : '');
    const r = S.scoreClickFix(msg.payload, pageText);
    if (!r.clickfix) return;
    document.dispatchEvent(new CustomEvent('__lsg_clip_reply', { detail: JSON.stringify({ block: true }) }));
    onClickFix({ via: msg.via, hits: r.hits });
  });

  function hookCmd(type) {
    document.dispatchEvent(new CustomEvent('__lsg_cmd', { detail: JSON.stringify({ type }) }));
  }

  function hookState() {
    lastHookState = null;
    hookCmd('report');            // hooks.js answers synchronously, if present
    return lastHookState;
  }

  // ---------------------------------------------------------------------------
  // Banner (closed shadow root; secondary to the extension's own blocked page)
  // ---------------------------------------------------------------------------
  let bannerShown = false;
  function showBanner(title, body, withLeave) {
    if (bannerShown || window !== window.top) return;
    bannerShown = true;
    const host = document.createElement('div');
    host.style.cssText = 'all:initial;position:fixed;z-index:2147483647;top:0;left:0;right:0;';
    const root = host.attachShadow({ mode: 'closed' });
    const wrap = document.createElement('div');
    wrap.style.cssText = 'font:14px/1.4 system-ui,sans-serif;background:#111827;color:#f9fafb;padding:12px 16px;display:flex;gap:12px;align-items:center;box-shadow:0 2px 8px rgba(0,0,0,.4)';
    const text = document.createElement('div');
    const strong = document.createElement('strong');
    strong.textContent = title + ' ';
    text.append(strong, document.createTextNode(body));
    text.style.flex = '1';
    wrap.append(text);
    if (withLeave) {
      const leave = document.createElement('button');
      leave.textContent = 'Leave page';
      leave.style.cssText = 'background:#f9fafb;color:#111827;border:0;border-radius:6px;padding:6px 12px;cursor:pointer';
      leave.addEventListener('click', () => send({ type: 'LEAVE_PAGE' }));
      wrap.append(leave);
    }
    const close = document.createElement('button');
    close.textContent = 'Dismiss';
    close.style.cssText = 'background:transparent;color:#f9fafb;border:1px solid #6b7280;border-radius:6px;padding:6px 12px;cursor:pointer';
    close.addEventListener('click', () => host.remove());
    wrap.append(close);
    root.append(wrap);
    (document.body || document.documentElement).append(host);
  }

  function onClickFix(detail) {
    send({ type: 'VERDICT', verdict: 'CLICKFIX', signals: { clickfix: detail.hits, via: detail.via }, url: location.href });
    showBanner('Blocked a dangerous clipboard command.',
      'This page tried to copy a command and get you to paste it into Run, PowerShell or a terminal. Your clipboard now holds a warning instead. Do not run commands from websites.',
      false);
  }

  // ---------------------------------------------------------------------------
  // Gate: only URL-less HTML documents get lock-screen analysis
  // ---------------------------------------------------------------------------
  const proto = location.protocol;
  const isTop = window === window.top;
  const gated = (proto === 'blob:' || proto === 'data:' || (proto === 'about:' && !isTop)) &&
    /html/i.test(document.contentType || 'text/html');
  if (!gated) return;

  // A subframe only matters if it covers most of the window (nested-frame trick).
  function frameCoversViewport() {
    if (isTop) return true;
    try {
      const area = innerWidth * innerHeight;
      const outer = (outerWidth || screen.availWidth) * (outerHeight || screen.availHeight);
      return outer > 0 && area / outer >= 0.6;
    } catch (_) { return false; }
  }

  // ---------------------------------------------------------------------------
  // Family B — active probing (works even if hooks.js never ran)
  // ---------------------------------------------------------------------------
  function probe(ev) {
    const target = document.body || document.documentElement;
    try { target.dispatchEvent(ev); } catch (_) { return false; }
    return ev.defaultPrevented;
  }

  function probeTraps() {
    const key = (key, mods) => new KeyboardEvent('keydown', Object.assign({ key, bubbles: true, cancelable: true, composed: true }, mods || {}));
    const escapeKeys = [
      key('F5'), key('F11'), key('F12'), key('Escape'),
      key('w', { ctrlKey: true }), key('r', { ctrlKey: true }), key('l', { ctrlKey: true }),
      key('w', { metaKey: true }), key('q', { metaKey: true }),
    ].filter(probe).length;
    const contextmenu = probe(new MouseEvent('contextmenu', { bubbles: true, cancelable: true, button: 2 }));
    let beforeunload = false;
    try {
      const bu = new Event('beforeunload', { cancelable: true });
      window.dispatchEvent(bu);
      beforeunload = bu.defaultPrevented || (typeof bu.returnValue === 'string' && bu.returnValue !== '') || bu.returnValue === false;
    } catch (_) { /* ignore */ }
    return { escapeKeys: escapeKeys >= 2, contextmenu, beforeunload };
  }

  let probed = null;
  function collectTraps() {
    if (!probed) probed = probeTraps();   // probe once per document
    const h = hookState() || {};
    return {
      escapeKeys: probed.escapeKeys,
      contextmenu: probed.contextmenu,
      beforeunload: probed.beforeunload || !!h.beforeunloadProp || (h.listeners && h.listeners.beforeunload > 0),
      lockApis: !!(h.lockApis && h.lockApis.length),
      historyFlood: !!h.historyFlood,
      dialogLoop: !!h.dialogLoop,
    };
  }

  // ---------------------------------------------------------------------------
  // Family C — content
  // ---------------------------------------------------------------------------
  function collectText() {
    const parts = [document.title || ''];
    // innerText = rendered text only. Never fall back to textContent: it would
    // include <script> source and score strings the user never sees.
    if (document.body) parts.push(typeof document.body.innerText === 'string' ? document.body.innerText : '');
    try {
      // open shadow roots are invisible to innerText
      const els = document.body ? document.body.querySelectorAll('*') : [];
      for (let i = 0; i < els.length && i < 2000; i++) {
        if (els[i].shadowRoot) parts.push(els[i].shadowRoot.textContent || '');
      }
    } catch (_) { /* ignore */ }
    return parts.join(' ').slice(0, 30000);
  }

  function parseRgb(c) {
    const m = /rgba?\((\d+),\s*(\d+),\s*(\d+)(?:,\s*([\d.]+))?/.exec(c || '');
    if (!m) return null;
    if (m[4] !== undefined && parseFloat(m[4]) === 0) return null;
    return { r: +m[1], g: +m[2], b: +m[3] };
  }
  function collectVisual() {
    const els = [document.body, document.documentElement];
    for (const el of els) {
      if (!el) continue;
      const c = parseRgb(getComputedStyle(el).backgroundColor);
      if (!c) continue;
      const blue = c.b >= 150 && c.r <= 60 && c.g <= 120;
      const black = c.r <= 40 && c.g <= 40 && c.b <= 40;
      return { systemColor: blue || black };
    }
    return { systemColor: false };
  }

  // ---------------------------------------------------------------------------
  // Evaluate + respond
  // ---------------------------------------------------------------------------
  let context = null;
  const contextReady = send({ type: 'GET_CONTEXT' }).then((ctx) => { context = ctx || {}; });

  let done = false;
  let lastReported = null;
  const startedAt = Date.now();

  async function evaluate() {
    if (done || !document.documentElement) return;
    if (!frameCoversViewport()) return;
    await Promise.race([contextReady, new Promise((r) => setTimeout(r, 300))]);

    const A = S.scoreContext(context);
    const B = S.scoreTraps(collectTraps());
    const C = S.scoreContent(collectText(), collectVisual());
    const verdict = S.decide({ A: A.score, B: B.score, C: C.score });
    const signals = { A: A.score, B: B.score, C: C.score, hits: [...A.hits, ...B.hits, ...C.hits] };

    if (verdict === 'SCAM') {
      done = true;
      respondScam(signals);
    } else if (verdict === 'WARN') {
      if (lastReported !== 'WARN') {
        send({ type: 'VERDICT', verdict, signals, url: location.href, isTop });
        showBanner('This page is blocking your keyboard.', 'It may be trying to trap you. You can leave safely.', true);
      }
    } else if (lastReported !== 'CLEAN') {
      send({ type: 'VERDICT', verdict, signals, url: location.href, isTop });
    }
    lastReported = verdict;
  }

  function respondScam(signals) {
    // 1. defuse the page's own handlers (works if hooks.js ran at document_start)
    hookCmd('defuse');
    try { if (document.fullscreenElement) document.exitFullscreen(); } catch (_) { /* ignore */ }
    // 2. hide the scam immediately, before the navigation lands
    try { window.stop(); } catch (_) { /* ignore */ }
    try {
      const root = document.documentElement;
      root.replaceChildren();
      const body = document.createElement('body');
      body.style.cssText = 'font:16px system-ui,sans-serif;background:#fff;color:#111;padding:40px';
      body.textContent = 'Lock-Screen Guard blocked a fake "computer locked" scam page. You are safe. Redirecting…';
      root.append(body);
      document.title = 'Blocked by Lock-Screen Guard';
    } catch (_) { /* ignore */ }
    // 3. let the background navigate the whole tab away (works even if we are in a subframe)
    send({ type: 'VERDICT', verdict: 'SCAM', signals, url: location.href, isTop });
  }

  let timer = null;
  function scheduleEvaluate(delay) {
    if (done) return;
    clearTimeout(timer);
    timer = setTimeout(evaluate, delay);
  }

  function start() {
    scheduleEvaluate(300);
    // Content can arrive late (scripts building the DOM); watch for 5 s max.
    try {
      const mo = new MutationObserver(() => {
        if (done || Date.now() - startedAt > 5000) { mo.disconnect(); return; }
        scheduleEvaluate(300);
      });
      mo.observe(document.documentElement, { childList: true, subtree: true, characterData: true });
      setTimeout(() => mo.disconnect(), 5000);
    } catch (_) { /* ignore */ }
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start, { once: true });
  else start();
})();
