/*
 * hooks.js — runs in the page's MAIN world at document_start, before any page
 * script. Two jobs:
 *
 *  1. Lock-screen traps (only in URL-less documents: blob:, data:, framed
 *     about:/srcdoc): record which escape-blocking APIs the page uses, and
 *     register OUR capture listeners first so that, once defused, the page's
 *     own handlers never run (plan.md §2.3 B1 and §3).
 *  2. ClickFix (every page, but event-triggered only): wrap the clipboard
 *     write paths and block command payloads written under a paste lure
 *     (plan.md §12.2). Costs nothing until a page writes to the clipboard.
 *
 * Communication with the isolated-world detector uses CustomEvents carrying
 * JSON strings (objects don't cross worlds). The page can see and forge these
 * events; the detector only treats them as additive "suspicious" signals.
 * No scoring logic lives in this world: the page could tamper with it.
 */
(function () {
  'use strict';
  if (window.__lsgHooks) return;
  Object.defineProperty(window, '__lsgHooks', { value: true });

  // Private references to originals, captured before page code runs.
  const _add = EventTarget.prototype.addEventListener;
  const _remove = EventTarget.prototype.removeEventListener;
  const _dispatch = EventTarget.prototype.dispatchEvent;
  const _stringify = JSON.stringify.bind(JSON);
  const _parse = JSON.parse.bind(JSON);
  const _now = Date.now;
  const _CustomEvent = window.CustomEvent;

  function emit(kind, detail) {
    try {
      _dispatch.call(document, new _CustomEvent('__lsg_hook', { detail: _stringify({ kind, detail }) }));
    } catch (_) { /* document not ready */ }
  }

  function hasActivation() {
    try { return !!(navigator.userActivation && navigator.userActivation.isActive); } catch (_) { return false; }
  }

  // ===========================================================================
  // 2. ClickFix — every page
  // ===========================================================================
  const WARNING_TEXT = 'Blocked by Lock-Screen Guard: a website tried to put a command on your clipboard. Do not paste it into Run, PowerShell or a terminal.';

  // The scoring lives in the isolated world (detector.js + signals.js), out of
  // the page's reach. We ask it synchronously: CustomEvent dispatch runs every
  // listener (in both worlds) before returning. A page can forge replies, but we
  // only ever honour "block", so forging can't unblock anything.
  function checkClipboardPayload(payload, via) {
    if (typeof payload !== 'string' || payload.length < 12) return false;
    let block = false;
    const onReply = (e) => {
      try { const m = _parse(e.detail); if (m && m.block === true) block = true; } catch (_) { /* ignore */ }
    };
    _add.call(document, '__lsg_clip_reply', onReply);
    try {
      _dispatch.call(document, new _CustomEvent('__lsg_clip', { detail: _stringify({ payload: payload.slice(0, 4000), via }) }));
    } finally {
      _remove.call(document, '__lsg_clip_reply', onReply);
    }
    return block;
  }

  try {
    const CP = window.Clipboard && Clipboard.prototype;
    if (CP && CP.writeText) {
      const _writeText = CP.writeText;
      CP.writeText = function (text) {
        if (checkClipboardPayload(String(text), 'clipboard.writeText')) {
          return _writeText.call(this, WARNING_TEXT).catch(() => undefined);
        }
        return _writeText.apply(this, arguments);
      };
    }
    if (CP && CP.write) {
      const _write = CP.write;
      CP.write = async function (items) {
        try {
          for (const item of items || []) {
            if (item.types && item.types.includes('text/plain')) {
              const text = await (await item.getType('text/plain')).text();
              if (checkClipboardPayload(text, 'clipboard.write')) {
                return CP.writeText.call(this, WARNING_TEXT).catch(() => undefined);
              }
            }
          }
        } catch (_) { /* fall through to original */ }
        return _write.apply(this, arguments);
      };
    }
  } catch (_) { /* clipboard API absent */ }

  // copy-event path: page handler calls e.clipboardData.setData(...)
  try {
    const DT = DataTransfer.prototype;
    const _setData = DT.setData;
    DT.setData = function (format, data) {
      if (/^text(\/plain)?$/i.test(String(format)) && checkClipboardPayload(String(data), 'copyEvent.setData')) {
        return _setData.call(this, format, WARNING_TEXT);
      }
      return _setData.apply(this, arguments);
    };
  } catch (_) { /* ignore */ }

  // execCommand('copy') path: copies the current selection (often a hidden textarea)
  try {
    const _exec = Document.prototype.execCommand;
    Document.prototype.execCommand = function (cmd) {
      if (String(cmd).toLowerCase() === 'copy') {
        let sel = '';
        try {
          const el = document.activeElement;
          if (el && (el.tagName === 'TEXTAREA' || el.tagName === 'INPUT') && typeof el.selectionStart === 'number') {
            sel = el.value.substring(el.selectionStart, el.selectionEnd);
          }
          if (!sel) sel = String(window.getSelection() || '');
        } catch (_) { /* ignore */ }
        if (checkClipboardPayload(sel, 'execCommand.copy')) return false;
      }
      return _exec.apply(this, arguments);
    };
  } catch (_) { /* ignore */ }

  // ===========================================================================
  // 1. Lock-screen traps — URL-less documents only (performance gate)
  // ===========================================================================
  const p = location.protocol;
  const isTop = window === window.top;
  const gated = p === 'blob:' || p === 'data:' || (p === 'about:' && !isTop);
  if (!gated) return;

  const state = {
    listeners: { keydown: 0, keyup: 0, keypress: 0, contextmenu: 0, beforeunload: 0 },
    beforeunloadProp: false,
    lockApis: [],          // names of lock APIs called without a user gesture
    pushStates: [],        // timestamps
    dialogs: [],           // timestamps
    opens: [],             // window.open timestamps without a gesture
  };
  let defused = false;

  // --- our capture listeners, registered FIRST ------------------------------
  // Inert until defused; then they swallow the events so page handlers never run.
  const swallow = (e) => { if (defused) e.stopImmediatePropagation(); };
  for (const type of ['keydown', 'keyup', 'keypress', 'contextmenu', 'beforeunload', 'mousedown', 'mouseup', 'click', 'auxclick']) {
    _add.call(window, type, swallow, true);
  }

  // --- record listener registrations ----------------------------------------
  EventTarget.prototype.addEventListener = function (type, listener, options) {
    try {
      if (type in state.listeners && (this === window || this === document || this === document.body || this === document.documentElement)) {
        state.listeners[type]++;
      }
    } catch (_) { /* ignore */ }
    return _add.call(this, type, listener, options);
  };

  try {
    const desc = Object.getOwnPropertyDescriptor(window, 'onbeforeunload') ||
                 Object.getOwnPropertyDescriptor(Window.prototype, 'onbeforeunload');
    if (desc && desc.set) {
      Object.defineProperty(window, 'onbeforeunload', {
        configurable: true,
        get() { return desc.get.call(window); },
        set(v) { if (v) state.beforeunloadProp = true; desc.set.call(window, defused ? null : v); },
      });
    }
  } catch (_) { /* ignore */ }

  // --- lock APIs: fullscreen, keyboard lock, pointer lock --------------------
  function wrapLock(obj, name, label) {
    try {
      const orig = obj && obj[name];
      if (typeof orig !== 'function') return;
      obj[name] = function () {
        if (!hasActivation()) { state.lockApis.push(label); emit('trap', { lockApi: label }); }
        if (defused) return Promise.resolve();
        return orig.apply(this, arguments);
      };
    } catch (_) { /* ignore */ }
  }
  wrapLock(Element.prototype, 'requestFullscreen', 'fullscreen');
  wrapLock(Element.prototype, 'webkitRequestFullscreen', 'fullscreen');
  wrapLock(Element.prototype, 'requestPointerLock', 'pointerLock');
  try { if (navigator.keyboard) wrapLock(Object.getPrototypeOf(navigator.keyboard), 'lock', 'keyboardLock'); } catch (_) { /* ignore */ }

  // --- history flooding ------------------------------------------------------
  for (const name of ['pushState', 'replaceState']) {
    try {
      const orig = History.prototype[name];
      History.prototype[name] = function () {
        state.pushStates.push(_now());
        if (defused) return undefined;
        return orig.apply(this, arguments);
      };
    } catch (_) { /* ignore */ }
  }

  // --- dialog loops and popup spam -------------------------------------------
  for (const name of ['alert', 'confirm', 'prompt']) {
    try {
      const orig = window[name];
      window[name] = function () {
        state.dialogs.push(_now());
        if (defused) return name === 'confirm' ? false : null;
        return orig.apply(this, arguments);
      };
    } catch (_) { /* ignore */ }
  }
  try {
    const origOpen = window.open;
    window.open = function () {
      if (!hasActivation()) state.opens.push(_now());
      if (defused) return null;
      return origOpen.apply(this, arguments);
    };
  } catch (_) { /* ignore */ }

  function burst(ts, n, windowMs) {
    const now = _now();
    return ts.filter((t) => now - t < windowMs).length >= n || ts.length >= n * 2;
  }

  function report() {
    return {
      listeners: state.listeners,
      beforeunloadProp: state.beforeunloadProp,
      lockApis: state.lockApis.slice(0, 10),
      historyFlood: burst(state.pushStates, 6, 2000),
      dialogLoop: burst(state.dialogs, 3, 5000),
      popupSpam: burst(state.opens, 3, 5000),
      defused,
    };
  }

  function defuse() {
    defused = true;
    try { desc0(); } catch (_) { /* ignore */ }
    try { if (document.fullscreenElement) document.exitFullscreen(); } catch (_) { /* ignore */ }
    try { document.exitPointerLock && document.exitPointerLock(); } catch (_) { /* ignore */ }
    try { navigator.keyboard && navigator.keyboard.unlock(); } catch (_) { /* ignore */ }
  }
  function desc0() { window.onbeforeunload = null; }

  // --- commands from the isolated-world detector ------------------------------
  _add.call(document, '__lsg_cmd', (e) => {
    let msg;
    try { msg = _parse(e.detail); } catch (_) { return; }
    if (!msg || typeof msg !== 'object') return;
    if (msg.type === 'report') emit('state', report());
    else if (msg.type === 'defuse') { defuse(); emit('state', report()); }
  });
})();
