/*
 * background.js — MV3 service worker.
 *
 *   - Family A: tracks how each tab reached a URL-less document (webNavigation).
 *   - Receives verdicts from detector.js; on SCAM navigates the tab to the
 *     extension's own blocked.html (with a close-and-reopen fallback).
 *   - Injects the detector into tabs that were already open on a blob:/data:
 *     page when the extension was installed, updated or enabled.
 *   - Records verdicts in chrome.storage.session (in-memory, cleared when the
 *     browser closes) so the eval harness can read them. Nothing leaves the
 *     machine: no network, no telemetry.
 */
'use strict';

const URL_LESS = /^(blob|data):/i;
const BLOCKED_PAGE = chrome.runtime.getURL('blocked.html');

// tabId -> { lastCommitTs, lastUrl, scriptRedirect, fast, userOpenedTab }
const navCtx = new Map();
// tabs opened by another tab (window.open / target=_blank)
const openedTabs = new Set();
// tabs we already acted on, to avoid double navigation
const handled = new Set();

chrome.webNavigation.onCreatedNavigationTarget.addListener((d) => {
  openedTabs.add(d.tabId);
});

chrome.webNavigation.onCommitted.addListener((d) => {
  if (d.frameId !== 0) return;
  const prev = navCtx.get(d.tabId) || {};
  const now = Date.now();
  const ctx = { lastCommitTs: now, lastUrl: d.url, scriptRedirect: false, fast: false, userOpenedTab: false };
  if (URL_LESS.test(d.url)) {
    const q = d.transitionQualifiers || [];
    const cameFromPageInSameTab = !!prev.lastUrl && !URL_LESS.test(prev.lastUrl) && !openedTabs.has(d.tabId);
    // A same-tab jump from a normal page into a blob/data document that the
    // user didn't type or pick from history: script-driven redirect.
    ctx.scriptRedirect = cameFromPageInSameTab &&
      !q.includes('from_address_bar') && !q.includes('forward_back') &&
      d.transitionType !== 'typed' && d.transitionType !== 'auto_bookmark';
    ctx.fast = ctx.scriptRedirect && prev.lastCommitTs && now - prev.lastCommitTs < 3000;
    ctx.clientRedirect = q.includes('client_redirect');
    ctx.userOpenedTab = openedTabs.has(d.tabId);
  } else {
    handled.delete(d.tabId);
  }
  navCtx.set(d.tabId, ctx);
});

chrome.tabs.onRemoved.addListener((tabId) => {
  navCtx.delete(tabId);
  openedTabs.delete(tabId);
  handled.delete(tabId);
});

// ---------------------------------------------------------------------------
// Verdict log (session storage) — read by eval/run-eval.mjs
// ---------------------------------------------------------------------------
async function logVerdict(entry) {
  try {
    const { log = [] } = await chrome.storage.session.get('log');
    log.push(entry);
    await chrome.storage.session.set({ log: log.slice(-200) });
  } catch (_) { /* storage unavailable */ }
}

// ---------------------------------------------------------------------------
// Response
// ---------------------------------------------------------------------------
async function navigateAway(tabId, info) {
  if (handled.has(tabId)) return;
  handled.add(tabId);
  const params = new URLSearchParams({
    reason: info.reason || 'scam',
    hits: (info.hits || []).join(','),
    score: String(info.score || ''),
  });
  const target = `${BLOCKED_PAGE}?${params}`;
  try {
    await chrome.tabs.update(tabId, { url: target });
  } catch (_) { /* tab may be gone */ }
  // Fallback: if the page somehow kept the tab, replace the tab entirely.
  setTimeout(async () => {
    try {
      const tab = await chrome.tabs.get(tabId);
      if (tab && !String(tab.url || tab.pendingUrl || '').startsWith(BLOCKED_PAGE)) {
        await chrome.tabs.create({ url: target, index: tab.index, windowId: tab.windowId });
        await chrome.tabs.remove(tabId);
      }
    } catch (_) { /* tab already closed */ }
  }, 1500);
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  const tabId = sender.tab && sender.tab.id;
  if (!msg || typeof msg !== 'object' || tabId === undefined) return false;

  if (msg.type === 'GET_CONTEXT') {
    sendResponse(navCtx.get(tabId) || {});
    return false;
  }

  if (msg.type === 'VERDICT') {
    const verdict = ['SCAM', 'WARN', 'CLEAN', 'CLICKFIX'].includes(msg.verdict) ? msg.verdict : 'CLEAN';
    const acted = verdict === 'SCAM' && !handled.has(tabId);
    logVerdict({
      ts: Date.now(),
      tabId,
      frameId: sender.frameId,
      url: String(msg.url || '').slice(0, 200),
      verdict,
      signals: msg.signals || {},
      context: navCtx.get(tabId) || {},
      acted: acted || verdict === 'CLICKFIX',
    });
    if (acted) {
      const s = msg.signals || {};
      navigateAway(tabId, { reason: 'lockscreen', hits: s.hits, score: `A${s.A}/B${s.B}/C${s.C}` });
    }
    return false;
  }

  if (msg.type === 'LEAVE_PAGE') {
    navigateAway(tabId, { reason: 'user-leave' });
    return false;
  }
  return false;
});

// ---------------------------------------------------------------------------
// "Already on the page when installed" (plan.md §4)
// Runs on install/update and on every service-worker start (covers enable).
// The detector guards against double injection with a window flag.
// ---------------------------------------------------------------------------
async function scanExistingTabs() {
  let tabs = [];
  try { tabs = await chrome.tabs.query({}); } catch (_) { return; }
  for (const tab of tabs) {
    if (!tab.id || !URL_LESS.test(tab.url || '')) continue;
    try {
      await chrome.scripting.executeScript({
        target: { tabId: tab.id, allFrames: true },
        files: ['content/signals.js', 'content/detector.js'],
      });
    } catch (_) { /* no access to this tab */ }
  }
}

chrome.runtime.onInstalled.addListener(scanExistingTabs);
chrome.runtime.onStartup.addListener(scanExistingTabs);
scanExistingTabs();
