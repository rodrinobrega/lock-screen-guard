// End-to-end eval: loads the unpacked extension in Chromium, runs every labelled
// fixture, reads the extension's own verdict log and checks the effect on the tab.
//
//   npm run eval                 # headless
//   HEADED=1 npm run eval        # watch it
//   ONLY=clickfix npm run eval   # filter by id substring
//
// Writes eval/report.json and exits non-zero on any mismatch (CI / agent friendly).
import { chromium } from 'playwright';
import http from 'node:http';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, '..');
const extDir = path.join(root, 'extension');
const fixturesDir = path.join(here, 'fixtures');
const SETTLE_MS = Number(process.env.SETTLE_MS || 3500);
const SEVERITY = { CLEAN: 0, WARN: 1, SCAM: 2, CLICKFIX: 2 };

// ---------------------------------------------------------------------------
// Corpus: visible cases + optional holdout cases
// ---------------------------------------------------------------------------
const visible = JSON.parse(fs.readFileSync(path.join(here, 'expected.json'), 'utf8')).cases
  .map((c) => ({ ...c, set: 'visible' }));
const holdoutFile = path.join(fixturesDir, 'holdout', 'holdout.json');
const holdout = fs.existsSync(holdoutFile)
  ? JSON.parse(fs.readFileSync(holdoutFile, 'utf8')).cases.map((c) => ({ ...c, set: 'holdout' }))
  : [];
let cases = [...visible, ...holdout];
if (process.env.ONLY) cases = cases.filter((c) => c.id.includes(process.env.ONLY));

// ---------------------------------------------------------------------------
// Static server (real http origin, not file://)
// ---------------------------------------------------------------------------
const server = http.createServer((req, res) => {
  const rel = decodeURIComponent(new URL(req.url, 'http://x').pathname).replace(/^\/+/, '');
  const file = path.resolve(fixturesDir, rel);
  if (!file.startsWith(fixturesDir) || !fs.existsSync(file) || fs.statSync(file).isDirectory()) {
    res.writeHead(404).end('not found');
    return;
  }
  res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
  fs.createReadStream(file).pipe(res);
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const base = `http://127.0.0.1:${server.address().port}/`;

// ---------------------------------------------------------------------------
// Browser with the unpacked extension
// ---------------------------------------------------------------------------
const userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'lsg-eval-'));
const context = await chromium.launchPersistentContext(userDataDir, {
  channel: 'chromium',               // new headless mode, which supports extensions
  headless: !process.env.HEADED,
  args: [`--disable-extensions-except=${extDir}`, `--load-extension=${extDir}`],
  permissions: ['clipboard-read', 'clipboard-write'],
});

async function getWorker() {
  let [sw] = context.serviceWorkers();
  if (!sw) sw = await context.waitForEvent('serviceworker', { timeout: 10000 });
  return sw;
}
let sw = await getWorker();
const extId = new URL(sw.url()).host;
const blockedPrefix = `chrome-extension://${extId}/blocked.html`;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function swEval(fn) {
  try { return await sw.evaluate(fn); } catch (_) { sw = await getWorker(); return sw.evaluate(fn); }
}

// Toggle the extension from chrome://extensions (has chrome.management) to
// simulate "the user was already on the page when the extension arrived".
async function setExtensionEnabled(enabled) {
  const mgmt = await context.newPage();
  await mgmt.goto('chrome://extensions/');
  await mgmt.evaluate(([id, on]) => new Promise((r) => chrome.management.setEnabled(id, on, r)), [extId, enabled]);
  await mgmt.close();
  if (enabled) {
    sw = context.serviceWorkers().find((w) => w.url().includes(extId)) ||
      await context.waitForEvent('serviceworker', { timeout: 10000 });
  }
}

async function closeAllPages() {
  for (const p of context.pages()) await p.close().catch(() => {});
}

async function readClipboard() {
  const p = await context.newPage();
  try {
    await p.goto(base + 'benign/docs-install-command.html');
    await p.bringToFront();
    return await p.evaluate(() => navigator.clipboard.readText());
  } catch (e) {
    return `<<clipboard unavailable: ${e.message}>>`;
  } finally {
    await p.close();
  }
}

async function resetClipboard() {
  const p = await context.newPage();
  try {
    await p.goto(base + 'benign/docs-install-command.html');
    await p.bringToFront();
    await p.evaluate(() => navigator.clipboard.writeText('__empty__'));
  } catch (_) { /* ignore */ } finally { await p.close(); }
}

// ---------------------------------------------------------------------------
// Run
// ---------------------------------------------------------------------------
const results = [];
for (const c of cases) {
  await closeAllPages();
  await swEval(() => chrome.storage.session.clear());
  if (c.clipboardMustContain || c.clipboardMustNotContain) await resetClipboard();

  const url = base + c.file;
  const errors = [];
  if (c.late) await setExtensionEnabled(false);

  const page = await context.newPage();
  try { await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 10000 }); } catch (e) { errors.push(`goto: ${e.message.split('\n')[0]}`); }

  if (c.late) {
    await sleep(1500);                 // scam fully rendered with no extension present
    await setExtensionEnabled(true);   // service worker starts -> scans existing tabs
  }

  for (const step of c.steps || []) {
    try {
      if (step.click) await page.click(step.click, { timeout: 5000 });
      if (step.wait) await sleep(step.wait);
    } catch (e) { errors.push(`step ${JSON.stringify(step)}: ${e.message.split('\n')[0]}`); }
  }

  await sleep(SETTLE_MS);

  const log = (await swEval(() => chrome.storage.session.get('log')))?.log || [];
  const got = log.reduce((acc, e) => (SEVERITY[e.verdict] > SEVERITY[acc] ? e.verdict : acc), 'CLEAN');
  const top = log.filter((e) => e.verdict === got).pop() || {};

  const pages = context.pages();
  const urls = pages.map((p) => p.url());
  const navigatedToBlocked = urls.some((u) => u.startsWith(blockedPrefix));
  const acted = log.some((e) => e.acted);

  const checks = { verdict: c.expected.includes(got) };
  if (got === 'SCAM' || c.expected.includes('SCAM')) checks.navigatedToBlocked = navigatedToBlocked;
  if (c.expected.every((v) => v === 'CLEAN' || v === 'WARN')) {
    checks.noAction = !acted && !navigatedToBlocked;
  }
  let clipboard;
  if (c.clipboardMustContain || c.clipboardMustNotContain) {
    clipboard = await readClipboard();
    if (c.clipboardMustContain) checks.clipboardKept = clipboard.includes(c.clipboardMustContain);
    if (c.clipboardMustNotContain) checks.clipboardBlocked = !clipboard.toLowerCase().includes(c.clipboardMustNotContain.toLowerCase());
  }

  const pass = Object.values(checks).every(Boolean);
  const r = {
    id: c.id, set: c.set, expected: c.expected, got, pass, checks,
    signals: top.signals || null,
    context: top.context || null,
    entries: log.length,
    tabs: urls.map((u) => u.slice(0, 90)),
    ...(clipboard !== undefined ? { clipboard: clipboard.slice(0, 120) } : {}),
    ...(errors.length ? { errors } : {}),
  };
  results.push(r);
  const s = r.signals ? ` A${r.signals.A ?? '-'} B${r.signals.B ?? '-'} C${r.signals.C ?? '-'} [${(r.signals.hits || r.signals.clickfix || []).join(',')}]` : '';
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${c.id.padEnd(32)} expected ${c.expected.join('|').padEnd(10)} got ${got.padEnd(8)}${s}${pass ? '' : '  ' + JSON.stringify(checks)}`);
}

await context.close();
server.close();
fs.rmSync(userDataDir, { recursive: true, force: true });

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------
function summarize(list) {
  const isBad = (v) => v === 'SCAM' || v === 'CLICKFIX';
  return {
    total: list.length,
    passed: list.filter((r) => r.pass).length,
    failed: list.filter((r) => !r.pass).length,
    falsePositives: list.filter((r) => !r.expected.some(isBad) && isBad(r.got)).length,
    falseNegatives: list.filter((r) => r.expected.some(isBad) && !isBad(r.got)).length,
  };
}
const report = {
  generatedAt: new Date().toISOString(),
  browser: 'chromium (Playwright, new headless)',
  summary: summarize(results.filter((r) => r.set === 'visible')),
  holdout: holdout.length ? summarize(results.filter((r) => r.set === 'holdout')) : null,
  cases: results,
};
fs.writeFileSync(path.join(here, 'report.json'), JSON.stringify(report, null, 2));
console.log('\nvisible:', JSON.stringify(report.summary));
if (report.holdout) console.log('holdout:', JSON.stringify(report.holdout));
process.exit(results.every((r) => r.pass) ? 0 : 1);
