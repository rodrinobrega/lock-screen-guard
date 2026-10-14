# plan.md — "Lock-Screen Guard" (Chrome MV3 extension)

## 1. Problem in one paragraph

`malicious.html` builds an HTML page in memory, wraps it in a `Blob`, and navigates the **same tab** to the resulting `blob:` URL (`window.location.href = blobUrl`) as soon as it loads, with no click. The page never contacts a scannable URL. The fake lock screen then blocks escape routes: `contextmenu`, F5/F11/F12/Esc, Ctrl+R/W/L, and `beforeunload`.

`benign.html` uses the same mechanism (`Blob` → `blob:` URL → render HTML). The differences are that it opens the blob in a **new tab after a user click**, it shows harmless content, and it sets no traps.

So **"blob: + text/html" alone cannot be the detection rule**. We combine three independent signal families and act only when they agree.

---

## 2. Detection design

### 2.1 Gate: only analyze "URL-less" documents (performance)

Every content script starts with a check that costs almost nothing:

```js
const p = location.protocol;
if (p !== 'blob:' && p !== 'data:' && !(p === 'about:' && window !== top)) return;
if (document.contentType !== 'text/html') return; // PDFs, images, etc. are skipped
```

On normal `http(s)` pages the extension does nothing beyond that string comparison. There are no observers, no DOM reads, and no messages. This meets the requirement that browsing performance stays unaffected.

> Alternative considered: don't register static content scripts at all, and inject on demand via `webNavigation.onCommitted` + `chrome.scripting.executeScript` only for `blob:` frames. This gives literally zero cost on normal pages, but we would lose `document_start` hooks (we'd inject after the page has registered its traps). I'm keeping the static script with an early exit and noting this as a tradeoff.

### 2.2 Signal family A — Navigation context (background, `webNavigation`)

| Signal | How | Score |
|---|---|---|
| Main frame committed a `blob:`/`data:` URL **in the same tab** with qualifier `client_redirect` (a script redirect, no gesture) | `webNavigation.onCommitted` with `frameId === 0`, `transitionQualifiers` | **+2** |
| Blob opened in a **new tab** from a user action | `webNavigation.onCreatedNavigationTarget` (has `sourceTabId`) | 0 (neutral, benign-like) |
| Redirect happened < ~1.5 s after the parent page committed | timestamps from `onCommitted` | +1 |

The background keeps a small `Map<tabId, ctx>` that holds only the latest navigation per tab. Nothing persists, so we stay inside the "single active tab, no persistent state" scope.

### 2.3 Signal family B — Trap behavior (content script, the strongest signal)

There are two complementary ways to observe traps.

**B1. Hooks (MAIN world, `document_start`)**: `hooks.js` runs before any page script and wraps:
- `EventTarget.prototype.addEventListener`. It records listeners for `keydown`/`keyup`/`keypress`, `contextmenu` and `beforeunload`, and also `onbeforeunload` / `oncontextmenu` property setters.
- `Element.prototype.requestFullscreen`, `navigator.keyboard.lock`, `Element.prototype.requestPointerLock`.
- `history.pushState`/`replaceState`, counting calls (history flooding to break Back).
- `window.alert/confirm/prompt`, counting calls (dialog loops).

The hooks also register **our own capture-phase listeners first** on `window`. That lets us neutralize traps later (see §3).

**B2. Active probing (isolated world)**: this works even when hooks didn't run, for example when the extension was installed *after* the page loaded. We dispatch synthetic, cancelable events and check whether the page cancels them:

```js
const probe = (ev) => { (document.body || document).dispatchEvent(ev); return ev.defaultPrevented; };
probe(new KeyboardEvent('keydown', { key: 'F5',  bubbles: true, cancelable: true }));
probe(new KeyboardEvent('keydown', { key: 'w', ctrlKey: true, bubbles: true, cancelable: true }));
probe(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true, cancelable: true }));
probe(new MouseEvent('contextmenu', { bubbles: true, cancelable: true }));
const bu = new Event('beforeunload', { cancelable: true }); window.dispatchEvent(bu); // defaultPrevented / returnValue
```

| Signal | Score |
|---|---|
| Browser-escape keys cancelled (F5, F11, F12, Esc, Ctrl+W/R/L) | **+3** |
| `beforeunload` cancelled | **+2** |
| `contextmenu` cancelled | +1 |
| Fullscreen / keyboard lock / pointer lock requested without a user gesture | **+3** (extra layer) |
| > 5 `pushState` calls in 2 s, or a dialog loop | +2 (extra layer) |

Probing runs only on gated documents, so it never touches normal sites.

### 2.4 Signal family C — Content (isolated world)

This runs once at `DOMContentLoaded`, then through a `MutationObserver` debounced to 300 ms that disconnects after 5 s or after a verdict. It reads `document.body.innerText`, plus open shadow roots and `<title>`, capped at about 20 KB.

| Signal | Example regex / check | Score |
|---|---|---|
| Lock / compromise wording | `/(computer|device|pc|mac).{0,20}(locked|blocked|infected|compromised)/i` | **+2** |
| OS / vendor impersonation | `/(microsoft|windows|apple|macos)\s+(support|defender|security|technician)/i` | **+2** |
| Support phone number | `/(\+?1[\s.-]?)?\(?8(00|33|44|55|66|77|88)\)?[\s.-]?\d{3}[\s.-]?\d{4}/` or generic international phone | **+2** |
| Urgency / anti-escape instructions | `/do not (restart|shut ?down|close)|immediately|call now/i` | +1 |
| Fake error code | `/error code[:\s]*0x[0-9a-f]{6,8}/i` | +1 |
| Full-viewport solid "system" background (BSOD blue / black) | `getComputedStyle(body).backgroundColor` + element covering ≥ 90% of the viewport | +1 |

### 2.5 Decision rule

```
A = navigation context, B = traps, C = content

SCAM   if  C ≥ 4  AND  (B ≥ 3 OR A ≥ 2)
WARN   if  B ≥ 6  AND  C < 4                 → non-blocking banner "This page is blocking your keyboard — Leave page"
                                               (covers canvas/image-rendered text that C can't read)
CLEAN  otherwise                             → do nothing
```

The rationale is that **content alone** is not enough, because a blog post about tech-support scams would match it. **Traps alone** are not enough either, because games, kiosks and editors legitimately capture keys. **Both together**, inside a URL-less document, are a very strong combination.

**Against the samples:**

| | A | B | C | Verdict |
|---|---|---|---|---|
| `malicious.html` → blob | 2 (same-tab client redirect) | 6 (keys + ctxmenu + beforeunload) | 8 | **SCAM** ✅ |
| `benign.html` → blob | 0 (new tab, user click) | 0 | 0 | **CLEAN** ✅ |

---

## 3. Response — make sure the user can actually leave

When the detector returns SCAM, the content script performs these steps in order:

1. **Defuse locally (MAIN world)**: flip a `defused` flag. Our capture listeners registered first on `window` (keydown, contextmenu, beforeunload) then call `stopImmediatePropagation()`, so the page's handlers never run. Set `window.onbeforeunload = null`, call `document.exitFullscreen()`, `document.exitPointerLock()`, `navigator.keyboard?.unlock()`, then `window.stop()`.
2. **Hide the scam right away**: `document.documentElement.replaceChildren()` plus a minimal "Blocked" message. The user sees the content disappear even before the navigation happens.
3. **Message the background**: `{ type: 'LOCKSCREEN_DETECTED', score, signals }`.
4. **Background navigates the tab away**: `chrome.tabs.update(tabId, { url: chrome.runtime.getURL('blocked.html') })`. This is an extension page the scam can't script, and it explains what happened and which signals fired. It offers **"Open a new tab"** and deliberately has no "Go back", because history may be poisoned and "back" leads to the scam's host page.
5. **Fallback chain**, if the tab URL is still `blob:` after 1 s: `chrome.tabs.create({ url: blocked.html })` followed by `chrome.tabs.remove(tabId)`.

Notes:
- Chrome only shows `beforeunload` dialogs after sticky user activation, so a fresh scam often can't block navigation anyway. The steps above cover the case where the user already clicked or typed on the page.
- All of this happens without any network requests.

---

## 4. "Already on the page when installed"

`chrome.runtime.onInstalled` →
1. `chrome.tabs.query({ active: true, currentWindow: true })`. Also query all tabs; it's cheap.
2. For tabs whose `url` starts with `blob:` or `data:`, run `chrome.scripting.executeScript({ target: { tabId, allFrames: true }, files: ['content/detector.js'] })`.
3. In that case hooks (B1) never ran, so the detector relies on **probing (B2) + content (C)**. A = unknown, scored as 0. The malicious sample still scores B = 6 and C = 8 → SCAM.
4. On defuse, we can't pre-empt the page's listeners because we registered late. The response therefore goes straight to the background `tabs.update`, with the close-and-reopen fallback.

---

## 5. File layout

```
lockscreen-guard/
├── manifest.json
├── background.js          # webNavigation context map, verdict handling, tab navigation, onInstalled injection
├── content/
│   ├── hooks.js           # MAIN world, document_start: API wrappers + our first-registered capture listeners
│   ├── detector.js        # isolated world: gate, probing, content scoring, decision, messaging
│   └── signals.js         # regexes / weights (pure functions, unit-testable)
├── blocked.html / blocked.js
├── samples/ (malicious.html, benign.html)
├── eval/                  # see §11 — fixtures, expected verdicts, harness
│   ├── fixtures/{malicious,benign}/*.html
│   ├── fixtures/holdout/*.html
│   ├── expected.json
│   ├── run-eval.mjs       # Playwright + unpacked extension → report.json
│   └── signals.test.mjs   # unit tests for signals.js (node --test)
└── NOTE.md                # the short write-up required by the assignment (§9)
```

### manifest.json

```json
{
  "manifest_version": 3,
  "name": "Lock-Screen Guard",
  "version": "0.1.0",
  "description": "Detects and stops fake OS lock-screen scam pages rendered from blob:/data: URLs.",
  "permissions": ["webNavigation", "scripting", "tabs"],
  "host_permissions": ["<all_urls>"],
  "background": { "service_worker": "background.js" },
  "content_scripts": [
    {
      "matches": ["<all_urls>"],
      "match_origin_as_fallback": true,
      "all_frames": true,
      "run_at": "document_start",
      "world": "MAIN",
      "js": ["content/hooks.js"]
    },
    {
      "matches": ["<all_urls>"],
      "match_origin_as_fallback": true,
      "all_frames": true,
      "run_at": "document_start",
      "js": ["content/signals.js", "content/detector.js"]
    }
  ]
}
```

`match_origin_as_fallback: true` is the key line. It is what lets content scripts run inside `blob:`, `data:` and `about:blank` documents, inheriting the creator's origin.

### MAIN ↔ isolated communication
`hooks.js` reports to `detector.js` through `window.postMessage({ __lsg: true, kind, detail })`. The page *can* forge these messages, but we only accept **additive** suspicious signals. Forging could therefore only incriminate the page itself, never clear it. `detector.js` → `hooks.js` sends the "defuse" command the same way, and `hooks.js` keeps private references to the original APIs captured at `document_start`.

---

## 6. Implementation steps (≈ 60 min budget)

| # | Step | Time |
|---|---|---|
| 1 | Manifest + skeleton files, load unpacked, confirm the content script runs inside the `blob:` page (log `location.href`) | 8 min |
| 2 | `signals.js`: content regexes + weights; `detector.js`: gate + content scoring | 10 min |
| 3 | Probing (B2) + decision rule + message to background | 10 min |
| 4 | `background.js`: `webNavigation` context (A), verdict → `tabs.update(blocked.html)` + fallback | 10 min |
| 5 | `hooks.js`: listener/fullscreen/history wrappers + first-registered capture listeners + defuse | 10 min |
| 6 | `onInstalled` injection into existing blob tabs | 4 min |
| 7 | Manual test matrix (§7) + `NOTE.md` | 8 min |

If time runs short, cut step 5's extras (history/dialog counters) first. Probing already covers the base traps.

---

## 7. Test matrix

Serve the samples over HTTP (`npx http-server samples`). On `file://`, you must enable "Allow access to file URLs" for the extension.

| Case | Expected |
|---|---|
| Open `malicious.html` fresh | Content vanishes, tab lands on `blocked.html` |
| Open `malicious.html`, *then* load the extension | `onInstalled` injection → blocked |
| Open `benign.html`, click "View Generated Report" | Report opens in a new tab, untouched; no console noise |
| Normal sites (news, Gmail, YouTube) | Detector exits at the gate (verify with a `console.count` in dev builds) |
| A blog article *about* tech-support scams (http) | Not analyzed (gate) |
| Same article text served as a blob, no traps, opened via click | CLEAN (C may be ≥ 4, but B = 0 and A = 0) |
| Blob page that only blocks keys (e.g. a game preview) | CLEAN or at most WARN banner, never a hard block |
| Malicious variant + `requestFullscreen` on first click | Blocked; fullscreen exited |
| Malicious variant inside a full-viewport `blob:` iframe | Blocked (all_frames + top-tab navigation) |

---

## 8. Bonus — extra trapping layers handled

- **Fullscreen / Keyboard Lock / Pointer Lock**: detected via hooks (+3) and reversed on defuse (`exitFullscreen`, `keyboard.unlock`, `exitPointerLock`).
- **History flooding** (`pushState` spam so Back keeps returning to the scam): counted. The response navigates to an extension page with no Back option.
- **Dialog loops** (`alert` in a loop): counted. On defuse, `hooks.js` replaces `alert/confirm/prompt` with no-ops before navigating.
- **Nested framing** (blob page → full-viewport iframe → another blob/data/srcdoc doc): `all_frames` + `match_origin_as_fallback` analyze each frame. A frame covering ≥ 90% of the viewport reports to the background, which acts on the **top** tab.
- **Popup re-spawning** (`window.open` loops): hooks count opens without a gesture. The background can close child tabs created via `onCreatedNavigationTarget` from a flagged tab.

---

## 9. NOTE.md (the required short write-up)

> **How it detects:** The extension only analyzes documents with no real URL (`blob:`, `data:`, framed `about:blank`), and exits immediately everywhere else, so normal browsing costs nothing. Inside those documents it scores three independent signals. (A) *How we got here*: a same-tab script redirect with no click, versus a user-initiated new tab. (B) *Escape blocking*: hooks plus synthetic probe events reveal whether the page cancels F5/Esc/Ctrl+W, right-click or unload, or grabs fullscreen or keyboard lock. (C) *Scam content*: "computer locked" wording, OS-vendor impersonation, a support phone number, fake error codes, and full-screen system styling. A page is blocked only when scam content coincides with trapping or a no-gesture redirect. Blocking means neutralizing the page's handlers, exiting fullscreen, wiping the DOM, and navigating the tab to an extension page.
>
> **Why:** The blob mechanism itself is legitimate (report previews, exports), so it can only be a *gate*, not a verdict. Each signal alone has known false positives: content matches articles about scams, and key capture matches games and editors. Requiring agreement keeps precision high, and probing works even when we're injected late.
>
> **False positives:** A legitimate blob-rendered page that discusses support numbers *and* captures keys, such as a helpdesk app's in-browser kiosk preview. Mitigation: blocking requires both families, and trap-only pages get a dismissible banner instead of a block.
>
> **False negatives:** Text rendered in canvas or images (C ≈ 0; partially covered by the trap-only WARN), non-English or obfuscated wording (zero-width characters, homoglyphs), scams that set no traps and arrive by a click, content hosted on a normal `https` URL (out of scope; the network/URL-reputation layer should catch that), and pages that detect our probes (e.g. checking `event.isTrusted`). The `isTrusted` case is mitigated by the MAIN-world `addEventListener` hooks, which see registrations regardless.
>
> **Threat classification (OWASP / MITRE):** The attack is [Content Spoofing](https://owasp.org/www-community/attacks/Content_Spoofing): deceptive content presented as a trusted source (the OS) to drive a social-engineering outcome, a phone call. It does this through [Abuse of Functionality](https://owasp.org/www-community/attacks/Abuse_of_Functionality), meaning legitimate APIs (Blob URLs, key events, `beforeunload`, Fullscreen) used against the user. The framed variants overlap with [Clickjacking / UI redress](https://owasp.org/www-community/attacks/Clickjacking). The clipboard extension (ClickFix) maps to MITRE ATT&CK [T1204.004 Malicious Copy and Paste](https://attack.mitre.org/techniques/T1204/004/). The extension itself follows the [OWASP Browser Extension Vulnerabilities Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Browser_Extension_Vulnerabilities_Cheat_Sheet.html). Full map in §12.

---

## 10. Extending to related "URL-less" techniques (description only)

- **`about:blank` + `document.write`** in popups or iframes: the address bar shows `about:blank` or the opener's origin. Same gate, already covered by `match_origin_as_fallback`; extend it to top-level `about:blank` windows opened by script.
- **`data:` URLs** in iframes (Chrome blocks top-level ones) and **`srcdoc` iframes**: analyze any frame covering most of the viewport.
- **Service-worker-fabricated responses**: the URL looks normal, but the content is synthesized offline. Watch for a full-viewport scam DOM on a page whose `navigator.serviceWorker.controller` is set, and run the same trap + content scoring on *any* origin once a trap signal fires. Hooks are cheap, and content analysis only starts after a trap is detected.
- **Fullscreen "browser-in-the-browser"** fake address bars or fake OS windows drawn over a legitimate-looking URL: treat `requestFullscreen` + an element mimicking browser chrome (an input showing a URL, lock icons) as a trap signal.
- **Canvas/WebGL or image-only rendering**: optional on-device OCR (e.g. the Shape Detection `TextDetector` API, where available) run *only* after strong trap signals, to keep performance intact.
- **`javascript:` / `blob:` links in `window.open` chains and `history.pushState` URL spoofing**: correlate them in the background through `webNavigation` and `tabs.onUpdated`.

---

## 11. Evaluation — how an AI agent (or CI) verifies the extension

The point of this section is that a reviewer should not have to click through tabs by hand to trust the thing. There are two layers: pure unit tests on the scoring logic, and an end-to-end harness that drives a real Chrome with the extension loaded and checks the verdict on a labelled corpus of attack variants we write ourselves.

### 11.1 Why build our own variants

The two provided samples prove the happy path and nothing else. A detector that hardcodes to them (e.g. greps for "1-800-555-0199") would pass and be worthless. So we expand the corpus with **(a) attack variants** that keep the scam intent but change surface details, to catch false negatives, and **(b) benign look-alikes** that trip one signal family but not the others, to catch false positives. Each fixture is labelled, and the eval fails if any verdict disagrees with its label.

### 11.2 Labelled corpus

`eval/expected.json` maps each fixture to its expected verdict and, for debugging, which signal families *should* fire.

**Malicious variants (expected `SCAM`):**

| Fixture | Varies | Targets |
|---|---|---|
| `base.html` | the provided sample | baseline |
| `data-uri.html` | `data:text/html` instead of `blob:` | gate must cover `data:` |
| `delayed-redirect.html` | redirect after `setTimeout(1200)` | timing window in signal A |
| `iframe-fullscreen.html` | scam in a full-viewport blob iframe + `requestFullscreen` | all_frames + bonus trap |
| `history-flood.html` | `pushState` loop instead of key blocking | Back-button trap |
| `phone-obfuscated.html` | number as "call 1‑800‑555‑ zero199" / unicode digits | content regex robustness |
| `apple-variant.html` | macOS / "Apple Support" wording, black bg | vendor-agnostic content |
| `late-install.html` | sets traps, loaded *before* extension (harness installs after) | §4 path, probing only |
| `no-beforeunload.html` | keys blocked but no unload trap | B still reaches threshold |

**Benign variants (expected `CLEAN`, a few `WARN` at most):**

| Fixture | Varies | Why it's a trap for us |
|---|---|---|
| `report-viewer.html` | the provided sample | baseline |
| `scam-article.html` | a blog post *about* lock-screen scams, served as a blob, user click | content C fires alone → must stay CLEAN |
| `webgl-game.html` | blob game that captures keys + requests fullscreen on click | traps fire alone → CLEAN or WARN, never SCAM |
| `code-sandbox.html` | editor capturing Ctrl+S, blob preview | key capture is legitimate |
| `kiosk-slides.html` | fullscreen slideshow, Esc hint | fullscreen alone |
| `pdf-preview.html` | `blob:application/pdf` | gate: non-HTML contentType, skipped |

A `holdout/` folder holds a handful of fixtures **not** committed until review time (or generated by a separate agent from a prompt), so the detector can't be overfit to the visible set. The eval reports visible and holdout scores separately.

### 11.3 Harness (`run-eval.mjs`)

Node + Playwright (`chromium.launchPersistentContext` with `--load-extension` / `--disable-extensions-except`; MV3 service workers need a persistent context). For each fixture:

1. Serve `eval/fixtures` over `http-server` (real origin, not `file://`).
2. For normal fixtures: open the opener page, trigger the click if the label needs a gesture, wait for the tab to settle.
3. For `late-install.*`: load the page first in a context with the extension disabled, then enable it and reload the service worker — approximates install-while-open.
4. **Read the verdict** without trusting the page. The extension writes each decision to `chrome.storage.session` keyed by tabId (`{verdict, score, signals, ts}`); the harness reads it from the service worker via `chrome.storage.session.get`. This is the machine-readable hook an agent checks — not a screenshot.
5. Cross-check the **effect**: after a SCAM verdict, assert the tab's URL is now the extension's `blocked.html` and that `document.title` no longer matches the scam; after CLEAN, assert the page DOM is intact and `blocked.html` was never loaded.
6. Assert **no action on benign**: a second counter in storage records whether defuse/navigation ran; it must be 0 for CLEAN fixtures.

Output is `report.json`:

```json
{
  "summary": { "total": 15, "passed": 15, "failed": 0,
               "falsePositives": 0, "falseNegatives": 0 },
  "cases": [
    { "fixture": "malicious/data-uri.html", "expected": "SCAM",
      "got": "SCAM", "score": 11, "signals": {"A":2,"B":6,"C":8},
      "effect": { "navigatedToBlocked": true, "domWiped": true }, "pass": true }
  ]
}
```

Exit code is non-zero on any mismatch, so it drops straight into CI or an agent loop. The `signals` breakdown lets an agent see *why* a case failed (wrong family firing) rather than just that it did.

### 11.4 Unit layer (`signals.test.mjs`)

`signals.js` is pure functions — `scoreContent(text) → {score, hits}`, `scoreTraps(probeResults) → score`, `decide({A,B,C}) → verdict`. `node --test` runs table-driven cases: each content regex against matching and deliberately-near-miss strings (e.g. "I locked my computer keys" must *not* fire the lock-wording signal strongly), and the decision boundary at its exact thresholds (C=4/B=3, C=4/B=2, B=6/C=3). This is fast, deterministic, and where threshold tuning happens, so the slow browser harness only validates integration.

### 11.5 How an AI agent uses this

The loop is: implement → `node --test` (logic) → `node eval/run-eval.mjs` (integration) → read `report.json`. On a failure the agent gets the fixture, expected vs actual verdict, and the per-family scores, which is enough to localize the fix (regex, threshold, or response wiring) without re-reading the whole codebase. A reviewing agent can also be handed *only* `expected.json` + the harness and asked to generate fresh adversarial fixtures, then run them — if new variants slip through, that's a real finding about the heuristic, not a code bug.

**Honest limits of the eval:** it's only as good as the corpus, so it measures robustness against *variations we thought of*. It can't prove the detector catches a genuinely novel evasion, and it runs in headless Chromium, so a handful of real-Chrome behaviours (actual `beforeunload` prompts, true OS fullscreen) still need one manual pass from §7. Treat a green eval as "no known regression", not "proven safe".

---

## 12. Threat map, OWASP references and scope boundaries

### 12.1 Threat map

The goal is to show the *threat class* we mapped and where we deliberately drew the line, not just the one sample we solved.

| # | Technique | Reference | Status in this extension | Why |
|---|---|---|---|---|
| 1 | Fake OS lock screen via same-tab `blob:` redirect (the assignment) | [OWASP Content Spoofing](https://owasp.org/www-community/attacks/Content_Spoofing), [OWASP Abuse of Functionality](https://owasp.org/www-community/attacks/Abuse_of_Functionality) | ✅ **Covered** | Core solution (§2–§4) |
| 2 | Same content via `data:` / `srcdoc` / `about:blank` + `document.write` | [OWASP Content Spoofing](https://owasp.org/www-community/attacks/Content_Spoofing) | ✅ **Covered** | Same gate; `match_origin_as_fallback` already injects there |
| 3 | Scam inside a full-viewport iframe (nested framing) | [OWASP Clickjacking (UI redress)](https://owasp.org/www-community/attacks/Clickjacking), [OWASP Cross Frame Scripting](https://owasp.org/www-community/attacks/Cross_Frame_Scripting), [WSTG-CLNT-09](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/09-Testing_for_Clickjacking) | ✅ **Covered** | `all_frames` + top-tab action |
| 4 | Extra trap layers: fullscreen, keyboard/pointer lock, history flood, dialog loops | [OWASP Abuse of Functionality](https://owasp.org/www-community/attacks/Abuse_of_Functionality) | ✅ **Covered** | More wrappers in `hooks.js` (§8) |
| 5 | **ClickFix**: page writes a shell command to the clipboard and tells the user to paste it into Win+R / a terminal | [MITRE ATT&CK T1204.004](https://attack.mitre.org/techniques/T1204/004/) (no dedicated OWASP entry; closest is [Abuse of Functionality](https://owasp.org/www-community/attacks/Abuse_of_Functionality)) | ✅ **Covered (extra)** | Event-triggered hook, zero cost until a page writes to the clipboard (§12.2) |
| 6 | Scam popups re-spawned via `window.open` chains / opener abuse | [OWASP Reverse Tabnabbing](https://owasp.org/www-community/attacks/Reverse_Tabnabbing) | 🟡 **Partial** | We close children of a flagged tab; we don't police opener rewrites in general |
| 7 | Canvas/image-only scam text (no DOM text) | [OWASP Content Spoofing](https://owasp.org/www-community/attacks/Content_Spoofing) | 🟡 **Partial** | Trap-only WARN banner; full detection needs OCR |
| 8 | Browser-in-the-Browser: fake browser/OS window with a spoofed address bar on a normal `https` page | [OWASP Clickjacking (UI redress)](https://owasp.org/www-community/attacks/Clickjacking), [OWASP Content Spoofing](https://owasp.org/www-community/attacks/Content_Spoofing) | ⛔ **Out of scope (documented)** | Lives on normal URLs, so detection means DOM analysis on every page, which conflicts with the performance requirement. Legit OAuth modals look similar (FP risk). Future: analyze only after fullscreen or a trap fires |
| 9 | Service-worker-synthesized content on a normal-looking URL | [OWASP Man-in-the-browser](https://owasp.org/www-community/attacks/Man-in-the-browser_attack) (adjacent: content altered inside the browser, below the URL bar) | ⛔ **Out of scope (documented)** | Hard to tell apart from legit offline PWAs without heavy per-page analysis |
| 10 | Scam on a plain `https` URL with no URL-less trick | [OWASP Content Spoofing](https://owasp.org/www-community/attacks/Content_Spoofing) | ⛔ **Out of scope** | That's the job of URL reputation / Safe Browsing, which the assignment says this attack evades |

### 12.2 ClickFix design (the headline extra)

**Why it's worth it:** it's the same intent as the lock screen (pressure the user into a dangerous action) through a different channel. MITRE added a dedicated sub-technique for it, T1204.004, because it became so common. Like our main attack, it gives URL scanners nothing to inspect, because no file is downloaded and no malicious link is followed.

**Detection (MAIN world, every page, but event-triggered):**
- Wrap `navigator.clipboard.writeText`, `navigator.clipboard.write`, and listen for `copy` events where the page calls `clipboardData.setData` (covers `document.execCommand('copy')` too).
- The wrappers do nothing until called, so normal browsing costs nothing. This is the one feature that runs outside the `blob:` gate, deliberately, because it only acts on an event.
- Score the **payload**: command-shaped strings (`powershell`, `pwsh`, `-enc`, `iex`, `mshta`, `rundll32`, `cmd /c`, `curl … | sh`, `bash -c`, base64 blobs) plus length > 50 chars.
- Score the **page text**: instructions like "press Win+R", "Windows key + R", "paste into terminal/PowerShell", "Ctrl+V then Enter", fake CAPTCHA / "verify you are human".
- Rule: command-shaped payload **and** paste-instruction text → ClickFix. A payload alone isn't enough, because dev docs legitimately offer "copy" buttons for shell commands. That's the FP we must avoid, and it's one more benign fixture for §11 (a docs page with a copy-to-clipboard install command).

**Response:** block the write (the wrapper doesn't call the original), or overwrite the clipboard with a harmless warning string. Show an in-page banner explaining that a website tried to make you run a command, and notify the background. No navigation is needed; the page itself isn't trapping the user.

**Eval fixtures to add:** `clickfix-fake-captcha.html` (expected `CLICKFIX`), `clickfix-silent-copy.html` (copies on any click, expected `CLICKFIX`), `docs-install-command.html` (benign copy button, expected `CLEAN`).

### 12.3 Securing the extension itself

A security extension with `<all_urls>` is an attractive target. We follow the [OWASP Browser Extension Vulnerabilities Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Browser_Extension_Vulnerabilities_Cheat_Sheet.html):
- **Least privilege:** only `webNavigation`, `scripting`, `tabs`, and `storage` (used solely for the in-memory `storage.session` verdict log). No network, no remote code.
- **No data leakage:** no telemetry, and URLs are never sent anywhere (also an assignment requirement).
- **Untrusted page input:** MAIN-world messages are treated as untrusted, and only *additive suspicious* signals are accepted (§5). Page text is only regex-matched, never injected via `innerHTML`.
- **Isolated UI:** warnings live on the extension's own `blocked.html`, not in the page DOM where the page could restyle or hide them. In-page banners (WARN, ClickFix) are secondary and use a closed shadow root. The cheat sheet notes this isn't bulletproof, so the background also shows the blocked page on SCAM.
- **Strict CSP** in the manifest for extension pages, with no inline scripts in `blocked.html`.

### 12.4 Reference list

- OWASP: [Content Spoofing](https://owasp.org/www-community/attacks/Content_Spoofing) · [Abuse of Functionality](https://owasp.org/www-community/attacks/Abuse_of_Functionality) · [Clickjacking](https://owasp.org/www-community/attacks/Clickjacking) · [Cross Frame Scripting](https://owasp.org/www-community/attacks/Cross_Frame_Scripting) · [Reverse Tabnabbing](https://owasp.org/www-community/attacks/Reverse_Tabnabbing) · [Man-in-the-browser attack](https://owasp.org/www-community/attacks/Man-in-the-browser_attack) · [WSTG-CLNT-09 Testing for Clickjacking](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/09-Testing_for_Clickjacking) · [Browser Extension Vulnerabilities Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Browser_Extension_Vulnerabilities_Cheat_Sheet.html)
- MITRE ATT&CK: [T1204.004 User Execution: Malicious Copy and Paste (ClickFix)](https://attack.mitre.org/techniques/T1204/004/)

---

## 13. Implementation notes — what changed while building it

The eval drove these changes. Each was a real bug or a design flaw that the corpus caught:

1. **A shared file can't be listed in both a MAIN-world and an isolated-world content script.** The first build listed `signals.js` in both entries, and Chrome injected it only once per frame. The isolated detector then never ran, and the whole malicious corpus came back as false negatives. The fix is also a security win: **no scoring logic lives in the page's world any more.** `hooks.js` asks the isolated detector synchronously through a CustomEvent round trip whenever a clipboard write happens. A page can forge replies, but only "block" is ever honoured, so forging can't unblock anything.
2. **Never fall back from `innerText` to `textContent`.** The canvas-only fixture rendered no text, so `innerText` was empty and the code fell back to `textContent`. That read the page's `<script>` source and produced a SCAM verdict from strings the user never sees. The detector now uses rendered text only, and the fixture correctly lands on WARN.
3. **Repo layout:** the extension lives in `extension/`, so the folder you load unpacked contains only extension files. The eval lives in `eval/`.
4. **`storage` permission** was added for `chrome.storage.session`, the in-memory verdict log the eval reads. Nothing is persisted to disk or sent anywhere.
5. **Navigation context (A):** a same-tab commit of a `blob:`/`data:` URL coming from a normal page, in a tab not opened by `window.open`, not typed and not back/forward, counts as a script redirect. It doesn't rely only on the `client_redirect` qualifier, which Chrome doesn't set consistently for script navigations. That qualifier is still recorded in the verdict log.
6. **Late install:** besides `onInstalled`, the service worker scans open `blob:`/`data:` tabs every time it starts, which also covers the extension being re-enabled. The eval simulates install-while-open by disabling the extension through `chrome.management`, loading the scam, then re-enabling it.
7. **Escape-key probe threshold:** a page must cancel at least 2 distinct escape combinations. The code-editor fixture cancels Ctrl+W and Cmd+W, so B reaches 5, but with no scam content it stays CLEAN. That's the case the agreement rule exists for.
