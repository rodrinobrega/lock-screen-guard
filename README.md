# Lock-Screen Guard

A Chrome (Manifest V3) extension that detects fake "your computer is locked — call Microsoft Support" scam pages rendered from `blob:` / `data:` URLs, and gets the user out of them. It leaves legitimate uses of the same mechanism, such as in-browser report previews, untouched.

It also blocks **ClickFix** clipboard lures ([MITRE T1204.004](https://attack.mitre.org/techniques/T1204/004/)).

- **[NOTE.md](NOTE.md)** — the short write-up: how it detects, why, and its false-positive / false-negative risks.
- **[plan.md](plan.md)** — the full design, eval methodology and OWASP threat map.

## Load it

1. Open `chrome://extensions` and turn on **Developer mode**.
2. Click **Load unpacked** and pick the `extension/` folder.
3. Serve the samples over HTTP, for example `npx http-server samples -p 8080`, and open:
   - `http://localhost:8080/malicious.html` — the tab is replaced by the extension's "We stopped a fake 'computer locked' page" screen.
   - `http://localhost:8080/benign.html` — click the button; the report opens normally.

To open the samples from `file://`, enable "Allow access to file URLs" for the extension.

## How it works (one screen)

```
any page ──► gate: blob: / data: / framed about:? ── no ──► do nothing (ClickFix hooks stay dormant)
                     │ yes
                     ▼
     A  navigation context    same-tab script redirect, no click     (background, webNavigation)
     B  trap behaviour        probes + MAIN-world hooks: escape keys, unload, right-click,
                              fullscreen/keyboard/pointer lock, history flood, dialog loop
     C  scam content          lock wording, vendor impersonation, phone, urgency, error code,
                              system colour (text normalised: zero-width, fullwidth digits)
                     ▼
     SCAM  if C ≥ 4 and (B ≥ 3 or A ≥ 2) → defuse handlers, wipe DOM, tab → blocked.html
     WARN  if B ≥ 6 and C < 4           → dismissible banner with "Leave page"
     CLEAN otherwise                     → nothing
```

| File | Role |
|---|---|
| `extension/manifest.json` | MV3 manifest. `match_origin_as_fallback` lets the content scripts run inside `blob:`, `data:` and `about:` documents |
| `extension/content/hooks.js` | MAIN world, `document_start`. Registers capture listeners before the page (used to defuse), records lock APIs, history and dialog abuse, and wraps clipboard writes. Contains no scoring logic |
| `extension/content/detector.js` | Isolated world. Gate, probes, content scoring, decision, response, banners |
| `extension/content/signals.js` | Pure scoring functions, shared with the unit tests |
| `extension/background.js` | Navigation context, verdict handling, navigates the tab away, injects into tabs that were already open |
| `extension/blocked.html` | The extension's own landing page. The scam can't script it, and it deliberately has no "Back" button |

## Verify it (built for AI agents and CI)

```bash
npm install                 # Playwright (uses an installed Chromium; else: npx playwright install chromium)
npm test                    # 14 unit tests on the scoring logic (node --test)
npm run eval                # 22 labelled fixtures in real headless Chromium → eval/report.json
npm run check               # both; non-zero exit on any mismatch
```

The eval loads the unpacked extension and opens each fixture. It reads the **extension's own verdict log** from `chrome.storage.session` rather than screenshotting the page, then checks the effect on the tab:
- **SCAM:** the tab ended on `blocked.html`.
- **Benign:** no action was taken.
- **ClickFix:** the clipboard no longer holds the payload.
- **Docs page:** the clipboard still holds the legitimate command.

| Set | Fixtures | What they stress |
|---|---|---|
| `malicious/` (11) | provided sample, delayed redirect, `data:` iframe, `srcdoc` + fullscreen, `about:blank` + `document.write`, history flood, obfuscated text, macOS variant, keys-only, **late install** (page open before the extension is enabled), canvas-only text (known gap, expects WARN) | false negatives |
| `benign/` (8) | provided sample, article *about* scams (content only), game (key capture), code editor (Ctrl+W + unsaved-changes guard), slideshow, PDF blob, same-tab auto export (context only), docs page with a copy-install-command button | false positives — each trips one family alone |
| `clickfix/` (3) | fake CAPTCHA + `writeText`, hidden textarea + `execCommand('copy')`, `copy`-event `setData` hijack | T1204.004 |
| `holdout/` | not committed; see [its README](eval/fixtures/holdout/README.md) | overfitting to the visible set |

Latest run: **22/22 passed, 0 false positives, 0 false negatives** (headless Chromium 141).

A green eval means "no known regression", not "proven safe". It only covers variations someone thought of, and a few real-Chrome behaviours, such as the actual `beforeunload` prompt and OS fullscreen, still deserve one manual pass.

## Privacy

There is no network access, no telemetry and no remote code. Verdicts live in `chrome.storage.session`, which is in memory and cleared when the browser closes. The only permissions are `webNavigation`, `scripting`, `tabs` and `storage`.
