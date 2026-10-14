# How Lock-Screen Guard detects the attack

**How it detects.** The extension only analyses documents that have no real URL (`blob:`, `data:`, and framed `about:blank` / `srcdoc`). On every other page it exits after a string comparison, so normal browsing costs nothing. Inside those documents it scores three independent signal families:

- **A — how we got here.** A same-tab script redirect into the blob with no click, versus a blob the user opened in a new tab (`webNavigation`).
- **B — escape blocking.** Synthetic, cancelable probe events (F5, Esc, F11, Ctrl+W, right-click, `beforeunload`) reveal whether the page cancels them. MAIN-world hooks also record fullscreen, keyboard or pointer lock without a gesture, `pushState` floods and dialog loops.
- **C — scam content.** "Computer locked" wording, OS-vendor impersonation, a support phone number, urgency, fake error codes and a full-screen system colour, all matched after normalising away zero-width characters and fullwidth digits.

A page is **blocked only when scam content coincides with trapping or with a no-gesture redirect** (C ≥ 4 and (B ≥ 3 or A ≥ 2)). Blocking means:
1. neutralising the page's handlers (our capture listeners were registered first),
2. exiting fullscreen and wiping the DOM,
3. navigating the tab to the extension's own `blocked.html`, with a close-and-reopen fallback.

Heavy trapping with unreadable content gives a dismissible **WARN** banner with a "Leave page" button instead of a block.

**Why.** The blob mechanism is legitimate (report previews, exports), so it can only be a *gate*, not a verdict. Each family alone has known false positives: content matches articles about scams, traps match games and editors, and same-tab blob redirects match export pages. The eval corpus contains one benign fixture for each of these single-family cases, and all of them stay clean. Requiring agreement keeps precision high, and probing works even when the detector is injected late, into a tab that was already open on the scam.

**False-positive risks.**
- A legitimate blob-rendered page that shows support-number-style text *and* blocks escape keys, such as a helpdesk kiosk preview.
- An article about scams that a site auto-opens in the same tab without a click.

**False-negative risks.**
- Text rendered in canvas or images. Content reads nothing, so trapping alone only reaches WARN; see the `canvas-only` fixture.
- Non-English or heavily paraphrased wording.
- Scams that set no traps and are opened by a click.
- Pages that detect synthetic probes via `event.isTrusted`. This is partially covered by the MAIN-world listener hooks.
- Scams hosted on a normal `https` URL, which is out of scope and belongs to URL reputation.
- A service worker restart (after about 30 s idle) loses the navigation-context map, so A drops to 0 for an already-open tab.

**Beyond the brief.**
- **Extra trapping layers:** fullscreen, pointer and keyboard lock, history flooding, dialog loops, and nested `data:` / `srcdoc` / `about:blank` frames.
- **Late install:** tabs already open when the extension is installed or enabled.
- **ClickFix clipboard lures** ([MITRE ATT&CK T1204.004](https://attack.mitre.org/techniques/T1204/004/)): a command written to the clipboard under a "press Win+R and paste" lure is replaced with a warning. Developer docs that show the exact command they copy are left alone.

**Threat classification.**
- The lock screen is [OWASP Content Spoofing](https://owasp.org/www-community/attacks/Content_Spoofing) delivered through [Abuse of Functionality](https://owasp.org/www-community/attacks/Abuse_of_Functionality).
- The framed variants overlap with [Clickjacking / UI redress](https://owasp.org/www-community/attacks/Clickjacking).
- The extension follows the [OWASP Browser Extension Vulnerabilities Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Browser_Extension_Vulnerabilities_Cheat_Sheet.html): least privilege, no network or telemetry, scoring kept out of the page's world, and an isolated blocked page.

The full threat map is in [plan.md §12](plan.md#12-threat-map-owasp-references-and-scope-boundaries).
