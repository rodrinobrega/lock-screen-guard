/*
 * signals.js — pure scoring functions shared by the content scripts,
 * the MAIN-world hooks and the Node unit tests. No DOM, no chrome.* here.
 *
 * Three signal families (see plan.md §2):
 *   A = navigation context  (how did we get to this URL-less document?)
 *   B = trap behaviour      (is the page blocking the user's escape routes?)
 *   C = content             (does it look like a fake OS / support lock screen?)
 * Plus a separate ClickFix check (plan.md §12.2).
 */
(function (root) {
  'use strict';

  // ---------------------------------------------------------------------------
  // Text normalisation: defeats cheap obfuscation (zero-width chars, fullwidth
  // digits, non-breaking hyphens, NBSP) before any regex runs.
  // ---------------------------------------------------------------------------
  const ZERO_WIDTH = /[​-‍⁠﻿­]/g;
  const DASHES = /[‐-―−﹘﹣－]/g;

  function normalizeText(text) {
    if (!text) return '';
    return String(text)
      .normalize('NFKC')          // fullwidth digits/letters -> ASCII
      .replace(ZERO_WIDTH, '')
      .replace(DASHES, '-')
      .replace(/\s+/g, ' ')
      .trim()
      .slice(0, 20000);           // cap work on huge pages
  }

  // ---------------------------------------------------------------------------
  // Family C — content
  // ---------------------------------------------------------------------------
  const SEP = '[\\s.\\-()]*';
  const CONTENT_RULES = [
    {
      id: 'lockWording',
      weight: 2,
      // noun first, then the state: "your computer has been locked"
      re: /\b(computer|device|pc|mac|system|browser|windows)\b.{0,30}?\b(locked|blocked|infected|compromised|suspended|disabled|hacked)\b/i,
    },
    {
      id: 'vendorImpersonation',
      weight: 2,
      re: /\b(microsoft|windows|apple|mac ?os|icloud|google|norton|mcafee)\b.{0,15}?\b(support|defender|security|technician|help ?desk|firewall|helpline)\b/i,
    },
    {
      id: 'supportPhone',
      weight: 2,
      // US/CA toll-free, or any international "+CC ..." number
      re: new RegExp(
        '(?:\\+?1' + SEP + ')?\\(?8(?:00|33|44|55|66|77|88)\\)?' + SEP + '\\d{3}' + SEP + '\\d{4}' +
        '|\\+\\d{1,3}' + SEP + '(?:\\d' + SEP + '){7,12}\\d'
      ),
    },
    {
      id: 'urgency',
      weight: 1,
      re: /do not (restart|shut ?down|turn off|close|ignore)|call (now|immediately|right away)|\bimmediately\b|toll[- ]free/i,
    },
    {
      id: 'fakeErrorCode',
      weight: 1,
      re: /error\s*(code)?\s*[:#]?\s*0x[0-9a-f]{6,8}/i,
    },
  ];

  /**
   * @param {string} rawText  visible page text (title + body)
   * @param {{systemColor?: boolean}} visual  computed by the detector
   * @returns {{score:number, hits:string[]}}
   */
  function scoreContent(rawText, visual) {
    const text = normalizeText(rawText);
    const hits = [];
    let score = 0;
    for (const rule of CONTENT_RULES) {
      if (rule.re.test(text)) {
        hits.push(rule.id);
        score += rule.weight;
      }
    }
    if (visual && visual.systemColor && score > 0) {
      // full-screen BSOD-blue / black background only counts as
      // corroboration, never on its own (lots of pages are dark)
      hits.push('systemColor');
      score += 1;
    }
    return { score, hits };
  }

  // ---------------------------------------------------------------------------
  // Family B — traps
  // ---------------------------------------------------------------------------
  const TRAP_WEIGHTS = {
    escapeKeys: 3,    // F5 / F11 / F12 / Esc / Ctrl+W|R|L cancelled
    beforeunload: 2,  // unload cancelled
    contextmenu: 1,   // right-click cancelled
    lockApis: 3,      // fullscreen / keyboard.lock / pointer lock without a gesture
    historyFlood: 2,  // pushState spam to poison Back
    dialogLoop: 2,    // alert/confirm loop
  };

  /** @param {Record<string, boolean>} t  @returns {{score:number, hits:string[]}} */
  function scoreTraps(t) {
    const hits = [];
    let score = 0;
    for (const [k, w] of Object.entries(TRAP_WEIGHTS)) {
      if (t && t[k]) { hits.push(k); score += w; }
    }
    return { score, hits };
  }

  // ---------------------------------------------------------------------------
  // Family A — navigation context (facts come from the background worker)
  // ---------------------------------------------------------------------------
  /**
   * @param {{scriptRedirect?:boolean, fast?:boolean, userOpenedTab?:boolean}} ctx
   */
  function scoreContext(ctx) {
    const hits = [];
    let score = 0;
    if (!ctx || ctx.userOpenedTab) return { score, hits };
    if (ctx.scriptRedirect) { hits.push('sameTabScriptRedirect'); score += 2; }
    if (ctx.scriptRedirect && ctx.fast) { hits.push('fastRedirect'); score += 1; }
    return { score, hits };
  }

  // ---------------------------------------------------------------------------
  // Decision
  // ---------------------------------------------------------------------------
  const THRESHOLDS = { content: 4, traps: 3, context: 2, trapsOnly: 6 };

  /** @returns {'SCAM'|'WARN'|'CLEAN'} */
  function decide({ A, B, C }) {
    if (C >= THRESHOLDS.content && (B >= THRESHOLDS.traps || A >= THRESHOLDS.context)) return 'SCAM';
    if (B >= THRESHOLDS.trapsOnly && C < THRESHOLDS.content) return 'WARN';
    return 'CLEAN';
  }

  const SEVERITY = { CLEAN: 0, WARN: 1, SCAM: 2, CLICKFIX: 2 };

  // ---------------------------------------------------------------------------
  // ClickFix (MITRE ATT&CK T1204.004) — command written to the clipboard plus
  // a lure telling the user to paste it into Run / a terminal.
  // ---------------------------------------------------------------------------
  const COMMAND_RULES = [
    /\b(powershell|pwsh)(\.exe)?\b/i,
    /\b(mshta|rundll32|regsvr32|certutil|bitsadmin|wscript|cscript|msiexec)(\.exe)?\b/i,
    /\bcmd(\.exe)?\s+\/[ck]\b/i,
    /\b(iex|invoke-expression|invoke-webrequest|iwr|irm|invoke-restmethod|start-process|frombase64string)\b/i,
    /\s-(e|en|enc|encodedcommand)\s+[A-Za-z0-9+/=]{16,}/i,
    /\b(curl|wget)\b[^|\n]{0,300}\|\s*(sudo\s+)?(ba|z|da)?sh\b/i,
    /\bbash\s+-c\b|\bosascript\b|\bbase64\s+(-d|--decode)\b/i,
  ];
  const OBFUSCATION = /-w(indowstyle)?\s+h(idden)?\b|-enc(odedcommand)?\b|frombase64string|\^[a-z]|`[a-z]|[A-Za-z0-9+/]{60,}={0,2}/i;

  const LURE_RULES = [
    { id: 'runDialog', re: /\b(win(dows)?(\s*key)?\s*\+\s*r|windows\s+key\s+and\s+r|run\s+dialog|press\s+win\b)/i },
    { id: 'fakeCaptcha', re: /\b(verify (that )?(you are|you'?re) (a )?human|i'?m not a robot|human verification|verification (step|steps|code)|complete the captcha)\b/i },
    { id: 'fixError', re: /\b(to fix (this|the) (error|issue|problem)|fix it\b|how to fix)\b/i },
  ];
  const PASTE_INSTRUCTION = /\b(ctrl\s*\+\s*v|cmd\s*\+\s*v|paste\b.{0,60}\b(terminal|powershell|command prompt|cmd|run|console|address bar)|open (powershell|terminal|command prompt|the run))/i;

  function isCommandShaped(payload) {
    const p = normalizeText(payload);
    if (p.length < 12) return false;
    return COMMAND_RULES.some((re) => re.test(p));
  }

  /**
   * @param {string} payload    what the page tried to put on the clipboard
   * @param {string} pageText   visible page text (innerText)
   * @returns {{clickfix:boolean, hits:string[]}}
   */
  function scoreClickFix(payload, pageText) {
    const hits = [];
    const p = normalizeText(payload);
    const text = normalizeText(pageText);
    if (!isCommandShaped(p)) return { clickfix: false, hits };
    hits.push('commandPayload');

    const lures = LURE_RULES.filter((r) => r.re.test(text)).map((r) => r.id);
    hits.push(...lures);
    const paste = PASTE_INSTRUCTION.test(text);
    if (paste) hits.push('pasteInstruction');
    // Docs pages show the exact command they copy; ClickFix hides it.
    const hidden = !text.includes(p.slice(0, 40));
    if (hidden) hits.push('hiddenPayload');
    const obfuscated = OBFUSCATION.test(p);
    if (obfuscated) hits.push('obfuscated');

    const lure = lures.length > 0;
    const clickfix = (lure && (paste || hidden || obfuscated)) || (hidden && paste);
    return { clickfix, hits };
  }

  const api = {
    normalizeText,
    scoreContent,
    scoreTraps,
    scoreContext,
    decide,
    scoreClickFix,
    isCommandShaped,
    SEVERITY,
    THRESHOLDS,
    TRAP_WEIGHTS,
  };

  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.LSG = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
