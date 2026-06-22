// GuardPrompt Content Script
// Injected into supported AI chat pages

(function () {
  "use strict";
  console.log("GuardPrompt content script loaded ✓");

  const RULES = [
    { id: "email", label: "Email Address", category: "identity", severity: "high", pattern: /\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b/g, placeholder: "[EMAIL]" },
    { id: "phone_in", label: "Phone (India)", category: "identity", severity: "high", pattern: /(?<!\d)(\+91[\s\-]?)?[6-9]\d{4}[\s\-]?\d{5}(?!\d)/g, placeholder: "[PHONE]" },
    { id: "phone_intl", label: "Phone (International)", category: "identity", severity: "high", pattern: /(?<!\d)\+?1?[\s.\-]?\(?\d{3}\)?[\s.\-]?\d{3}[\s.\-]?\d{4}(?!\d)/g, placeholder: "[PHONE]" },
    { id: "aadhaar", label: "Aadhaar Number", category: "gov_id", severity: "critical", pattern: /(?<!\d[\s\-]?)\b[2-9]{1}\d{3}[\s\-]?\d{4}[\s\-]?\d{4}\b(?![\s\-]?\d)/g, placeholder: "[AADHAAR]" },
    { id: "pan", label: "PAN Number", category: "gov_id", severity: "critical", pattern: /\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b/g, placeholder: "[PAN]" },
    { id: "credit_card", label: "Credit/Debit Card", category: "financial", severity: "critical", pattern: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b/g, placeholder: "[CARD_NUMBER]" },
    { id: "ifsc", label: "IFSC Code", category: "financial", severity: "medium", pattern: /\b[A-Z]{4}0[A-Z0-9]{6}\b/g, placeholder: "[IFSC]" },
    { id: "api_key_generic", label: "API Key / Token", category: "credentials", severity: "critical", pattern: /\b(?:sk|pk|api|key|token|secret|bearer)[-_]?[a-zA-Z0-9]{16,}\b/gi, placeholder: "[API_KEY]" },
    { id: "aws_key", label: "AWS Access Key", category: "credentials", severity: "critical", pattern: /\bAKIA[0-9A-Z]{16}\b/g, placeholder: "[AWS_KEY]" },
    { id: "jwt", label: "JWT Token", category: "credentials", severity: "critical", pattern: /\beyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\b/g, placeholder: "[JWT_TOKEN]" },
    { id: "password_inline", label: "Inline Password", category: "credentials", severity: "critical", pattern: /(?:password|passwd|pwd)\s*[:=]\s*\S+/gi, placeholder: "[PASSWORD]" },
    { id: "ipv4", label: "IP Address", category: "network", severity: "medium", pattern: /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g, placeholder: "[IP_ADDRESS]" },
  ];

  function scanText(text, customRules = []) {
    const allRules = [...RULES, ...customRules];
    const findings = [];
    const seen = new Set();
    for (const rule of allRules) {
      const re = new RegExp(rule.pattern.source, rule.pattern.flags);
      let m;
      while ((m = re.exec(text)) !== null) {
        const key = `${m.index}-${m[0]}`;
        if (seen.has(key)) continue;
        seen.add(key);
        if (rule.id === "ipv4") {
          const ip = m[0];
          if (ip.startsWith("127.") || ip.startsWith("10.") || ip.startsWith("192.168.") || /^172\.(1[6-9]|2\d|3[01])\./.test(ip)) continue;
        }
        findings.push({ ruleId: rule.id, label: rule.label, category: rule.category, severity: rule.severity, match: m[0], start: m.index, end: m.index + m[0].length, placeholder: rule.placeholder });
      }
    }
    findings.sort((a, b) => a.start - b.start);
    return findings;
  }

  function redactFindings(text, findings) {
    let result = "", cursor = 0;
    for (const f of findings) {
      result += text.slice(cursor, f.start) + f.placeholder;
      cursor = f.end;
    }
    return result + text.slice(cursor);
  }

  let settings = { enabled: true, autoRedact: false, customKeywords: [] };

  chrome.storage.sync.get(["enabled", "autoRedact", "customKeywords"], (res) => {
    if (res.enabled !== undefined) settings.enabled = res.enabled;
    if (res.autoRedact !== undefined) settings.autoRedact = res.autoRedact;
    if (res.customKeywords) settings.customKeywords = res.customKeywords;
  });

  chrome.storage.onChanged.addListener((changes) => {
    if (changes.enabled) settings.enabled = changes.enabled.newValue;
    if (changes.autoRedact) settings.autoRedact = changes.autoRedact.newValue;
    if (changes.customKeywords) settings.customKeywords = changes.customKeywords.newValue;
  });

  function buildCustomRules(keywords) {
    return keywords.map((kw) => ({
      id: `custom_${kw}`,
      label: `Custom: ${kw}`,
      category: "custom",
      severity: "high",
      pattern: new RegExp(`\\b${escapeRegExp(kw)}\\b`, "gi"),
      placeholder: `[${kw.toUpperCase()}]`,
    }));
  }

  function escapeRegExp(str) {
    return str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  }

  const INPUT_SELECTORS = [
    '[data-testid="chat-input"]',
    '#prompt-textarea',
    'div[contenteditable="true"]',
    'textarea[data-id="root"]',
    "rich-textarea .ql-editor",
    'textarea[placeholder*="message" i]',
    'textarea[placeholder*="ask" i]',
    'textarea[placeholder*="prompt" i]',
    '[role="textbox"]',
  ];

  let overlayEl = null;
  let pendingInput = null;
  let pendingText = "";
  let pendingFindings = [];
  let findingCheckboxes = {};
  let cachedInputText = ""; // KEY FIX: cache text on input — ProseMirror clears DOM at keydown

  function getInputText(el) {
    // For contenteditable (ProseMirror/Tiptap), always use the cache
    if (el.getAttribute("contenteditable")) {
      return cachedInputText || el.innerText || el.textContent || "";
    }
    return el.tagName === "TEXTAREA" ? el.value : el.innerText || el.textContent || "";
  }

  function setInputText(el, text) {
    if (el.tagName === "TEXTAREA") {
      const nativeInputValueSetter = Object.getOwnPropertyDescriptor(window.HTMLTextAreaElement.prototype, "value").set;
      nativeInputValueSetter.call(el, text);
      el.dispatchEvent(new Event("input", { bubbles: true }));
    } else {
      el.innerText = text;
      el.dispatchEvent(new Event("input", { bubbles: true }));
      const range = document.createRange();
      range.selectNodeContents(el);
      range.collapse(false);
      const sel = window.getSelection();
      sel.removeAllRanges();
      sel.addRange(range);
    }
  }

  function handleSubmitAttempt(inputEl) {
    if (!settings.enabled) return true;
    const text = getInputText(inputEl);
    if (!text || !text.trim()) return true;

    const customRules = buildCustomRules(settings.customKeywords || []);
    const findings = scanText(text, customRules);
    if (findings.length === 0) return true;

    if (settings.autoRedact) {
      const redacted = redactFindings(text, findings);
      setInputText(inputEl, redacted);
      logToSession(findings, text);
      return true;
    }

    pendingInput = inputEl;
    pendingText = text;
    pendingFindings = findings;
    showOverlay(text, findings);
    return false;
  }

  const SEVERITY_COLOR = { critical: "#ef4444", high: "#f97316", medium: "#eab308", low: "#22c55e" };

  function highlightText(text, findings) {
    let html = "", cursor = 0;
    for (const f of findings) {
      html += escapeHtml(text.slice(cursor, f.start));
      html += `<mark class="gp-mark gp-mark--${f.severity}" title="${f.label}">${escapeHtml(f.match)}</mark>`;
      cursor = f.end;
    }
    html += escapeHtml(text.slice(cursor));
    return html;
  }

  function escapeHtml(str) {
    return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/\n/g, "<br>");
  }

  function groupByCategory(findings) {
    const groups = {};
    for (const f of findings) {
      if (!groups[f.category]) groups[f.category] = [];
      groups[f.category].push(f);
    }
    return groups;
  }

  const CATEGORY_LABELS = {
    identity: "Identity & Contact",
    gov_id: "Government IDs",
    financial: "Financial",
    credentials: "Credentials & Secrets",
    network: "Network / Infrastructure",
    custom: "Custom Keywords",
  };

  function showOverlay(text, findings) {
    removeOverlay();
    const backdrop = document.createElement("div");
    backdrop.id = "gp-backdrop";
    const panel = document.createElement("div");
    panel.id = "gp-panel";
    const groups = groupByCategory(findings);
    findingCheckboxes = {};
    let checklistHTML = "";
    for (const [cat, items] of Object.entries(groups)) {
      const label = CATEGORY_LABELS[cat] || cat;
      checklistHTML += `<div class="gp-cat-label">${label}</div>`;
      const seen = new Set();
      for (const f of items) {
        const uid = `${f.ruleId}::${f.match}`;
        if (seen.has(uid)) continue;
        seen.add(uid);
        const count = findings.filter((x) => x.ruleId === f.ruleId && x.match === f.match).length;
        checklistHTML += `
          <label class="gp-finding-row">
            <input type="checkbox" class="gp-cb" data-uid="${uid}" checked />
            <span class="gp-severity-dot" style="background:${SEVERITY_COLOR[f.severity]}"></span>
            <span class="gp-finding-label">${f.label}</span>
            <code class="gp-finding-match">${escapeHtml(f.match.length > 40 ? f.match.slice(0, 37) + "…" : f.match)}</code>
            ${count > 1 ? `<span class="gp-count">×${count}</span>` : ""}
          </label>`;
      }
    }
    panel.innerHTML = `
      <div class="gp-header">
        <div class="gp-header-left">
          <span class="gp-shield">🛡️</span>
          <div>
            <div class="gp-title">GuardPrompt</div>
            <div class="gp-subtitle">Sensitive data detected before sending</div>
          </div>
        </div>
        <button class="gp-close" id="gp-close-btn">✕</button>
      </div>
      <div class="gp-preview-label">Your message (highlighted):</div>
      <div class="gp-preview" id="gp-preview">${highlightText(text, findings)}</div>
      <div class="gp-findings-label">
        Found <strong>${findings.length}</strong> item${findings.length > 1 ? "s" : ""} — select which to redact:
      </div>
      <div class="gp-checklist" id="gp-checklist">${checklistHTML}</div>
      <div class="gp-actions">
        <button class="gp-btn gp-btn--secondary" id="gp-send-anyway">Send Unmodified</button>
        <button class="gp-btn gp-btn--primary" id="gp-redact-send">Redact &amp; Send</button>
      </div>
      <div class="gp-footer">All processing is local. No data is sent to GuardPrompt servers.</div>
    `;
    backdrop.appendChild(panel);
    document.body.appendChild(backdrop);
    overlayEl = backdrop;
    document.getElementById("gp-close-btn").addEventListener("click", removeOverlay);
    backdrop.addEventListener("click", (e) => { if (e.target === backdrop) removeOverlay(); });
    document.getElementById("gp-send-anyway").addEventListener("click", () => {
      removeOverlay();
      submitInput(pendingInput);
    });
    document.getElementById("gp-redact-send").addEventListener("click", () => {
      const checked = [...document.querySelectorAll(".gp-cb:checked")].map((cb) => cb.dataset.uid);
      const toRedact = pendingFindings.filter((f) => checked.includes(`${f.ruleId}::${f.match}`));
      const redacted = redactFindings(pendingText, toRedact);
      setInputText(pendingInput, redacted);
      logToSession(toRedact, pendingText);
      removeOverlay();
      setTimeout(() => submitInput(pendingInput), 80);
    });
    document.getElementById("gp-checklist").addEventListener("change", () => {
      const checked = [...document.querySelectorAll(".gp-cb:checked")].map((cb) => cb.dataset.uid);
      const toHighlight = pendingFindings.filter((f) => checked.includes(`${f.ruleId}::${f.match}`));
      document.getElementById("gp-preview").innerHTML = highlightText(pendingText, toHighlight);
    });
  }

  function deduplicateFindings(findings) {
    const seen = new Set();
    return findings.filter((f) => {
      const k = `${f.ruleId}::${f.match}`;
      if (seen.has(k)) return false;
      seen.add(k);
      return true;
    });
  }

  function removeOverlay() {
    if (overlayEl) { overlayEl.remove(); overlayEl = null; }
  }

  function submitInput(el) {
    if (!el) return;
    const container = el.closest("form") || el.parentElement?.parentElement?.parentElement;
    if (container) {
      const btn = container.querySelector('button[type="submit"], button[aria-label*="send" i], button[data-testid*="send" i]');
      if (btn) { btn.click(); return; }
    }
    el.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", code: "Enter", keyCode: 13, bubbles: true, cancelable: true }));
  }

  function logToSession(findings, originalText) {
    if (!chrome?.storage?.local) return;
    chrome.storage.local.get(["sessionLog"], (res) => {
      const log = res.sessionLog || [];
      log.push({
        ts: new Date().toISOString(),
        url: location.hostname,
        count: findings.length,
        types: [...new Set(findings.map((f) => f.label))],
        snippet: originalText.slice(0, 60) + (originalText.length > 60 ? "…" : ""),
      });
      chrome.storage.local.set({ sessionLog: log.slice(-200) });
    });
  }

  function attachKeyboardIntercept(el) {
    if (el.dataset.gpAttached) return;
    el.dataset.gpAttached = "1";

    // Cache text on every input event
    el.addEventListener("input", () => {
      cachedInputText = el.innerText || el.textContent || "";
    });

    // Intercept at document level with capture — fires before site listeners
    document.addEventListener("keydown", (e) => {
      if (e.key !== "Enter" || e.shiftKey) return;
      if (document.activeElement !== el) return;
      
      const allowed = handleSubmitAttempt(el);
      if (!allowed) {
        e.preventDefault();
        e.stopImmediatePropagation();
        e.stopPropagation();
      }
    }, true);
  }

  function attachButtonIntercept(sendBtn, inputEl) {
    if (sendBtn.dataset.gpBtnAttached) return;
    sendBtn.dataset.gpBtnAttached = "1";
    sendBtn.addEventListener("click", (e) => {
      const allowed = handleSubmitAttempt(inputEl);
      if (!allowed) {
        e.preventDefault();
        e.stopImmediatePropagation();
      }
    }, true);
  }

  function findAndAttach() {
    for (const selector of INPUT_SELECTORS) {
      document.querySelectorAll(selector).forEach((el) => {
        attachKeyboardIntercept(el);

        // Search broadly for send button — check parent, grandparent, great-grandparent
        let container = el.parentElement;
        for (let i = 0; i < 6; i++) {
          if (!container) break;
          const sendBtn = container.querySelector(
            'button[type="submit"], button[aria-label*="send" i], button[data-testid*="send" i], button[aria-label*="Send" i]'
          );
          if (sendBtn) {
            attachButtonIntercept(sendBtn, el);
            break;
          }
          container = container.parentElement;
        }
      });
    }
  }

  const observer = new MutationObserver(findAndAttach);
  observer.observe(document.body, { childList: true, subtree: true });
  findAndAttach();

})();