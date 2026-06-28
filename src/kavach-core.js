/**
 * kavach-core.js
 * PromptKavach — Core PII Detection and Redaction Engine
 *
 * Single source of truth for all pattern definitions, detection logic,
 * and redaction strategies. Zero browser APIs. Zero DOM. Zero side effects.
 * Runs identically in: Chrome extension, Firefox extension, Node.js,
 * Electron, Deno, Web Worker, and future WASM/mobile runtimes.
 *
 * Public API:
 *   detect(text, options?)  → Finding[]
 *   redact(text, findings, options?)  → RedactResult
 *   getRules()  → Rule[]
 *   getRule(id)  → Rule | undefined
 *
 * @version 1.0.0
 * @license MIT
 */

"use strict";

// ─────────────────────────────────────────────────────────────────────────────
// TYPE DEFINITIONS (JSDoc — no runtime cost)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * @typedef {Object} RuleMeta
 * Open bag — add any field here without touching core functions.
 * Core functions only read the required Rule fields above; they are
 * structurally blind to meta. New capabilities always land in meta first.
 *
 * @property {string}   [description]        Human-readable description of the PII type
 * @property {string}   [addedInVersion]     Semver when this rule was introduced
 * @property {Function} [filter]             Post-match filter: (matchStr) => boolean.
 *                                           Return false to discard the match.
 *                                           Used for: private IP exclusion, context checks, etc.
 * @property {Function} [fakeDataFn]         () => string  — generates structurally valid fake value.
 *                                           Used by synthetic redaction mode (Pro tier).
 * @property {string}   [defaultRedactMode]  "token" | "synthetic" | "generalise" | "suppress"
 *                                           Per-rule default. Falls back to "token" if absent.
 * @property {string}   [generalisedLabel]   Human text used in generalise mode.
 *                                           e.g. "a government ID number", "a mobile number"
 * @property {boolean}  [requiresContext]    If true, this rule needs surrounding text to confirm.
 *                                           Reserved for future NER integration.
 * @property {string[]} [tags]               Arbitrary string tags for filtering/grouping.
 */

/**
 * @typedef {Object} Rule
 * @property {string}   id          Stable unique identifier. Never rename after v1.0.
 * @property {string}   label       Human-readable display name shown in the overlay.
 * @property {string}   category    Grouping key: "identity"|"gov_id"|"financial"|"credentials"|"network"|"custom"
 * @property {string}   severity    "critical"|"high"|"medium"|"low"
 * @property {RegExp}   pattern     Compiled regex with the /g flag. Pre-compiled at module init.
 * @property {boolean}  enabled     If false, rule is skipped during detection. Toggled by user settings.
 * @property {string}   placeholder Token used in "token" redaction mode. e.g. "[AADHAAR]"
 * @property {RuleMeta} [meta]      Open extension bag. See RuleMeta typedef.
 */

/**
 * @typedef {Object} Finding
 * @property {string} ruleId     The id of the Rule that produced this finding.
 * @property {string} label      Human-readable label (copied from Rule for convenience).
 * @property {string} category   Category (copied from Rule for convenience).
 * @property {string} severity   Severity (copied from Rule for convenience).
 * @property {string} match      The exact matched string from the input text.
 * @property {number} start      Start index (inclusive) in the original text.
 * @property {number} end        End index (exclusive) in the original text.
 * @property {string} placeholder Token for this finding (copied from Rule).
 */

/**
 * @typedef {Object} RedactResult
 * @property {string}              redacted  The text with PII replaced.
 * @property {Map<string, string>} valueMap  Maps replacement token → original value.
 *                                           Used by the token round-trip feature to restore
 *                                           redacted values from AI responses.
 *                                           Key format: "[LABEL:N]" where N is occurrence index.
 */

/**
 * @typedef {Object} DetectOptions
 * @property {Rule[]}   [extraRules]      Additional rules (e.g. custom keyword rules) merged
 *                                        with the built-in registry for this call only.
 * @property {string[]} [disabledRuleIds] Override: disable specific rule IDs for this call.
 * @property {number}   [maxFindings]     Abort after this many findings (performance ceiling).
 *                                        Default: Infinity.
 */

/**
 * @typedef {Object} RedactOptions
 * @property {"token"|"synthetic"|"generalise"|"suppress"} [mode]
 *   Redaction strategy for this call. Overrides per-rule defaults.
 *   If omitted, each finding uses its rule's meta.defaultRedactMode, falling back to "token".
 * @property {Map<string, string>} [existingValueMap]
 *   Pass an existing valueMap to continue numbering tokens from a prior redact() call.
 *   Used when processing multi-part messages.
 */

// ─────────────────────────────────────────────────────────────────────────────
// PATTERN REGISTRY
// The single authoritative list of all PII rules.
//
// HOW TO ADD A NEW RULE:
//   1. Add one object to the RULES array below following the Rule typedef.
//   2. Set meta.addedInVersion to the next semver.
//   3. That is the entire change — no other file needs editing.
//
// HOW TO ADD A NEW FIELD:
//   Add it to rule.meta. Core functions will ignore it until you explicitly
//   read it. Existing functions never break.
// ─────────────────────────────────────────────────────────────────────────────

const RULES = [

  // ── Identity & Contact ─────────────────────────────────────────────────────

  {
    id: "email",
    label: "Email Address",
    category: "identity",
    severity: "high",
    pattern: /\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b/g,
    enabled: true,
    placeholder: "[EMAIL]",
    meta: {
      description: "Standard email address",
      addedInVersion: "1.0.0",
      defaultRedactMode: "token",
      generalisedLabel: "an email address",
    },
  },

  {
    id: "phone_in",
    label: "Phone Number (India)",
    category: "identity",
    severity: "high",
    // Handles: 9876543210 / +91 98765 43210 / +91-9876543210
    // Negative lookbehind prevents matching inside longer digit strings.
    pattern: /(?<!\d)(\+91[\s\-]?)?[6-9]\d{4}[\s\-]?\d{5}(?!\d)/g,
    enabled: true,
    placeholder: "[PHONE]",
    meta: {
      description: "Indian mobile number with optional +91 prefix and spacing",
      addedInVersion: "1.0.0",
      defaultRedactMode: "token",
      generalisedLabel: "a mobile number",
      fakeDataFn: () => {
        const prefix = [6, 7, 8, 9][Math.floor(Math.random() * 4)];
        const rest = Math.floor(Math.random() * 900000000 + 100000000);
        return `+91 ${prefix}${rest}`.slice(0, 14);
      },
    },
  },

  {
    id: "phone_intl",
    label: "Phone Number (International)",
    category: "identity",
    severity: "high",
    pattern: /(?<!\d)\+?1?[\s.\-]?\(?\d{3}\)?[\s.\-]?\d{3}[\s.\-]?\d{4}(?!\d)/g,
    enabled: true,
    placeholder: "[PHONE]",
    meta: {
      description: "International phone number in common formats",
      addedInVersion: "1.0.0",
      defaultRedactMode: "token",
      generalisedLabel: "a phone number",
    },
  },

  {
    id: "dob",
    label: "Date of Birth",
    category: "identity",
    severity: "medium",
    // Requires a label prefix (dob:, date of birth:, born on, birthdate:)
    // to avoid false-positives on general dates in conversation.
    pattern: /\b(?:dob|date of birth|born on|birthdate)[:\s]+\d{1,2}[\/\-\.]\d{1,2}[\/\-\.]\d{2,4}\b/gi,
    enabled: true,
    placeholder: "[DOB]",
    meta: {
      description: "Date of birth with labelled prefix",
      addedInVersion: "1.0.0",
      defaultRedactMode: "token",
      generalisedLabel: "a date of birth",
    },
  },

  // ── Indian Government IDs ──────────────────────────────────────────────────

  {
    id: "aadhaar",
    label: "Aadhaar Number",
    category: "gov_id",
    severity: "critical",
    // Matches: 2345 6789 0123 / 2345-6789-0123 / 234567890123
    // First digit 2–9 (UIDAI spec). Negative lookahead/behind to prevent
    // false-positive against 16-digit credit card numbers.
    pattern: /(?<!\d[\s\-]?)\b[2-9]{1}\d{3}[\s\-]?\d{4}[\s\-]?\d{4}\b(?![\s\-]?\d)/g,
    enabled: true,
    placeholder: "[AADHAAR]",
    meta: {
      description: "12-digit UIDAI Aadhaar number with optional spacing or hyphens",
      addedInVersion: "1.0.0",
      defaultRedactMode: "token",
      generalisedLabel: "an Aadhaar number",
      fakeDataFn: () => {
        // First digit 2–9, then 11 random digits
        const first = Math.floor(Math.random() * 8) + 2;
        const rest = String(Math.floor(Math.random() * 1e11)).padStart(11, "0");
        const n = `${first}${rest}`;
        return `${n.slice(0,4)} ${n.slice(4,8)} ${n.slice(8,12)}`;
      },
    },
  },

  {
    id: "pan",
    label: "PAN Number",
    category: "gov_id",
    severity: "critical",
    // Format: AAAAA9999A — 5 letters, 4 digits, 1 letter (all uppercase)
    pattern: /\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b/g,
    enabled: true,
    placeholder: "[PAN]",
    meta: {
      description: "Indian Permanent Account Number — 10-character alphanumeric",
      addedInVersion: "1.0.0",
      defaultRedactMode: "token",
      generalisedLabel: "a PAN number",
      fakeDataFn: () => {
        const letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        const rand = (n) => Array.from({length: n}, () => letters[Math.floor(Math.random() * 26)]).join("");
        const digits = String(Math.floor(Math.random() * 9000 + 1000));
        return `${rand(5)}${digits}${rand(1)}`;
      },
    },
  },

  {
    id: "passport",
    label: "Passport Number",
    category: "gov_id",
    severity: "critical",
    // Indian passport: 1 letter (A–Z, not Q/X/Z) + 7 digits
    pattern: /\b[A-PR-WY][1-9]\d\s?\d{4}[1-9]\b/g,
    enabled: true,
    placeholder: "[PASSPORT]",
    meta: {
      description: "Indian passport number — letter prefix followed by 7 digits",
      addedInVersion: "1.0.0",
      defaultRedactMode: "token",
      generalisedLabel: "a passport number",
    },
  },

  // Planned — patterns to be added in v1.1.0:
  // { id: "voter_id", label: "Voter ID", ... }
  // { id: "upi_id",   label: "UPI ID",   ... }
  // { id: "gst_no",   label: "GST Number", ... }

  // ── Financial ──────────────────────────────────────────────────────────────

  {
    id: "credit_card",
    label: "Credit / Debit Card Number",
    category: "financial",
    severity: "critical",
    // Covers: Visa, Mastercard, Amex, RuPay, JCB, Discover
    // detector.js version — broader than original content.js (adds RuPay + JCB)
    pattern: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b/g,
    enabled: true,
    placeholder: "[CARD_NUMBER]",
    meta: {
      description: "Credit and debit card numbers — Visa, MC, Amex, RuPay, JCB, Discover",
      addedInVersion: "1.0.0",
      defaultRedactMode: "suppress",   // never show even a fake card number
      generalisedLabel: "a card number",
    },
  },

  {
    id: "bank_account",
    label: "Bank Account Number",
    category: "financial",
    severity: "high",
    // Only fires when the number appears near banking keywords — reduces false positives
    // on general numbers. The lookbehind/ahead window is handled by context matching.
    pattern: /\b\d{9,18}\b(?=.*(?:account|acc|bank|NEFT|RTGS|IFSC))/gi,
    enabled: true,
    placeholder: "[ACCOUNT_NUMBER]",
    meta: {
      description: "Indian bank account number (9–18 digits) near banking keyword",
      addedInVersion: "1.0.0",
      defaultRedactMode: "token",
      generalisedLabel: "a bank account number",
      requiresContext: true,   // flag for future NER pass to confirm
    },
  },

  {
    id: "ifsc",
    label: "IFSC Code",
    category: "financial",
    severity: "medium",
    // Format: 4 letters + 0 + 6 alphanumeric
    pattern: /\b[A-Z]{4}0[A-Z0-9]{6}\b/g,
    enabled: true,
    placeholder: "[IFSC]",
    meta: {
      description: "RBI bank branch IFSC code",
      addedInVersion: "1.0.0",
      defaultRedactMode: "token",
      generalisedLabel: "a bank branch code",
    },
  },

  // ── Credentials & Secrets ──────────────────────────────────────────────────

  {
    id: "api_key_generic",
    label: "API Key / Secret Token",
    category: "credentials",
    severity: "critical",
    // Prefix-anchored: must start with sk-, pk-, api-, key-, token-, secret-, bearer-
    // Minimum 16 alphanumeric characters after prefix.
    pattern: /\b(?:sk|pk|api|key|token|secret|bearer)[-_]?[a-zA-Z0-9]{16,}\b/gi,
    enabled: true,
    placeholder: "[API_KEY]",
    meta: {
      description: "Generic API key or secret token with common prefix",
      addedInVersion: "1.0.0",
      defaultRedactMode: "suppress",  // secrets always suppressed, never tokenised
      generalisedLabel: "an API key",
    },
  },

  {
    id: "aws_key",
    label: "AWS Access Key",
    category: "credentials",
    severity: "critical",
    // AWS access keys always start with AKIA followed by 16 uppercase alphanumerics
    pattern: /\bAKIA[0-9A-Z]{16}\b/g,
    enabled: true,
    placeholder: "[AWS_KEY]",
    meta: {
      description: "AWS IAM access key ID",
      addedInVersion: "1.0.0",
      defaultRedactMode: "suppress",
      generalisedLabel: "an AWS access key",
    },
  },

  {
    id: "jwt",
    label: "JWT Token",
    category: "credentials",
    severity: "critical",
    // JWTs always start with eyJ (base64-encoded {"  )
    pattern: /\beyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\b/g,
    enabled: true,
    placeholder: "[JWT_TOKEN]",
    meta: {
      description: "JSON Web Token — three base64url segments separated by dots",
      addedInVersion: "1.0.0",
      defaultRedactMode: "suppress",
      generalisedLabel: "an authentication token",
    },
  },

  {
    id: "password_inline",
    label: "Inline Password",
    category: "credentials",
    severity: "critical",
    // Matches: password: mySecret / pwd=abc123 / passwd: hunter2
    pattern: /(?:password|passwd|pwd)\s*[:=]\s*\S+/gi,
    enabled: true,
    placeholder: "[PASSWORD]",
    meta: {
      description: "Password appearing inline with a label prefix",
      addedInVersion: "1.0.0",
      defaultRedactMode: "suppress",
      generalisedLabel: "a password",
    },
  },

  // ── Network / Infrastructure ───────────────────────────────────────────────

  {
    id: "ipv4",
    label: "IP Address (IPv4)",
    category: "network",
    severity: "medium",
    pattern: /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g,
    enabled: true,
    placeholder: "[IP_ADDRESS]",
    meta: {
      description: "Public IPv4 address — private/loopback ranges excluded via filter",
      addedInVersion: "1.0.0",
      defaultRedactMode: "token",
      generalisedLabel: "an IP address",
      // filter() runs after each regex match. Return false to discard the match.
      // This replaces the hardcoded if-block inside the old scanText loop.
      filter: (match) => {
        return !(
          match.startsWith("127.") ||
          match.startsWith("10.")  ||
          match.startsWith("192.168.") ||
          /^172\.(1[6-9]|2\d|3[01])\./.test(match)
        );
      },
    },
  },

];

// ─────────────────────────────────────────────────────────────────────────────
// COMPILED REGEX CACHE
// All patterns are compiled once at module initialisation.
// Never compiled inside detect() — that would be O(rules × calls).
// Each entry: { rule, re } where re is a fresh RegExp copy of rule.pattern.
// We need fresh RegExp objects (not rule.pattern itself) because exec() mutates
// lastIndex on the same instance, causing incorrect results under concurrent use.
// ─────────────────────────────────────────────────────────────────────────────

const _compiledRules = RULES.map((rule) => ({
  rule,
  // Preserve original flags. Always include 'g' — scanText needs exec() looping.
  re: new RegExp(rule.pattern.source, rule.pattern.flags.includes("g") ? rule.pattern.flags : rule.pattern.flags + "g"),
}));

// ─────────────────────────────────────────────────────────────────────────────
// CORE FUNCTIONS
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Build custom rules from user-defined keyword strings.
 * Used by content.js to convert settings.customKeywords into Rule objects.
 *
 * @param {string[]} keywords
 * @returns {Rule[]}
 */
function buildCustomRules(keywords) {
  return keywords.map((kw) => ({
    id: `custom_${kw.toLowerCase().replace(/\s+/g, "_")}`,
    label: `Custom: ${kw}`,
    category: "custom",
    severity: "high",
    pattern: new RegExp(`\\b${_escapeRegExp(kw)}\\b`, "gi"),
    enabled: true,
    placeholder: `[${kw.toUpperCase().replace(/\s+/g, "_")}]`,
    meta: {
      description: `User-defined keyword: ${kw}`,
      defaultRedactMode: "token",
      generalisedLabel: "a custom keyword",
    },
  }));
}

/**
 * Scan text for PII and return sorted, deduplicated findings.
 * Pure function — no side effects, no globals mutated.
 *
 * Performance notes:
 *   - Regex objects are pre-compiled. This function only calls exec().
 *   - Early return on empty / short input (< 6 chars — no PII fits).
 *   - Extra rules (customRules) are compiled fresh per call (acceptable:
 *     custom keywords change infrequently; cache them at the call site
 *     if profiling shows it matters).
 *   - maxFindings allows callers to cap work for large inputs.
 *
 * @param {string}        text
 * @param {DetectOptions} [options]
 * @returns {Finding[]}
 */
function detect(text, options = {}) {
  if (!text || text.length < 6) return [];

  const { extraRules = [], disabledRuleIds = [], maxFindings = Infinity } = options;

  // Merge built-in compiled rules with any extra rules for this call
  const compiledExtra = extraRules.map((rule) => ({
    rule,
    re: new RegExp(rule.pattern.source, rule.pattern.flags.includes("g") ? rule.pattern.flags : rule.pattern.flags + "g"),
  }));
  const allCompiled = [..._compiledRules, ...compiledExtra];

  const findings = [];
  const seen = new Set(); // deduplication key: "{start}-{match}"

  for (const { rule, re } of allCompiled) {
    if (!rule.enabled) continue;
    if (disabledRuleIds.includes(rule.id)) continue;
    if (findings.length >= maxFindings) break;

    // Reset lastIndex — essential when reusing compiled regex objects
    re.lastIndex = 0;

    let m;
    while ((m = re.exec(text)) !== null) {
      // Guard: infinite loop protection for zero-width matches
      if (m[0].length === 0) { re.lastIndex++; continue; }

      const key = `${m.index}-${m[0]}`;
      if (seen.has(key)) continue;

      // Run per-rule post-match filter (e.g. private IP exclusion)
      if (rule.meta?.filter && !rule.meta.filter(m[0])) continue;

      seen.add(key);
      findings.push({
        ruleId:      rule.id,
        label:       rule.label,
        category:    rule.category,
        severity:    rule.severity,
        match:       m[0],
        start:       m.index,
        end:         m.index + m[0].length,
        placeholder: rule.placeholder,
      });

      if (findings.length >= maxFindings) break;
    }
  }

  // Sort by position in original text
  findings.sort((a, b) => a.start - b.start);
  return findings;
}

/**
 * Apply redaction to text based on findings and chosen strategy.
 * Pure function — returns a new string and a valueMap; never mutates input.
 *
 * Strategy resolution order per finding:
 *   1. options.mode (call-level override)
 *   2. rule.meta.defaultRedactMode
 *   3. "token" (global fallback)
 *
 * @param {string}        text
 * @param {Finding[]}     findings    Must be sorted by start position (detect() guarantees this).
 * @param {RedactOptions} [options]
 * @returns {RedactResult}
 */
function redact(text, findings, options = {}) {
  const { mode: callMode, existingValueMap } = options;

  // valueMap: token → original value. Populated for token and synthetic modes.
  // Used by the round-trip feature to restore values from AI responses.
  const valueMap = existingValueMap || new Map();

  // Track occurrence counts per placeholder for numbered tokens: [EMAIL:1], [EMAIL:2] etc.
  const occurrenceCounts = {};

  let result = "";
  let cursor = 0;

  for (const finding of findings) {
    // Append unchanged text before this finding
    result += text.slice(cursor, finding.start);

    // Resolve the strategy for this finding
    const rule = getRule(finding.ruleId);
    const strategy = callMode || rule?.meta?.defaultRedactMode || "token";

    let replacement;

    switch (strategy) {
      case "suppress":
        // Remove entirely — no replacement whatsoever
        replacement = "";
        break;

      case "generalise":
        // Replace with human-readable category description
        replacement = rule?.meta?.generalisedLabel || finding.label.toLowerCase();
        break;

      case "synthetic":
        // Replace with structurally valid fake data.
        // Falls back to token if no fakeDataFn is defined for this rule.
        if (rule?.meta?.fakeDataFn) {
          const fakeValue = rule.meta.fakeDataFn();
          replacement = fakeValue;
          // Store mapping so the UI can show what was replaced
          const countKey = `${finding.placeholder}:synthetic`;
          occurrenceCounts[countKey] = (occurrenceCounts[countKey] || 0) + 1;
          const syntheticToken = `${finding.placeholder}:FAKE:${occurrenceCounts[countKey]}`;
          valueMap.set(syntheticToken, finding.match);
        } else {
          // Graceful fallback to token mode
          replacement = _makeNumberedToken(finding.placeholder, occurrenceCounts, valueMap, finding.match);
        }
        break;

      case "token":
      default:
        // Replace with numbered placeholder: [EMAIL:1], [EMAIL:2] etc.
        replacement = _makeNumberedToken(finding.placeholder, occurrenceCounts, valueMap, finding.match);
        break;
    }

    result += replacement;
    cursor = finding.end;
  }

  // Append remaining text after last finding
  result += text.slice(cursor);

  return { redacted: result, valueMap };
}

/**
 * Restore original values into an AI response using the valueMap from a prior redact() call.
 * Scans the response for known [LABEL:N] tokens and replaces them with original values.
 * Only token-mode entries are in the valueMap; synthetic and suppress have no original to restore.
 *
 * @param {string}              aiResponse
 * @param {Map<string, string>} valueMap    From a prior RedactResult.
 * @returns {string}
 */
function restore(aiResponse, valueMap) {
  let result = aiResponse;
  for (const [token, original] of valueMap.entries()) {
    // Escape brackets for regex safety
    const escaped = token.replace(/[[\]]/g, "\\$&");
    result = result.replace(new RegExp(escaped, "g"), original);
  }
  return result;
}

// ─────────────────────────────────────────────────────────────────────────────
// REGISTRY ACCESS
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Return a shallow copy of all built-in rules.
 * Callers should not mutate the returned objects.
 *
 * @returns {Rule[]}
 */
function getRules() {
  return [...RULES];
}

/**
 * Look up a rule by id.
 *
 * @param {string} id
 * @returns {Rule | undefined}
 */
function getRule(id) {
  return RULES.find((r) => r.id === id);
}

// ─────────────────────────────────────────────────────────────────────────────
// PRIVATE HELPERS
// ─────────────────────────────────────────────────────────────────────────────

function _makeNumberedToken(placeholder, counts, valueMap, originalValue) {
  counts[placeholder] = (counts[placeholder] || 0) + 1;
  const token = `${placeholder.slice(0, -1)}:${counts[placeholder]}]`;
  // e.g. "[EMAIL]" → "[EMAIL:1]", "[EMAIL:2]" ...
  valueMap.set(token, originalValue);
  return token;
}

function _escapeRegExp(str) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// ─────────────────────────────────────────────────────────────────────────────
// EXPORTS
// Compatible with: CommonJS (Node.js / Electron), ES Module (import),
// and plain <script> tag injection (sets window.KavachCore).
// ─────────────────────────────────────────────────────────────────────────────

const KavachCore = { detect, redact, restore, getRules, getRule, buildCustomRules };

if (typeof module !== "undefined" && module.exports) {
  // CommonJS — Node.js, Electron, extension background via require()
  module.exports = KavachCore;
} else if (typeof define === "function" && define.amd) {
  // AMD — unlikely but safe
  define([], () => KavachCore);
} else {
  // Browser global — extension content scripts loaded via manifest
  (typeof globalThis !== "undefined" ? globalThis : self).KavachCore = KavachCore;
}
