// GuardPrompt – PII/Sensitive Data Detector
// Runs entirely client-side. No data leaves the browser.

const RULES = [
  // ── Identity ──────────────────────────────────────────────────────────────
  {
    id: "email",
    label: "Email Address",
    category: "identity",
    severity: "high",
    pattern: /\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b/g,
    placeholder: "[EMAIL]",
  },
  {
    id: "phone_in",
    label: "Phone Number (India)",
    category: "identity",
    severity: "high",
    pattern: /(?<!\d)(\+91[\s\-]?)?[6-9]\d{9}(?!\d)/g,
    placeholder: "[PHONE]",
  },
  {
    id: "phone_intl",
    label: "Phone Number (International)",
    category: "identity",
    severity: "high",
    pattern: /(?<!\d)\+?1?[\s.\-]?\(?\d{3}\)?[\s.\-]?\d{3}[\s.\-]?\d{4}(?!\d)/g,
    placeholder: "[PHONE]",
  },

  // ── Indian Government IDs ─────────────────────────────────────────────────
  {
    id: "aadhaar",
    label: "Aadhaar Number",
    category: "gov_id",
    severity: "critical",
    pattern: /\b[2-9]{1}\d{3}[\s\-]?\d{4}[\s\-]?\d{4}\b/g,
    placeholder: "[AADHAAR]",
  },
  {
    id: "pan",
    label: "PAN Number",
    category: "gov_id",
    severity: "critical",
    pattern: /\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b/g,
    placeholder: "[PAN]",
  },
  {
    id: "passport",
    label: "Passport Number",
    category: "gov_id",
    severity: "critical",
    pattern: /\b[A-PR-WY][1-9]\d\s?\d{4}[1-9]\b/g,
    placeholder: "[PASSPORT]",
  },

  // ── Financial ─────────────────────────────────────────────────────────────
  {
    id: "credit_card",
    label: "Credit / Debit Card Number",
    category: "financial",
    severity: "critical",
    pattern: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b/g,
    placeholder: "[CARD_NUMBER]",
  },
  {
    id: "bank_account",
    label: "Bank Account Number",
    category: "financial",
    severity: "high",
    pattern: /\b\d{9,18}\b(?=.*(?:account|acc|bank|NEFT|RTGS|IFSC))/gi,
    placeholder: "[ACCOUNT_NUMBER]",
  },
  {
    id: "ifsc",
    label: "IFSC Code",
    category: "financial",
    severity: "medium",
    pattern: /\b[A-Z]{4}0[A-Z0-9]{6}\b/g,
    placeholder: "[IFSC]",
  },

  // ── Credentials & Secrets ─────────────────────────────────────────────────
  {
    id: "api_key_generic",
    label: "API Key / Secret Token",
    category: "credentials",
    severity: "critical",
    pattern: /\b(?:sk|pk|api|key|token|secret|bearer)[-_]?[a-zA-Z0-9]{20,}\b/gi,
    placeholder: "[API_KEY]",
  },
  {
    id: "aws_key",
    label: "AWS Access Key",
    category: "credentials",
    severity: "critical",
    pattern: /\bAKIA[0-9A-Z]{16}\b/g,
    placeholder: "[AWS_KEY]",
  },
  {
    id: "jwt",
    label: "JWT Token",
    category: "credentials",
    severity: "critical",
    pattern: /\beyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\b/g,
    placeholder: "[JWT_TOKEN]",
  },
  {
    id: "password_inline",
    label: "Inline Password",
    category: "credentials",
    severity: "critical",
    pattern: /(?:password|passwd|pwd)\s*[:=]\s*\S+/gi,
    placeholder: "[PASSWORD]",
  },

  // ── Network / Infrastructure ──────────────────────────────────────────────
  {
    id: "ipv4",
    label: "IP Address (IPv4)",
    category: "network",
    severity: "medium",
    pattern: /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g,
    placeholder: "[IP_ADDRESS]",
    // Exclude localhost / private ranges in post-processing
  },

  // ── Date of Birth ─────────────────────────────────────────────────────────
  {
    id: "dob",
    label: "Date of Birth",
    category: "identity",
    severity: "medium",
    pattern: /\b(?:dob|date of birth|born on|birthdate)[:\s]+\d{1,2}[\/\-\.]\d{1,2}[\/\-\.]\d{2,4}\b/gi,
    placeholder: "[DOB]",
  },
];

/**
 * Scan text and return an array of findings.
 * Each finding: { ruleId, label, category, severity, match, start, end, placeholder }
 */
function scanText(text, customRules = []) {
  const allRules = [...RULES, ...customRules];
  const findings = [];
  const seen = new Set(); // deduplicate overlapping matches

  for (const rule of allRules) {
    const re = new RegExp(rule.pattern.source, rule.pattern.flags);
    let m;
    while ((m = re.exec(text)) !== null) {
      const key = `${m.index}-${m[0]}`;
      if (seen.has(key)) continue;
      seen.add(key);

      // Skip private IP ranges for ipv4 rule
      if (rule.id === "ipv4") {
        const ip = m[0];
        if (
          ip.startsWith("127.") ||
          ip.startsWith("10.") ||
          ip.startsWith("192.168.") ||
          /^172\.(1[6-9]|2\d|3[01])\./.test(ip)
        )
          continue;
      }

      findings.push({
        ruleId: rule.id,
        label: rule.label,
        category: rule.category,
        severity: rule.severity,
        match: m[0],
        start: m.index,
        end: m.index + m[0].length,
        placeholder: rule.placeholder,
      });
    }
  }

  // Sort by position
  findings.sort((a, b) => a.start - b.start);
  return findings;
}

/**
 * Apply redactions to text, returning cleaned string.
 */
function redactText(text, findings) {
  let result = "";
  let cursor = 0;
  for (const f of findings) {
    result += text.slice(cursor, f.start);
    result += f.placeholder;
    cursor = f.end;
  }
  result += text.slice(cursor);
  return result;
}

// Export for content script (loaded as module-like via concatenation)
if (typeof module !== "undefined") {
  module.exports = { scanText, redactText, RULES };
}
