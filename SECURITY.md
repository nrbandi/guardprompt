# Security Policy — GuardPrompt

## Supported versions

| Version | Supported |
|---------|-----------|
| Latest (master) | ✅ |
| Older commits | ❌ — please update to latest |

---

## Reporting a vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

GuardPrompt is a privacy tool. A public vulnerability disclosure before a fix is available could put users at risk. Private disclosure first gives us time to patch and release before the issue is public knowledge.

**To report a vulnerability:**

1. Open a [GitHub Security Advisory](https://github.com/nrbandi/guardprompt/security/advisories/new) — this is private and only visible to maintainers
2. Or email the maintainer directly via the contact on the GitHub profile

Please include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact (what an attacker could do)
- Your suggested fix, if you have one

---

## What to expect

- **Acknowledgement:** within 72 hours
- **Assessment:** within 7 days — whether it's confirmed, disputed, or needs more information
- **Fix timeline:** depends on severity. Critical issues will be prioritised above all other work.
- **Credit:** if you'd like to be credited in the release notes, say so in your report

---

## Scope

**In scope** — things we want to hear about:

- Code that causes data to be transmitted externally (violates the zero-transmission guarantee)
- Pattern bypass — input that contains PII but GuardPrompt fails to flag it in a way that could be exploited
- Privilege escalation via extension permissions
- Content script injection vulnerabilities
- Storage manipulation (tampering with audit logs or settings)

**Out of scope:**

- False positives or false negatives in PII detection (use a regular issue for these)
- UI/UX bugs
- Vulnerabilities in AI sites that GuardPrompt runs on (report those to the respective companies)
- Issues only reproducible in outdated Chrome versions

---

## Security design principles

GuardPrompt is built around two non-negotiable constraints:

**1. Zero external transmission.** The extension makes no outbound network requests. Detection, redaction, and storage all happen locally. This can be verified by inspecting `manifest.json` (no host permissions beyond the supported AI sites) and the source code (no `fetch`, no `XMLHttpRequest`, no WebSocket).

**2. Minimal permissions.** GuardPrompt requests only `storage` and `activeTab`, plus access to the specific AI chat sites it supports. It does not request broad host permissions, browsing history, or cross-origin access.

If you find code that violates either principle, that is a critical severity issue.

---

## Malicious clones

A known risk in the Chrome extension ecosystem is malicious forks that impersonate privacy tools. If you find an extension claiming to be GuardPrompt that is not published by `nrbandi`, please report it to the [Chrome Web Store](https://support.google.com/chrome_webstore/answer/7508032) and open an issue here so we can warn users.

The canonical source is always: **github.com/nrbandi/guardprompt**
