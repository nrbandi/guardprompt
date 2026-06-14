# Contributing to GuardPrompt

Thanks for taking the time to contribute. GuardPrompt is a solo-maintained open source project built in limited hours — focused, small contributions are the most valuable kind.

---

## What we need most

The highest-value contributions right now, in order:

1. **New PII patterns** — especially Indian formats not yet covered: UPI IDs, GST numbers, Voter ID, Passport numbers
2. **Bug fixes** — pattern false positives/negatives, site compatibility issues
3. **New AI site support** — if GuardPrompt doesn't work on an AI site you use, a fix is welcome
4. **Improved regex accuracy** — tighter patterns that reduce false positives without missing real PII

---

## Before you start

- Check [open issues](https://github.com/nrbandi/guardprompt/issues) to see if someone is already working on it
- For anything beyond a small fix, open an issue first to discuss — saves you from building something that won't be merged
- Keep pull requests focused: one fix or one feature per PR

---

## Development setup

No build step required. GuardPrompt is vanilla JS with no dependencies.

```bash
git clone https://github.com/nrbandi/guardprompt.git
cd guardprompt
```

Load in Chrome:
1. Go to `chrome://extensions`
2. Enable **Developer mode**
3. Click **Load unpacked** → select the `guardprompt` folder

After any code change:
1. Go to `chrome://extensions` → click the refresh icon on GuardPrompt
2. Refresh the AI chat tab (`Ctrl+R`)
3. Test your change

---

## Adding a PII pattern

All patterns live in `src/detector.js` in the `RULES` array. Each rule follows this structure:

```javascript
{
  id: "upi_id",
  label: "UPI ID",
  category: "Financial",
  pattern: /your-regex-here/gi,
}
```

**Guidelines for new patterns:**
- Test against at least 10 real-format examples (positive) and 10 non-matching strings (negative)
- Prefer specificity over recall — a false positive breaks user trust more than a miss
- Add the pattern name and category to the README's "PII Patterns Detected" section in your PR

---

## Code style

- Vanilla JS only — no frameworks, no build tools, no npm
- No external libraries or CDN imports
- Keep the zero-dependency principle: everything must work offline
- Comment non-obvious regex patterns explaining what format they match and why

---

## Pull request checklist

Before submitting:

- [ ] Tested manually on at least one supported AI site
- [ ] No new external dependencies introduced
- [ ] README updated if you added a new pattern or supported site
- [ ] Commit message is descriptive (`Fix: Aadhaar pattern matching credit card numbers` not `fix bug`)

---

## Reporting bugs

Open a GitHub issue with:
- What you typed (you can redact it, just show the format — e.g. "12-digit number with spaces")
- Which AI site you were on
- What GuardPrompt did vs. what you expected
- Chrome version and OS

---

## Code of conduct

Be direct, be respectful, assume good intent. This project is maintained in limited personal time — responses may not be immediate.
