# 🛡️ GuardPrompt – AI PII Filter Chrome Extension

**Intercepts sensitive and personally identifiable information before it reaches any AI chat interface.**

All processing is 100% local. No data leaves your browser. Zero telemetry.

---

## Supported AI Chat Sites

| Site | URL |
|------|-----|
| Claude | claude.ai |
| ChatGPT | chat.openai.com / chatgpt.com |
| Gemini | gemini.google.com |
| Microsoft Copilot | copilot.microsoft.com |
| Perplexity | perplexity.ai |
| You.com | you.com |
| Poe | poe.com |

---

## What It Detects

### Identity & Contact
- Email addresses
- Phone numbers (India +91 and international)

### Government IDs
- Aadhaar numbers
- PAN numbers  
- Passport numbers

### Financial
- Credit/Debit card numbers (Visa, Mastercard, Amex)
- IFSC codes

### Credentials & Secrets
- API keys and tokens (generic, AWS, JWT)
- Inline passwords (e.g., `password: abc123`)

### Network
- Public IPv4 addresses (private ranges excluded)

### Custom
- Any keywords you define in the popup (e.g. project codenames, client names)

---

## How to Install (Developer Mode)

1. Clone or download this repository
2. Open Chrome → `chrome://extensions`
3. Enable **Developer mode** (top right toggle)
4. Click **Load unpacked**
5. Select the `guardprompt/` folder
6. Navigate to any supported AI chat site and try typing something with sensitive data

> **Note:** Icon files (`icons/icon16.png`, `icons/icon48.png`, `icons/icon128.png`) need to be added before publishing to Chrome Web Store. Any 16×16, 48×48, 128×128 PNG will work for development.

---

## How It Works

```
User types message
       ↓
[Content Script monitors input fields]
       ↓
User hits Enter / clicks Send
       ↓
GuardPrompt intercepts the submit event
       ↓
PII Scanner runs locally on the message text
       ↓
    No PII found?          PII found?
       ↓                      ↓
  Message sent          Review Overlay appears
  normally              (or auto-redact if enabled)
                               ↓
                     User selects what to redact
                               ↓
                     Redacted text replaces original
                               ↓
                         Message sent
```

---

## Settings (Popup)

| Setting | Description |
|---------|-------------|
| **Protection enabled** | Master on/off switch |
| **Auto-redact** | Silently replace all findings without showing the review prompt |
| **Custom Keywords** | Words/phrases to block in addition to built-in patterns |

---

## Architecture

```
guardprompt/
├── manifest.json          # Chrome MV3 manifest
├── popup.html             # Extension popup UI
├── popup.js               # Popup logic (settings, session log)
├── src/
│   ├── content.js         # Main content script (injected into AI sites)
│   ├── detector.js        # PII detection engine (patterns + scanner)
│   ├── overlay.css        # Review overlay styles
│   └── background.js      # Service worker (install defaults, badge)
└── icons/
    ├── icon16.png
    ├── icon48.png
    └── icon128.png
```

---

## Roadmap / Future Features

- [ ] Named Entity Recognition using an on-device ML model (e.g. Transformers.js) for name detection
- [ ] Team policy sync via a shared config URL
- [ ] Export session audit log as CSV
- [ ] Per-site enable/disable rules
- [ ] Firefox (MV3) support
- [ ] Safari extension port
- [ ] Enterprise: GPO / MDM policy deployment

---

## Privacy

- **Zero network calls** – the extension never contacts any external server
- **No analytics** – no usage tracking whatsoever
- **Storage** – settings saved in `chrome.storage.sync` (your Google account only), session log in `chrome.storage.local`
- **Open source** – all detection logic is readable in `src/detector.js`

---

## License

MIT License – free to use, modify, and distribute.
