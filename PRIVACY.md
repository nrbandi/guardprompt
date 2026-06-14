# Privacy Policy — GuardPrompt

*Last updated: June 2026*

## The short version

GuardPrompt processes all data locally on your device. Nothing you type is ever sent to GuardPrompt's servers — because there are none.

---

## What GuardPrompt does

GuardPrompt is a Chrome browser extension that scans text you type into AI chat interfaces and detects personally identifiable information (PII) before it is sent. When PII is detected, GuardPrompt shows a review overlay or automatically redacts the sensitive content, depending on your settings.

---

## Data we collect

**GuardPrompt collects nothing.**

- No text you type is transmitted to any external server.
- No usage data, analytics, or telemetry is collected.
- No account is required. No email address is collected.
- No cookies are set.

---

## Data processed locally

The following data is processed **entirely on your device** and never leaves your browser:

- Text you type into supported AI chat interfaces (scanned in memory, never stored externally)
- Your extension settings (stored in `chrome.storage.local` on your device)
- Your session audit log (stored in `chrome.storage.local` on your device, cleared when you choose)
- Custom keywords you define (stored in `chrome.storage.local` on your device)

You can clear all locally stored data at any time from the extension popup.

---

## Permissions used

GuardPrompt requests the following Chrome permissions:

| Permission | Why |
|------------|-----|
| `storage` | To save your settings and session log locally on your device |
| `activeTab` | To inject the privacy scanner into the active AI chat tab |
| Access to supported AI sites | To intercept and scan text before it is submitted |

GuardPrompt does not request permissions to read your browsing history, access other tabs, or communicate with external servers.

---

## Third parties

GuardPrompt does not share any data with any third party. There are no third-party analytics libraries, advertising SDKs, or tracking pixels in this extension.

---

## Open source

GuardPrompt is fully open source under the MIT licence. The complete source code is available at [github.com/nrbandi/guardprompt](https://github.com/nrbandi/guardprompt). You can inspect every line of code to verify these claims.

---

## Changes to this policy

If this policy is updated, the updated version will be committed to the GitHub repository with a clear commit message and the "Last updated" date above will be changed. Significant changes will be noted in the release notes.

---

## Contact

For privacy questions or vulnerability reports, please open an issue on GitHub or contact the maintainer directly via the GitHub profile.
