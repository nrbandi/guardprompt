// GuardPrompt Background Service Worker

// Listen for install
chrome.runtime.onInstalled.addListener(() => {
  // Set defaults
  chrome.storage.sync.set({
    enabled: true,
    autoRedact: false,
    customKeywords: [],
  });
  chrome.storage.local.set({ sessionLog: [] });
});

// Badge update based on enabled state
chrome.storage.onChanged.addListener((changes) => {
  if (changes.enabled) {
    const enabled = changes.enabled.newValue;
    chrome.action.setBadgeText({ text: enabled ? "" : "OFF" });
    chrome.action.setBadgeBackgroundColor({ color: "#ef4444" });
  }
});
