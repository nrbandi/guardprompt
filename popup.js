// GuardPrompt Popup Script

const $ = (id) => document.getElementById(id);

// ── Load settings ──────────────────────────────────────────────────────────
chrome.storage.sync.get(["enabled", "autoRedact", "customKeywords"], (res) => {
  $("toggle-enabled").checked = res.enabled !== false; // default true
  $("toggle-auto").checked = res.autoRedact === true;
  renderKeywords(res.customKeywords || []);
});

chrome.storage.local.get(["sessionLog"], (res) => {
  renderLog(res.sessionLog || []);
  renderStats(res.sessionLog || []);
});

// ── Settings toggles ──────────────────────────────────────────────────────
$("toggle-enabled").addEventListener("change", (e) => {
  chrome.storage.sync.set({ enabled: e.target.checked });
});

$("toggle-auto").addEventListener("change", (e) => {
  chrome.storage.sync.set({ autoRedact: e.target.checked });
});

// ── Custom keywords ────────────────────────────────────────────────────────
let keywords = [];

function renderKeywords(kws) {
  keywords = kws;
  const container = $("keyword-tags");
  container.innerHTML = "";
  for (const kw of kws) {
    const tag = document.createElement("div");
    tag.className = "keyword-tag";
    tag.innerHTML = `${kw}<button class="remove" data-kw="${kw}">×</button>`;
    container.appendChild(tag);
  }
  container.querySelectorAll(".remove").forEach((btn) => {
    btn.addEventListener("click", () => removeKeyword(btn.dataset.kw));
  });
}

function addKeyword() {
  const input = $("keyword-input");
  const val = input.value.trim();
  if (!val || keywords.includes(val)) return;
  keywords.push(val);
  chrome.storage.sync.set({ customKeywords: keywords }, () => renderKeywords(keywords));
  input.value = "";
}

function removeKeyword(kw) {
  keywords = keywords.filter((k) => k !== kw);
  chrome.storage.sync.set({ customKeywords: keywords }, () => renderKeywords(keywords));
}

$("keyword-add").addEventListener("click", addKeyword);
$("keyword-input").addEventListener("keydown", (e) => { if (e.key === "Enter") addKeyword(); });

// ── Session log ────────────────────────────────────────────────────────────
function renderLog(log) {
  const container = $("log-list");
  if (!log || log.length === 0) {
    container.innerHTML = '<div class="log-empty">Nothing redacted yet this session</div>';
    return;
  }
  const recent = [...log].reverse().slice(0, 10);
  container.innerHTML = recent.map((entry) => `
    <div class="log-item">
      <span class="log-site">${entry.url}</span>
      <span class="log-count">${entry.count} item${entry.count > 1 ? "s" : ""}</span>
      <span class="log-types">${entry.types.join(", ")}</span>
    </div>
  `).join("");
}

function renderStats(log) {
  $("stat-scans").textContent = log.length;
  const total = log.reduce((sum, e) => sum + e.count, 0);
  $("stat-redactions").textContent = total;
}

$("clear-log").addEventListener("click", () => {
  chrome.storage.local.set({ sessionLog: [] }, () => {
    renderLog([]);
    renderStats([]);
  });
});
