/**
 * kavach-core test suite
 * Run: node kavach-core.test.js
 */

const core = require("./kavach-core");
const { detect, redact, restore, getRules, getRule, buildCustomRules } = core;

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`  ✓ ${name}`);
    passed++;
  } catch (e) {
    console.log(`  ✗ ${name}`);
    console.log(`      ${e.message}`);
    failed++;
  }
}

function assert(condition, msg) {
  if (!condition) throw new Error(msg || "Assertion failed");
}

function assertEq(a, b, msg) {
  if (a !== b) throw new Error(`${msg || "Expected equal"}\n      got:      ${JSON.stringify(a)}\n      expected: ${JSON.stringify(b)}`);
}

// ─── Section: detect() ────────────────────────────────────────────────────────

console.log("\n▶ detect() — basic PII types");

test("email address detected", () => {
  const f = detect("Contact me at nag@aikavach.in for details");
  assert(f.length === 1, `Expected 1 finding, got ${f.length}`);
  assertEq(f[0].ruleId, "email");
  assertEq(f[0].match, "nag@aikavach.in");
});

test("Indian phone number detected — plain 10 digits", () => {
  const f = detect("Call me on 9876543210 please");
  const phone = f.find(x => x.ruleId === "phone_in");
  assert(phone, "No phone_in finding");
  assertEq(phone.match, "9876543210");
});

test("Indian phone number detected — +91 with spaces", () => {
  const f = detect("My number is +91 98765 43210");
  const phone = f.find(x => x.ruleId === "phone_in");
  assert(phone, "No phone_in finding for spaced format");
});

test("Aadhaar number detected — spaced format", () => {
  const f = detect("Aadhaar: 2345 6789 0123");
  const a = f.find(x => x.ruleId === "aadhaar");
  assert(a, `No aadhaar finding. Got: ${JSON.stringify(f)}`);
});

test("Aadhaar number detected — plain 12 digits", () => {
  const f = detect("aadhar no is 234567890123");
  const a = f.find(x => x.ruleId === "aadhaar");
  assert(a, "No aadhaar finding for plain format");
});

test("Aadhaar false-positive on 16-digit card number suppressed", () => {
  const f = detect("card: 4111111111111111");
  const a = f.find(x => x.ruleId === "aadhaar");
  assert(!a, "Aadhaar should NOT match 16-digit credit card");
});

test("PAN number detected", () => {
  const f = detect("PAN: ABCDE1234F");
  const p = f.find(x => x.ruleId === "pan");
  assert(p, "No PAN finding");
  assertEq(p.match, "ABCDE1234F");
});

test("Passport number detected", () => {
  const f = detect("passport A1234567");
  const p = f.find(x => x.ruleId === "passport");
  assert(p, "No passport finding");
});

test("Credit card detected — Visa", () => {
  const f = detect("card number is 4111111111111111");
  const c = f.find(x => x.ruleId === "credit_card");
  assert(c, "No credit_card finding");
});

test("Credit card detected — RuPay (detector.js improvement over content.js)", () => {
  const f = detect("rupay card 6521234567890123");
  const c = f.find(x => x.ruleId === "credit_card");
  assert(c, "No RuPay credit_card finding — pattern should cover 65xx cards");
});

test("IFSC code detected", () => {
  const f = detect("IFSC: HDFC0001234");
  const i = f.find(x => x.ruleId === "ifsc");
  assert(i, "No IFSC finding");
});

test("API key detected — sk- prefix", () => {
  const f = detect("key is sk-abc123def456ghi789");
  const k = f.find(x => x.ruleId === "api_key_generic");
  assert(k, "No api_key_generic finding");
});

test("API key minimum length — 15 chars NOT matched, 16 chars matched", () => {
  // Pattern requires 16 alphanumeric chars after the optional separator (sk-, sk_, etc.)
  // 'abc123def456gh1' = 15 chars → no match
  // 'abc123def456gh12' = 16 chars → match
  const short = detect("key is sk-abc123def456gh1");   // sk- + 15 = no match
  const long  = detect("key is sk-abc123def456gh12");  // sk- + 16 = match
  const kShort = short.find(x => x.ruleId === "api_key_generic");
  const kLong  = long.find(x => x.ruleId === "api_key_generic");
  assert(!kShort, `Short key (15 chars after separator) should NOT match, got: ${JSON.stringify(kShort?.match)}`);
  assert(kLong,   "Long key (16 chars after separator) SHOULD match");
});

test("AWS access key detected", () => {
  // Real AWS access key: AKIA + exactly 16 uppercase alphanumerics = 20 chars total
  const f = detect("aws key AKIAIOSFODNN7EXAMPLE");
  const k = f.find(x => x.ruleId === "aws_key");
  assert(k, "No aws_key finding");
});

test("JWT token detected", () => {
  const f = detect("token: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c");
  const j = f.find(x => x.ruleId === "jwt");
  assert(j, "No JWT finding");
});

test("Inline password detected", () => {
  const f = detect("password: mySecret123");
  const p = f.find(x => x.ruleId === "password_inline");
  assert(p, "No password_inline finding");
});

test("IPv4 public address detected", () => {
  const f = detect("server at 203.0.113.1");
  const ip = f.find(x => x.ruleId === "ipv4");
  assert(ip, "No ipv4 finding");
});

test("IPv4 private ranges excluded — 192.168.x.x", () => {
  const f = detect("local server at 192.168.1.100");
  const ip = f.find(x => x.ruleId === "ipv4");
  assert(!ip, "Private IP 192.168.x.x should NOT be flagged");
});

test("IPv4 private ranges excluded — 10.x.x.x", () => {
  const f = detect("internal host 10.0.0.5");
  const ip = f.find(x => x.ruleId === "ipv4");
  assert(!ip, "Private IP 10.x.x.x should NOT be flagged");
});

test("IPv4 private ranges excluded — 127.x.x.x", () => {
  const f = detect("localhost is 127.0.0.1");
  const ip = f.find(x => x.ruleId === "ipv4");
  assert(!ip, "Loopback IP should NOT be flagged");
});

test("DOB detected with label prefix", () => {
  const f = detect("dob: 15/08/1990");
  const d = f.find(x => x.ruleId === "dob");
  assert(d, "No DOB finding");
});

test("Date without label prefix NOT detected as DOB", () => {
  const f = detect("The meeting is on 15/08/2024");
  const d = f.find(x => x.ruleId === "dob");
  assert(!d, "Bare date without DOB prefix should NOT be flagged");
});

console.log("\n▶ detect() — multi-finding behaviour");

test("Multiple PII types in one text", () => {
  const f = detect("My email is nag@test.com and phone is 9876543210 and PAN is ABCDE1234F");
  const ruleIds = f.map(x => x.ruleId);
  assert(ruleIds.includes("email"),    "Missing email");
  assert(ruleIds.includes("phone_in"), "Missing phone_in");
  assert(ruleIds.includes("pan"),      "Missing pan");
});

test("Findings sorted by position", () => {
  const f = detect("PAN ABCDE1234F and email nag@test.com");
  assert(f.length >= 2, "Expected at least 2 findings");
  assert(f[0].start < f[1].start, "Findings not sorted by position");
});

test("Same match at same position deduplicated (cross-rule overlap guard)", () => {
  // Dedup key is "{start}-{match}" — same value at DIFFERENT positions = 2 findings (correct).
  // This test verifies the seen-set prevents a single match being recorded twice
  // if two rules somehow produce the same start+match (e.g. overlapping custom rules).
  const customRules = buildCustomRules(["test@test.com"]);
  // email rule AND custom rule both match — only one finding at that position
  const f = detect("send to test@test.com please", { extraRules: customRules });
  const atPosition = f.filter(x => x.start === f[0].start);
  assertEq(atPosition.length, 1, "Same match at same start position should only appear once");
});

test("Short input skipped — under 6 chars", () => {
  const f = detect("hi");
  assertEq(f.length, 0, "Short input should return no findings");
});

test("Empty string returns empty array", () => {
  const f = detect("");
  assertEq(f.length, 0);
});

test("maxFindings option caps results", () => {
  const text = "nag@test.com and 9876543210 and ABCDE1234F";
  const f = detect(text, { maxFindings: 1 });
  assert(f.length <= 1, `maxFindings=1 should return at most 1, got ${f.length}`);
});

test("disabledRuleIds skips specified rules", () => {
  const f = detect("nag@test.com", { disabledRuleIds: ["email"] });
  assert(!f.find(x => x.ruleId === "email"), "email rule should be skipped");
});

console.log("\n▶ detect() — custom rules");

test("Custom keyword detected via extraRules", () => {
  const customRules = buildCustomRules(["ProjectNova"]);
  const f = detect("This is related to ProjectNova", { extraRules: customRules });
  assert(f.find(x => x.ruleId === "custom_projectnova"), "Custom keyword not detected");
});

// ─── Section: redact() ────────────────────────────────────────────────────────

console.log("\n▶ redact() — token mode");

test("Token mode replaces finding with numbered placeholder", () => {
  const f = detect("email is nag@test.com");
  const r = redact("email is nag@test.com", f);
  assert(r.redacted.includes("[EMAIL:1]"), `Expected [EMAIL:1], got: ${r.redacted}`);
  assert(!r.redacted.includes("nag@test.com"), "Original email should be removed");
});

test("valueMap populated in token mode", () => {
  const text = "email is nag@test.com";
  const f = detect(text);
  const r = redact(text, f);
  assert(r.valueMap.size > 0, "valueMap should not be empty");
  assert(r.valueMap.get("[EMAIL:1]") === "nag@test.com", "valueMap should map token to original");
});

test("Multiple same-type findings get unique numbered tokens", () => {
  const text = "emails: nag@test.com and foo@bar.com";
  const f = detect(text);
  const r = redact(text, f);
  assert(r.redacted.includes("[EMAIL:1]"), "Missing [EMAIL:1]");
  assert(r.redacted.includes("[EMAIL:2]"), "Missing [EMAIL:2]");
});

test("Text before and after finding preserved", () => {
  const text = "Contact nag@test.com today";
  const f = detect(text);
  const r = redact(text, f);
  assert(r.redacted.startsWith("Contact "), "Text before finding not preserved");
  assert(r.redacted.endsWith(" today"), "Text after finding not preserved");
});

console.log("\n▶ redact() — suppress mode");

test("Suppress mode removes finding entirely", () => {
  const text = "password: hunter2 is secure";
  const f = detect(text);
  const r = redact(text, f, { mode: "suppress" });
  assert(!r.redacted.includes("hunter2"), "Suppressed value should not appear");
  assert(!r.redacted.includes("[PASSWORD"), "Suppress should not add placeholder");
});

test("Secrets use suppress by default (no mode override needed)", () => {
  const text = "my api key is sk-abc123def456ghi789jkl";
  const f = detect(text);
  // No mode option — should use rule.meta.defaultRedactMode = "suppress"
  const r = redact(text, f);
  assert(!r.redacted.includes("sk-abc"), "API key should be suppressed by default");
  assert(!r.redacted.includes("[API_KEY"), "Suppress mode should not leave placeholder");
});

console.log("\n▶ redact() — generalise mode");

test("Generalise mode uses generalisedLabel", () => {
  const text = "call me on 9876543210";
  const f = detect(text);
  const r = redact(text, f, { mode: "generalise" });
  assert(r.redacted.includes("a mobile number"), `Expected generalised label, got: ${r.redacted}`);
  assert(!r.redacted.includes("9876543210"), "Original number should be removed");
});

console.log("\n▶ redact() — synthetic mode");

test("Synthetic mode uses fakeDataFn for Aadhaar", () => {
  const text = "aadhaar 2345 6789 0123";
  const f = detect(text);
  const r = redact(text, f, { mode: "synthetic" });
  assert(!r.redacted.includes("2345 6789 0123"), "Original Aadhaar should not appear");
  assert(!r.redacted.includes("[AADHAAR"), "Synthetic mode should not show token");
});

test("Synthetic mode falls back to token if no fakeDataFn", () => {
  const text = "ifsc code HDFC0001234";
  const f = detect(text);
  // ifsc rule has no fakeDataFn — should fall back to token
  const r = redact(text, f, { mode: "synthetic" });
  assert(r.redacted.includes("[IFSC:1]"), `Expected token fallback [IFSC:1], got: ${r.redacted}`);
});

// ─── Section: restore() ───────────────────────────────────────────────────────

console.log("\n▶ restore()");

test("restore() replaces tokens with original values in AI response", () => {
  const text = "nag@test.com";
  const f = detect(text);
  const r = redact(text, f);
  const aiResponse = "I'll send the confirmation to [EMAIL:1] right away.";
  const restored = restore(aiResponse, r.valueMap);
  assert(restored.includes("nag@test.com"), `Expected original email, got: ${restored}`);
  assert(!restored.includes("[EMAIL:1]"), "Token should be replaced after restore");
});

test("restore() leaves unknown tokens unchanged", () => {
  const text = "nag@test.com";
  const f = detect(text);
  const r = redact(text, f);
  const aiResponse = "Reply to [EMAIL:1] and also [UNKNOWN:1]";
  const restored = restore(aiResponse, r.valueMap);
  assert(restored.includes("nag@test.com"), "Known token should be restored");
  assert(restored.includes("[UNKNOWN:1]"), "Unknown token should be left as-is");
});

// ─── Section: Registry ────────────────────────────────────────────────────────

console.log("\n▶ getRules() / getRule()");

test("getRules() returns array of all built-in rules", () => {
  const rules = getRules();
  assert(Array.isArray(rules), "Should return array");
  assert(rules.length >= 12, `Expected at least 12 rules, got ${rules.length}`);
});

test("getRules() returns a copy — mutations don't affect registry", () => {
  const rules = getRules();
  rules.push({ id: "fake" });
  const rules2 = getRules();
  assert(!rules2.find(r => r.id === "fake"), "Registry should not be mutated");
});

test("getRule() finds rule by id", () => {
  const rule = getRule("aadhaar");
  assert(rule, "Should find aadhaar rule");
  assertEq(rule.id, "aadhaar");
});

test("getRule() returns undefined for unknown id", () => {
  const rule = getRule("does_not_exist");
  assert(rule === undefined, "Should return undefined for missing rule");
});

test("All rules have required fields", () => {
  const rules = getRules();
  for (const rule of rules) {
    assert(rule.id,          `Rule missing id`);
    assert(rule.label,       `Rule ${rule.id} missing label`);
    assert(rule.category,    `Rule ${rule.id} missing category`);
    assert(rule.severity,    `Rule ${rule.id} missing severity`);
    assert(rule.pattern,     `Rule ${rule.id} missing pattern`);
    assert(rule.placeholder, `Rule ${rule.id} missing placeholder`);
    assert(typeof rule.enabled === "boolean", `Rule ${rule.id} enabled must be boolean`);
  }
});

test("All rule patterns have /g flag", () => {
  const rules = getRules();
  for (const rule of rules) {
    assert(rule.pattern.flags.includes("g"), `Rule ${rule.id} pattern missing /g flag`);
  }
});

// ─── Summary ─────────────────────────────────────────────────────────────────

console.log(`\n${"─".repeat(50)}`);
console.log(`  Results: ${passed} passed, ${failed} failed`);
if (failed > 0) {
  console.log("  ⚠️  Fix failures before integrating into extension.");
  process.exit(1);
} else {
  console.log("  ✅  All tests passed. kavach-core is ready.");
}
console.log(`${"─".repeat(50)}\n`);
