const assert = require("assert");
const {
  parseExport,
  filterFindings,
  sortFindings,
  countByLabel,
  countByCategory,
  isRevealable,
  REDACTED_PLACEHOLDER,
} = require("./core.js");

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`PASS: ${name}`);
    passed++;
  } catch (e) {
    console.log(`FAIL: ${name}`);
    console.log(`  ${e.message}`);
    failed++;
  }
}

// Sample data matching the actual shape produced by json_export.py
const sampleRedactedExport = {
  generated_at: "2026-09-03T12:00:00Z",
  redacted: true,
  total_findings: 3,
  findings: [
    {
      risk_score: 10.0, risk_label: "CRITICAL", rule_id: "db_connection_string", category: "credentials",
      matched_text: REDACTED_PLACEHOLDER, matched_text_length: 54, base_severity: 9.0, entropy_score: null,
      identity_confidence: 1.5, identity_reason: "Direct match against known identity string 'staging.co'",
      exposure_level: "public_reachable", source_type: "git_patch", origin: "/repo", context: "commit abc123",
      occurrence_count: 3, metadata: {},
    },
    {
      risk_score: 5.06, risk_label: "MEDIUM", rule_id: "personal_email_domain", category: "personal",
      matched_text: REDACTED_PLACEHOLDER, matched_text_length: 19, base_severity: 4.5, entropy_score: null,
      identity_confidence: 1.5, identity_reason: "Direct match against known identity string 'john.doe@gmail.com'",
      exposure_level: "local_only", source_type: "git_commit_meta", context: "commit def456 (author email)",
      origin: "/repo", occurrence_count: 8, metadata: {},
    },
    {
      risk_score: 2.81, risk_label: "LOW", rule_id: "internal_hostname", category: "infrastructure",
      matched_text: REDACTED_PLACEHOLDER, matched_text_length: 11, base_severity: 7.5, entropy_score: null,
      identity_confidence: 0.5, identity_reason: "No correlation found against target identity profile (generic/low-confidence match)",
      exposure_level: "local_only", source_type: "git_patch", origin: "/repo", context: "commit ghi789",
      occurrence_count: 1, metadata: {},
    },
  ],
};

const sampleRevealedExport = JSON.parse(JSON.stringify(sampleRedactedExport));
sampleRevealedExport.redacted = false;
sampleRevealedExport.findings[0].matched_text = "postgres://admin:Password123@db.internal.staging.co:5432/main";
sampleRevealedExport.findings[1].matched_text = "john.doe@gmail.com";
sampleRevealedExport.findings[2].matched_text = "db.internal";

// --- parseExport ---
test("parseExport rejects invalid JSON with a clear message, not a stack trace", () => {
  const result = parseExport("{not valid json");
  assert.strictEqual(result.ok, false);
  assert.ok(result.error.length > 0);
  assert.ok(!result.error.includes("SyntaxError"), "error message should not leak a raw JS exception");
});

test("parseExport rejects a JSON file with no findings array", () => {
  const result = parseExport(JSON.stringify({ hello: "world" }));
  assert.strictEqual(result.ok, false);
  assert.ok(result.error.toLowerCase().includes("findings"));
});

test("parseExport accepts a valid opsec-scan export", () => {
  const result = parseExport(JSON.stringify(sampleRedactedExport));
  assert.strictEqual(result.ok, true);
  assert.strictEqual(result.data.findings.length, 3);
});

// --- filterFindings ---
test("filterFindings with no filters returns everything", () => {
  const result = filterFindings(sampleRedactedExport.findings, {});
  assert.strictEqual(result.length, 3);
});

test("filterFindings by category narrows correctly", () => {
  const result = filterFindings(sampleRedactedExport.findings, { category: "credentials" });
  assert.strictEqual(result.length, 1);
  assert.strictEqual(result[0].rule_id, "db_connection_string");
});

test("filterFindings by risk level narrows correctly", () => {
  const result = filterFindings(sampleRedactedExport.findings, { riskLevel: "LOW" });
  assert.strictEqual(result.length, 1);
  assert.strictEqual(result[0].rule_id, "internal_hostname");
});

test("filterFindings search matches rule_id, origin, and context", () => {
  const result = filterFindings(sampleRedactedExport.findings, { search: "personal_email" });
  assert.strictEqual(result.length, 1);
});

test("filterFindings search is case-insensitive", () => {
  const result = filterFindings(sampleRedactedExport.findings, { search: "PERSONAL_EMAIL" });
  assert.strictEqual(result.length, 1);
});

test("filterFindings combining category + search narrows further", () => {
  const result = filterFindings(sampleRedactedExport.findings, { category: "credentials", search: "email" });
  assert.strictEqual(result.length, 0);
});

// --- sortFindings ---
test("sortFindings risk_desc puts CRITICAL first", () => {
  const result = sortFindings(sampleRedactedExport.findings, "risk_desc");
  assert.strictEqual(result[0].risk_label, "CRITICAL");
  assert.strictEqual(result[result.length - 1].risk_label, "LOW");
});

test("sortFindings risk_asc puts LOW first", () => {
  const result = sortFindings(sampleRedactedExport.findings, "risk_asc");
  assert.strictEqual(result[0].risk_label, "LOW");
});

test("sortFindings does not mutate the original array", () => {
  const original = sampleRedactedExport.findings.slice();
  sortFindings(sampleRedactedExport.findings, "risk_asc");
  assert.deepStrictEqual(sampleRedactedExport.findings.map(f => f.rule_id), original.map(f => f.rule_id));
});

// --- countByLabel / countByCategory ---
test("countByLabel tallies correctly", () => {
  const counts = countByLabel(sampleRedactedExport.findings);
  assert.strictEqual(counts.CRITICAL, 1);
  assert.strictEqual(counts.MEDIUM, 1);
  assert.strictEqual(counts.LOW, 1);
  assert.strictEqual(counts.HIGH, 0);
});

test("countByCategory tallies correctly", () => {
  const counts = countByCategory(sampleRedactedExport.findings);
  assert.strictEqual(counts.credentials, 1);
  assert.strictEqual(counts.personal, 1);
  assert.strictEqual(counts.infrastructure, 1);
});

// --- isRevealable: the actual safety-critical logic ---
test("isRevealable is false when the export was redacted at generation time", () => {
  const finding = sampleRedactedExport.findings[0];
  assert.strictEqual(isRevealable(true, finding), false);
});

test("isRevealable is true when the export has real values and wasn't redacted", () => {
  const finding = sampleRevealedExport.findings[0];
  assert.strictEqual(isRevealable(false, finding), true);
});

test("isRevealable is false even on a non-redacted export if this specific value is still the placeholder", () => {
  // Defensive case: a hand-edited or malformed file claims redacted:false
  // but this particular finding's matched_text is still the placeholder.
  const finding = { matched_text: REDACTED_PLACEHOLDER };
  assert.strictEqual(isRevealable(false, finding), false);
});

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed > 0 ? 1 : 0);
