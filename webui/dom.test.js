const fs = require("fs");
const path = require("path");
const { JSDOM } = require("jsdom");

const html = fs.readFileSync(path.join(__dirname, "findings_explorer.html"), "utf8");

// Fixtures built inline (matching the real shape produced by
// json_export.py) so this test suite is self-contained and doesn't
// depend on having run the Python CLI first to generate sample files.
const REDACTED_PLACEHOLDER = "\u2588".repeat(18);

function buildExport(redacted) {
  const base = {
    generated_at: "2026-09-03T12:00:00Z",
    redacted,
    total_findings: 3,
    findings: [
      {
        risk_score: 10.0, risk_label: "CRITICAL", rule_id: "db_connection_string", category: "credentials",
        matched_text: redacted ? REDACTED_PLACEHOLDER : "postgres://admin:Password123@db.internal.staging.co:5432/main",
        matched_text_length: 61, base_severity: 9.0, entropy_score: null,
        identity_confidence: 1.5, identity_reason: "Direct match against known identity string 'staging.co'",
        exposure_level: "public_reachable", source_type: "git_patch", origin: "/repo/secret.txt", context: "commit abc123",
        occurrence_count: 3, metadata: {},
      },
      {
        risk_score: 5.06, risk_label: "MEDIUM", rule_id: "personal_email_domain", category: "personal",
        matched_text: redacted ? REDACTED_PLACEHOLDER : "john.doe@gmail.com",
        matched_text_length: 19, base_severity: 4.5, entropy_score: null,
        identity_confidence: 1.5, identity_reason: "Direct match against known identity string 'john.doe@gmail.com'",
        exposure_level: "local_only", source_type: "git_commit_meta", origin: "/repo", context: "commit def456 (author email)",
        occurrence_count: 8, metadata: {},
      },
      {
        risk_score: 2.81, risk_label: "LOW", rule_id: "internal_hostname", category: "infrastructure",
        matched_text: redacted ? REDACTED_PLACEHOLDER : "db.internal",
        matched_text_length: 11, base_severity: 7.5, entropy_score: null,
        identity_confidence: 0.5, identity_reason: "No correlation found against target identity profile (generic/low-confidence match)",
        exposure_level: "local_only", source_type: "git_patch", origin: "/repo", context: "commit ghi789",
        occurrence_count: 1, metadata: {},
      },
    ],
  };
  return JSON.stringify(base);
}

const redactedExport = buildExport(true);
const revealedExport = buildExport(false);

const testQueue = [];
function test(name, fn) { testQueue.push([name, fn]); }

function freshDom() {
  return new JSDOM(html, { runScripts: "dangerously", pretendToBeVisual: true });
}

// jsdom doesn't implement FileReader, so we shim a minimal one that
// drives the exact same "change" event path the real file-picker uses —
// this tests the actual DOM-rendering code in the HTML file, not a
// reimplementation of it.
function loadJsonIntoDom(dom, jsonText) {
  const win = dom.window;
  class FakeFileReader {
    readAsText(file) {
      setTimeout(() => {
        this.result = file.__content;
        if (this.onload) this.onload({ target: this });
      }, 0);
    }
  }
  win.FileReader = FakeFileReader;

  const file = { __content: jsonText, name: "export.json" };
  const fileInput = win.document.getElementById("file-input");
  Object.defineProperty(fileInput, "files", { value: [file], writable: true });
  fileInput.dispatchEvent(new win.Event("change"));
}

function wait(ms) { return new Promise((resolve) => setTimeout(resolve, ms)); }

test("empty state shows before any file is loaded", async () => {
  const dom = freshDom();
  const doc = dom.window.document;
  if (doc.getElementById("empty-state").style.display === "none") throw new Error("empty state should be visible initially");
  if (doc.getElementById("docket").style.display === "block") throw new Error("docket should not be visible before load");
});

test("invalid JSON shows a clean error, not a crash", async () => {
  const dom = freshDom();
  loadJsonIntoDom(dom, "{not valid json");
  await wait(20);
  const doc = dom.window.document;
  const err = doc.getElementById("error-banner");
  if (err.style.display !== "block") throw new Error("error banner should be visible");
  if (!err.textContent.includes("valid JSON")) throw new Error("error message should mention invalid JSON, got: " + err.textContent);
});

test("valid redacted export renders docket summary and findings", async () => {
  const dom = freshDom();
  loadJsonIntoDom(dom, redactedExport);
  await wait(20);
  const doc = dom.window.document;
  if (doc.getElementById("docket").style.display !== "block") throw new Error("docket should be visible after load");
  const articles = doc.getElementById("findings-list").querySelectorAll(".finding");
  if (articles.length !== 3) throw new Error("expected 3 findings rendered, got " + articles.length);
});

test("CRITICAL finding is sorted first by default", async () => {
  const dom = freshDom();
  loadJsonIntoDom(dom, redactedExport);
  await wait(20);
  const doc = dom.window.document;
  const firstStamp = doc.querySelector(".finding .stamp");
  if (!firstStamp.textContent.includes("CRITICAL")) throw new Error("expected CRITICAL first, got: " + firstStamp.textContent);
});

test("redacted export shows unavailable-reveal note, not a broken reveal button", async () => {
  const dom = freshDom();
  loadJsonIntoDom(dom, redactedExport);
  await wait(20);
  const doc = dom.window.document;
  const revealBtns = doc.querySelectorAll(".reveal-btn");
  const unavailableNotes = doc.querySelectorAll(".reveal-unavailable");
  if (revealBtns.length !== 0) throw new Error("a redacted export should not offer any working reveal buttons, found " + revealBtns.length);
  if (unavailableNotes.length !== 3) throw new Error("expected 3 'redacted at export time' notes, got " + unavailableNotes.length);
});

test("revealed export offers working reveal buttons that show real values", async () => {
  const dom = freshDom();
  loadJsonIntoDom(dom, revealedExport);
  await wait(20);
  const doc = dom.window.document;
  const revealBtns = doc.querySelectorAll(".reveal-btn[data-action='reveal']");
  if (revealBtns.length !== 3) throw new Error("expected 3 reveal buttons on a non-redacted export, got " + revealBtns.length);

  revealBtns[0].click();
  const revealedValue = doc.querySelector(".evidence-value.revealed");
  if (!revealedValue) throw new Error("clicking reveal should show the real value");
  if (!revealedValue.textContent.includes("postgres://")) throw new Error("revealed value should show the real connection string, got: " + revealedValue.textContent);
});

test("hide button re-redacts a revealed value", async () => {
  const dom = freshDom();
  loadJsonIntoDom(dom, revealedExport);
  await wait(20);
  const doc = dom.window.document;
  doc.querySelector(".reveal-btn[data-action='reveal']").click();
  doc.querySelector(".reveal-btn[data-action='hide']").click();
  const revealedValues = doc.querySelectorAll(".evidence-value.revealed");
  if (revealedValues.length !== 0) throw new Error("after clicking hide, no value should remain revealed");
});

test("search filter narrows results and updates the count", async () => {
  const dom = freshDom();
  loadJsonIntoDom(dom, redactedExport);
  await wait(20);
  const doc = dom.window.document;
  const win = dom.window;
  const searchInput = doc.getElementById("search-input");
  searchInput.value = "personal_email";
  searchInput.dispatchEvent(new win.Event("input"));

  const articles = doc.querySelectorAll(".finding");
  if (articles.length !== 1) throw new Error("expected 1 result after search filter, got " + articles.length);
  const count = doc.getElementById("result-count").textContent;
  if (!count.includes("1 of 3")) throw new Error("result count should read '1 of 3 shown', got: " + count);
});

test("category filter combined with search narrows to zero and shows no-results state", async () => {
  const dom = freshDom();
  loadJsonIntoDom(dom, redactedExport);
  await wait(20);
  const doc = dom.window.document;
  const win = dom.window;
  doc.getElementById("category-filter").value = "credentials";
  doc.getElementById("category-filter").dispatchEvent(new win.Event("change"));
  doc.getElementById("search-input").value = "email";
  doc.getElementById("search-input").dispatchEvent(new win.Event("input"));

  if (doc.getElementById("no-results").style.display !== "block") throw new Error("no-results state should show when filters exclude everything");
});

test("risk level filter works", async () => {
  const dom = freshDom();
  loadJsonIntoDom(dom, redactedExport);
  await wait(20);
  const doc = dom.window.document;
  const win = dom.window;
  doc.getElementById("risk-filter").value = "LOW";
  doc.getElementById("risk-filter").dispatchEvent(new win.Event("change"));
  const articles = doc.querySelectorAll(".finding");
  if (articles.length !== 1) throw new Error("expected 1 LOW finding, got " + articles.length);
});

test("XSS payload in a finding field is escaped, not executed or rendered as real markup", async () => {
  const dom = freshDom();
  const maliciousExport = JSON.stringify({
    generated_at: "2026-01-01T00:00:00Z", redacted: false, total_findings: 1,
    findings: [{
      risk_score: "not-a-number", risk_label: "<img src=x onerror=window.__xss_risk=true>", rule_id: "test", category: "system",
      matched_text: "<img src=x onerror=window.__xss_img=true>", matched_text_length: 10,
      base_severity: 5.0, entropy_score: "not-a-number", identity_confidence: "<svg onload=window.__xss_conf=true>",
      identity_reason: "<script>window.__xss_fired = true</script>",
      exposure_level: "local_only", source_type: "git_patch",
      origin: "<script>window.__xss_fired2 = true</script>", context: "test", occurrence_count: 1, metadata: {},
    }],
  });
  loadJsonIntoDom(dom, maliciousExport);
  await wait(20);
  const win = dom.window;
  const listEl = win.document.getElementById("findings-list");

  // The real safety questions: did any payload execute, and did any
  // payload become an actual parsed <script>/<img> element (as opposed
  // to inert escaped text that happens to render back out with literal
  // "<" characters inside an already-safe attribute value or text node —
  // that's expected and fine, HTML attribute serialization doesn't need
  // to re-escape "<" the way element content does).
  if (win.__xss_fired || win.__xss_fired2 || win.__xss_img || win.__xss_risk || win.__xss_conf) throw new Error("XSS payload executed — escaping or numeric validation is broken");
  if (listEl.querySelectorAll("script").length > 0) throw new Error("a real <script> element was created in the DOM");
  if (listEl.querySelectorAll("img").length > 0) throw new Error("a real <img> element was created in the DOM");
  if (listEl.querySelectorAll("svg").length > 0) throw new Error("a real <svg> element was created in the DOM");
  if (listEl.querySelectorAll("img").length > 0) throw new Error("a real <img> element was created in the DOM");

  // And the visible text content (what a person actually reads) should
  // show the payload as literal text, not silently swallow or misrender it.
  if (!listEl.textContent.includes("<script>window.__xss_fired = true</script>")) {
    throw new Error("expected the payload to appear as literal visible text in the identity-reason note");
  }
});

test("total findings count in case metadata matches the loaded file", async () => {
  const dom = freshDom();
  loadJsonIntoDom(dom, redactedExport);
  await wait(20);
  const doc = dom.window.document;
  const meta = doc.getElementById("case-meta").textContent;
  if (!meta.includes("3 findings")) throw new Error("case meta should mention 3 findings, got: " + meta);
  if (!meta.includes("redacted export")) throw new Error("case meta should flag this as a redacted export, got: " + meta);
});

test("file with no findings array is rejected with a clear message", async () => {
  const dom = freshDom();
  loadJsonIntoDom(dom, JSON.stringify({ hello: "world" }));
  await wait(20);
  const doc = dom.window.document;
  const err = doc.getElementById("error-banner");
  if (err.style.display !== "block") throw new Error("error banner should show for a non-export JSON file");
  if (!err.textContent.toLowerCase().includes("findings")) throw new Error("error should mention the missing findings array");
});

(async () => {
  let passed = 0, failed = 0;
  for (const [name, fn] of testQueue) {
    try {
      await fn();
      console.log(`PASS: ${name}`);
      passed++;
    } catch (e) {
      console.log(`FAIL: ${name}`);
      console.log(`  ${e.message}`);
      failed++;
    }
  }
  console.log(`\n${passed} passed, ${failed} failed`);
  process.exit(failed > 0 ? 1 : 0);
})();
