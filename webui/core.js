// Core logic for the OPSEC Findings Explorer, kept as pure functions so
// it can be unit-tested under Node before being embedded in the final
// single-file HTML artifact.

const STAMP_COLORS = {
  CRITICAL: "#c75854",
  HIGH: "#c07f3f",
  MEDIUM: "#b8a13f",
  LOW: "#3f8f6e",
};

const CATEGORY_LABELS = {
  credentials: "Credentials & Keys",
  infrastructure: "Infrastructure Exposure",
  personal: "Personal Identity",
  system: "System Footprint",
};

const REDACTED_PLACEHOLDER = "\u2588".repeat(18); // matches the Python export's redaction bar

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

// Validates the uploaded file has the shape produced by `opsec-scan
// --json-output`. Returns { ok: true, data } or { ok: false, error }
// with a message written for the person using the tool, not a stack trace.
function parseExport(rawText) {
  let data;
  try {
    data = JSON.parse(rawText);
  } catch (e) {
    return { ok: false, error: "That file isn't valid JSON. Make sure you're loading the file from --json-output, not a report.html or .pdf." };
  }
  if (!data || typeof data !== "object") {
    return { ok: false, error: "That file doesn't look like an opsec-scan export." };
  }
  if (!Array.isArray(data.findings)) {
    return { ok: false, error: "This JSON file has no 'findings' array — it doesn't look like an opsec-scan export." };
  }
  return { ok: true, data };
}

function filterFindings(findings, filters) {
  const { search, category, riskLevel } = filters;
  const q = (search || "").trim().toLowerCase();

  return findings.filter((f) => {
    if (category && category !== "all" && f.category !== category) return false;
    if (riskLevel && riskLevel !== "all" && f.risk_label !== riskLevel) return false;
    if (q) {
      const haystack = [f.rule_id, f.category, f.origin, f.context, f.identity_reason]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();
      if (!haystack.includes(q)) return false;
    }
    return true;
  });
}

function sortFindings(findings, sortBy) {
  const copy = findings.slice();
  if (sortBy === "risk_desc" || !sortBy) {
    copy.sort((a, b) => b.risk_score - a.risk_score);
  } else if (sortBy === "risk_asc") {
    copy.sort((a, b) => a.risk_score - b.risk_score);
  } else if (sortBy === "category") {
    copy.sort((a, b) => (a.category || "").localeCompare(b.category || ""));
  } else if (sortBy === "occurrence") {
    copy.sort((a, b) => (b.occurrence_count || 1) - (a.occurrence_count || 1));
  }
  return copy;
}

function countByLabel(findings) {
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  for (const f of findings) {
    if (counts[f.risk_label] !== undefined) counts[f.risk_label] += 1;
  }
  return counts;
}

function countByCategory(findings) {
  const counts = {};
  for (const f of findings) {
    counts[f.category] = (counts[f.category] || 0) + 1;
  }
  return counts;
}

// A finding's matched_text is only genuinely revealable client-side if
// the export itself wasn't redacted at generation time. If it was
// (data.redacted === true), the real value simply isn't in the file —
// no client-side toggle can show what was never sent, so the UI must
// say that plainly instead of rendering a reveal button that silently
// does nothing.
function isRevealable(exportWasRedacted, finding) {
  return exportWasRedacted === false && finding.matched_text !== REDACTED_PLACEHOLDER;
}

module.exports = {
  STAMP_COLORS,
  CATEGORY_LABELS,
  REDACTED_PLACEHOLDER,
  escapeHtml,
  parseExport,
  filterFindings,
  sortFindings,
  countByLabel,
  countByCategory,
  isRevealable,
};
