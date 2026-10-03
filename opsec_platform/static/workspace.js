"use strict";
// Signed-in workspace: Operations Center, scans, findings explorer,
// identity profile, CLI tokens, account and organization management.
// Hash routes (#/overview, #/scan/<id>, ...) keep everything in one
// document that the server only serves to a valid session.

const $ = (id) => document.getElementById(id);
const view = () => $("view");
const LABELS = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
const state = { user: null, caps: null, poll: null, route: "" };

// ------------------------------------------------------------------ utils

function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;" })[c]);
}
// API timestamps are UTC; SQLite returns them without an offset.
function toDate(value) {
  const s = String(value);
  return new Date(/[zZ]|[+-]\d\d:?\d\d$/.test(s) ? s : s + "Z");
}
function fmtDate(value) {
  if (!value) return "—";
  try { return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(toDate(value)); } catch { return String(value); }
}
function ago(value) {
  if (!value) return "";
  const s = Math.max(0, (Date.now() - toDate(value).getTime()) / 1000);
  if (s < 60) return "just now";
  if (s < 3600) return Math.floor(s / 60) + " min ago";
  if (s < 86400) return Math.floor(s / 3600) + " h ago";
  return Math.floor(s / 86400) + " d ago";
}
function notice(type, message) {
  const el = $("notice");
  el.className = "notice show " + type;
  el.textContent = message;
  if (type === "success") setTimeout(() => { if (el.textContent === message) clearNotice(); }, 5000);
}
function clearNotice() { const el = $("notice"); el.className = "notice"; el.textContent = ""; }

async function api(url, options = {}) {
  const isForm = options.body instanceof FormData;
  const response = await fetch(url, {
    credentials: "same-origin",
    ...options,
    headers: { ...(options.body && !isForm ? { "Content-Type": "application/json" } : {}), ...(options.headers || {}) },
  });
  if (response.status === 401) { window.location.assign("/login"); throw new Error("Signed out."); }
  const type = response.headers.get("content-type") || "";
  const body = type.includes("application/json") ? await response.json() : null;
  if (!response.ok) {
    const detail = body?.detail;
    const message = Array.isArray(detail) ? detail.map((x) => x.msg || "Invalid input").join(" ") : (detail || "Request failed (" + response.status + ").");
    const error = new Error(message);
    error.status = response.status;
    throw error;
  }
  return body;
}

function sev(label) { return '<span class="sev ' + esc(label) + '">' + esc(label) + "</span>"; }
function statusPill(status) { return '<span class="status-pill ' + esc(status) + '">' + esc(status) + "</span>"; }
function counts(s) {
  const parts = [["c", s.critical_count ?? s.critical], ["h", s.high_count ?? s.high], ["m", s.medium_count ?? s.medium], ["l", s.low_count ?? s.low]];
  return '<span class="counts" aria-label="Critical, high, medium, low">' + parts.map(([k, v]) => '<span class="count ' + k + (v ? "" : " zero") + '">' + (v ?? 0) + "</span>").join("") + "</span>";
}
const SOURCE_LABEL = { cli_upload: "CLI upload", json_import: "JSON import", media_upload: "Media upload", git_url: "Repository", monitor: "Monitoring" };
function sourceTag(source) { return '<span class="tag">' + esc(SOURCE_LABEL[source] || source) + "</span>"; }
function pageHead(eyebrow, title, text, actions = "") {
  return '<div class="page-head"><div><div class="eyebrow">' + esc(eyebrow) + "</div><h1>" + esc(title) + "</h1>" + (text ? "<p>" + text + "</p>" : "") + "</div>" + (actions ? '<div class="button-row">' + actions + "</div>" : "") + "</div>";
}
function emptyState(title, text, action = "") {
  return '<div class="card empty-state"><h3>' + esc(title) + "</h3><p>" + text + "</p>" + action + "</div>";
}
function applyBarWidths(root = document) {
  root.querySelectorAll("[data-w]").forEach((el) => { el.style.width = Math.max(2, Math.min(100, Number(el.dataset.w))) + "%"; });
}
function stopPolling() { if (state.poll) { clearTimeout(state.poll); state.poll = null; } }
function schedule(fn, ms) { stopPolling(); state.poll = setTimeout(fn, ms); }

// ------------------------------------------------------------------ router

const routes = {
  overview: renderOverview,
  summary: renderSummary,
  findings: renderFindings,
  targets: renderTargets,
  infra: renderInfra,
  graph: renderGraph,
  integrations: renderIntegrations,
  rules: renderRules,
  scans: renderScans,
  new: renderNewScan,
  scan: renderScan,
  profile: renderProfile,
  tokens: renderTokens,
  account: renderAccount,
  org: renderOrg,
};

async function route() {
  stopPolling();
  clearNotice();
  const parts = (location.hash.replace(/^#\/?/, "") || "overview").split("/");
  const name = routes[parts[0]] ? parts[0] : "overview";
  state.route = location.hash;
  document.querySelectorAll("[data-nav]").forEach((a) => {
    const active = a.dataset.nav === name || (name === "scan" && a.dataset.nav === "scans");
    a.classList.toggle("active", active);
    if (active) a.setAttribute("aria-current", "page"); else a.removeAttribute("aria-current");
  });
  $("wsNav").classList.remove("open");
  $("navToggle").setAttribute("aria-expanded", "false");
  view().innerHTML = '<div class="skeleton"></div><div class="skeleton"></div><div class="skeleton"></div>';
  try {
    await routes[name](...parts.slice(1));
  } catch (error) {
    if (error.status === 404) view().innerHTML = emptyState("Not found", "That item does not exist or you do not have access to it.", '<a class="btn" href="#/scans">Back to scans</a>');
    else view().innerHTML = emptyState("Something went wrong", esc(error.message || "Could not load this page."), '<button class="btn" type="button" data-action="retry">Try again</button>');
    view().querySelector('[data-action="retry"]')?.addEventListener("click", route);
  }
  $("main").focus({ preventScroll: true });
}

// ------------------------------------------------------------------ overview

function trendChart(trend) {
  if (!trend.length) return '<p class="hint">Run a few scans to see the trend.</p>';
  const W = 640, H = 170, pad = 22, n = trend.length;
  const max = Math.max(1, ...trend.map((t) => t.critical + t.high + t.medium + t.low));
  const bw = Math.max(4, Math.min(36, (W - pad * 2) / n - 6));
  const colors = { critical: "#ff7a75", high: "#f5a35c", medium: "#e8d26a", low: "#7fb3d9" };
  let bars = "";
  trend.forEach((t, i) => {
    const x = pad + i * ((W - pad * 2) / n) + 3;
    let y = H - pad;
    ["low", "medium", "high", "critical"].forEach((k) => {
      const h = (t[k] / max) * (H - pad * 2);
      if (h > 0) { y -= h; bars += '<rect x="' + x.toFixed(1) + '" y="' + y.toFixed(1) + '" width="' + bw.toFixed(1) + '" height="' + h.toFixed(1) + '" rx="2" fill="' + colors[k] + '"><title>' + esc(t.target_label) + " · " + esc(fmtDate(t.created_at)) + " · " + k + ": " + t[k] + "</title></rect>"; }
    });
  });
  return '<svg class="bar-chart" viewBox="0 0 ' + W + " " + H + '" role="img" aria-label="Findings per scan, oldest to newest">' +
    '<line x1="' + pad + '" y1="' + (H - pad) + '" x2="' + (W - pad) + '" y2="' + (H - pad) + '" stroke="#25303a"/>' +
    '<text x="' + pad + '" y="14">' + max + ' findings</text>' + bars + "</svg>" +
    '<div class="legend"><span><i class="c"></i>Critical</span><span><i class="h"></i>High</span><span><i class="m"></i>Medium</span><span><i class="l"></i>Low</span></div>';
}

function hbars(rows, key) {
  if (!rows.length) return '<p class="hint">No findings yet.</p>';
  const max = Math.max(...rows.map((r) => r.count));
  return rows.map((r) => '<div class="hbar"><div><div class="mono small">' + esc(r[key]) + '</div><div class="track"><div class="fill" data-w="' + (r.count / max) * 100 + '"></div></div></div><div class="num">' + r.count + "</div></div>").join("");
}

async function renderOverview() {
  const scope = new URLSearchParams(location.hash.split("?")[1] || "").get("scope") === "org" && state.user?.is_org_admin ? "org" : "mine";
  const data = await api("/scans/overview?scope=" + scope);
  const o = data.open_findings;
  const scopeToggle = state.user?.is_org_admin && state.user.org_id
    ? '<div class="tabs-inline" role="tablist"><button type="button" data-scope="mine" class="' + (scope === "mine" ? "active" : "") + '">My scans</button><button type="button" data-scope="org" class="' + (scope === "org" ? "active" : "") + '">Organization</button></div>' : "";
  let html = pageHead("Operations Center", "Exposure overview", "Open findings are taken from the latest completed scan of each target. New and resolved counts compare it with that target's previous scan.",
    '<a class="secondary compact" href="#/summary">Executive summary</a><a class="btn" href="#/new">New scan</a>');
  html += scopeToggle;
  if (!data.scans_total) {
    view().innerHTML = html + emptyState("No scans yet", "Scan a public repository, upload images or documents, or import results from the CLI. Your first results will show up here.", '<a class="btn" href="#/new">Start a scan</a>');
    bindScope();
    return;
  }
  html += '<div class="grid grid-4">' +
    '<div class="tile crit"><span>Critical open</span><strong>' + o.CRITICAL + "</strong></div>" +
    '<div class="tile high"><span>High open</span><strong>' + o.HIGH + "</strong></div>" +
    '<div class="tile med"><span>Medium open</span><strong>' + o.MEDIUM + "</strong></div>" +
    '<div class="tile low"><span>Low open</span><strong>' + o.LOW + "</strong><small>" + data.targets.length + " target(s) · " + data.scans_total + " scan(s)</small></div></div>";
  html += '<div class="grid grid-wide section"><section class="card"><h3>Findings per scan</h3><p class="card-subtext">Last ' + data.trend.length + " completed scans.</p>" + trendChart(data.trend) + "</section>" +
    '<section class="card"><h3>Most frequent rules</h3><p class="card-subtext">Across the latest scan of each target.</p>' + hbars(data.top_rules, "rule_id") + "</section></div>";
  const running = (data.scans_by_status.running || 0) + (data.scans_by_status.queued || 0);
  html += '<section class="section"><div class="card-head"><div><h3>Targets</h3><p class="card-subtext">' + (running ? running + " scan(s) in progress. " : "") + "Sorted by severity.</p></div></div>";
  html += '<div class="table-wrap section"><table><thead><tr><th>Target</th><th>Open findings</th><th class="num">Risk max</th><th>Since previous</th><th>Last scanned</th></tr></thead><tbody>' +
    data.targets.map((t) => '<tr class="clickable" data-href="#/scan/' + esc(t.latest_scan_id) + '"><td><div class="cell-main">' + esc(t.target_label) + '</div><div class="cell-sub">' + sourceTag(t.source) + " · " + t.scans + " scan(s)</div></td><td>" + counts(t) + '</td><td class="num">' + t.max_risk_score.toFixed(1) + "</td><td>" +
      (t.new === null ? '<span class="faint small">First scan</span>' : '<span class="small">+' + t.new + " new · −" + t.resolved + " resolved</span>") + '</td><td class="small">' + esc(ago(t.latest_at)) + "</td></tr>").join("") +
    "</tbody></table></div></section>";
  if (data.categories.length) html += '<section class="card section"><h3>Categories</h3>' + hbars(data.categories, "category") + "</section>";
  view().innerHTML = html;
  applyBarWidths(view());
  bindRowLinks();
  bindScope();
  if (running) schedule(() => { if (location.hash.startsWith("#/overview") || !location.hash) renderOverview().catch(() => {}); }, 5000);
}

function bindScope() {
  view().querySelectorAll("[data-scope]").forEach((b) => b.addEventListener("click", () => {
    location.hash = b.dataset.scope === "org" ? "#/overview?scope=org" : "#/overview";
  }));
}
function bindRowLinks() {
  view().querySelectorAll("tr[data-href]").forEach((tr) => {
    tr.tabIndex = 0;
    tr.addEventListener("click", () => { location.hash = tr.dataset.href; });
    tr.addEventListener("keydown", (e) => { if (e.key === "Enter") location.hash = tr.dataset.href; });
  });
}

// ------------------------------------------------------------------ scans list

async function renderScans() {
  const params = new URLSearchParams(location.hash.split("?")[1] || "");
  const scope = params.get("scope") === "org" && state.user?.is_org_admin ? "org" : "mine";
  const status = params.get("status") || "";
  const q = params.get("q") || "";
  const query = new URLSearchParams({ scope, limit: "100" });
  if (status) query.set("status", status);
  if (q) query.set("q", q);
  const scans = await api("/scans?" + query);
  let html = pageHead("Scanner", "Scan history", "Every scan you have run or imported. Open one to explore its findings.", '<a class="btn" href="#/new">New scan</a>');
  html += '<form class="filters" id="scanFilters">' +
    (state.user?.is_org_admin && state.user.org_id ? '<select class="select" name="scope" aria-label="Scope"><option value="mine">My scans</option><option value="org"' + (scope === "org" ? " selected" : "") + ">Organization</option></select>" : "") +
    '<select class="select" name="status" aria-label="Status"><option value="">All statuses</option>' + ["completed", "running", "queued", "failed"].map((s) => '<option value="' + s + '"' + (s === status ? " selected" : "") + ">" + s + "</option>").join("") + "</select>" +
    '<input class="input grow" name="q" type="search" placeholder="Search target name" value="' + esc(q) + '" aria-label="Search scans"><button class="secondary compact" type="submit">Apply</button></form>';
  if (!scans.length) {
    html += emptyState(q || status ? "No matching scans" : "No scans yet", q || status ? "Try different filters." : "Start by scanning a public repository or uploading files.", '<a class="btn" href="#/new">New scan</a>');
  } else {
    html += '<div class="table-wrap"><table><thead><tr><th>Target</th><th>Status</th><th>Findings</th><th class="num">Risk max</th><th>Started</th></tr></thead><tbody>' +
      scans.map((s) => '<tr class="clickable" data-href="#/scan/' + esc(s.id) + '"><td><div class="cell-main">' + esc(s.target_label) + '</div><div class="cell-sub">' + sourceTag(s.source) + (s.owner_email ? " · " + esc(s.owner_email) : "") + "</div></td><td>" + statusPill(s.status) + (s.status === "failed" && s.error ? '<div class="cell-sub">' + esc(s.error) + "</div>" : "") + "</td><td>" + (s.status === "completed" ? counts(s) : '<span class="faint">—</span>') + '</td><td class="num">' + (s.status === "completed" ? s.max_risk_score.toFixed(1) : "—") + '</td><td class="small">' + esc(fmtDate(s.created_at)) + "</td></tr>").join("") +
      "</tbody></table></div>";
  }
  view().innerHTML = html;
  bindRowLinks();
  $("scanFilters").addEventListener("submit", (e) => {
    e.preventDefault();
    const f = new FormData(e.target);
    const next = new URLSearchParams();
    for (const [k, v] of f.entries()) if (v && !(k === "scope" && v === "mine")) next.set(k, v);
    location.hash = "#/scans" + (next.toString() ? "?" + next : "");
  });
  view().querySelectorAll("#scanFilters select").forEach((s) => s.addEventListener("change", () => $("scanFilters").requestSubmit()));
  if (scans.some((s) => s.status === "running" || s.status === "queued")) schedule(() => { if (location.hash.startsWith("#/scans")) renderScans().catch(() => {}); }, 4000);
}

// ------------------------------------------------------------------ new scan

async function renderNewScan(tab) {
  if (!state.caps) state.caps = await api("/scans/capabilities");
  const caps = state.caps;
  const L = caps.limits;
  const active = ["repo", "media", "import"].includes(tab) ? tab : (caps.web_scans_enabled ? "repo" : "import");
  let html = pageHead("Scanner", "New scan", "Findings are scored against your <a class=\"link-button\" href=\"#/profile\">identity profile</a>. Secret values are redacted before anything is stored.");
  html += '<p class="hint">To watch your own domain, website, email address or GitHub account continuously, add it under <a class="link-button" href="#/targets">Monitored targets</a>.</p>';
  if (!caps.rules.ok) html += '<div class="notice show error">Detection rules are not available on this server, so scans cannot run. Ask an administrator to check the deployment.</div>';
  html += '<div class="tabs-inline" role="tablist">' +
    [["repo", "Public repository"], ["media", "Images & documents"], ["import", "Import CLI results"]].map(([k, l]) => '<button type="button" role="tab" data-tab="' + k + '" aria-selected="' + (k === active) + '" class="' + (k === active ? "active" : "") + '">' + l + "</button>").join("") + "</div>";

  if (active === "repo") {
    if (!caps.web_scans_enabled) html += emptyState("Server-side scans are disabled", "This deployment only accepts results uploaded from the CLI.", '<a class="btn" href="#/new/import">Import results</a>');
    else html += '<section class="card"><h3>Scan a public git repository</h3><p class="card-subtext">The server makes a shallow clone, walks commit metadata and patches, then deletes the clone. Allowed hosts: ' + caps.allowed_git_hosts.map(esc).join(", ") + ".</p>" +
      '<form id="repoForm" class="form-grid section"><div class="field"><label for="repoUrl">Repository URL</label><input id="repoUrl" class="input" name="url" type="url" required placeholder="https://github.com/owner/repo" autocomplete="off"></div>' +
      '<div class="form-row"><div class="field"><label for="repoLabel">Label (optional)</label><input id="repoLabel" class="input" name="label" maxlength="120" placeholder="Defaults to the repository path"></div>' +
      '<div class="field"><label for="repoDepth">Commits</label><input id="repoDepth" class="input" name="depth" type="number" min="1" max="' + L.git_max_depth + '" value="' + L.git_default_depth + '"></div></div>' +
      '<p class="hint">Scanning the same URL again lets you compare new and resolved findings. Repositories up to ' + L.git_max_mb + " MB.</p>" +
      '<div><button class="btn" type="submit">Start scan</button></div></form></section>';
  } else if (active === "media") {
    if (!caps.web_scans_enabled) html += emptyState("Server-side scans are disabled", "This deployment only accepts results uploaded from the CLI.", '<a class="btn" href="#/new/import">Import results</a>');
    else html += '<section class="card"><h3>Scan images and documents</h3><p class="card-subtext">EXIF metadata, PDF and Office properties, document text' + (caps.ocr_available ? " and OCR of images" : "") + ". Files are deleted after the scan.</p>" +
      ((!caps.exiftool_available || !caps.ocr_available) ? '<p class="hint section">Not installed on this server: ' + [!caps.exiftool_available && "exiftool (image EXIF)", !caps.ocr_available && "tesseract (image OCR)"].filter(Boolean).join(", ") + ". PDFs and Office documents are fully supported.</p>" : "") +
      '<form id="mediaForm" class="form-grid section"><label class="dropzone" id="dropzone" for="mediaFiles"><strong>Drop files here or choose files</strong><span class="small">' + caps.media_extensions.map(esc).join(" ") + "</span><span class=\"small faint\">Up to " + L.media_max_files + " files, " + L.media_max_file_mb + " MB each, " + L.media_max_total_mb + ' MB total</span></label>' +
      '<input id="mediaFiles" class="sr-only" type="file" multiple accept="' + caps.media_extensions.join(",") + '"><div id="fileList" class="file-list"></div>' +
      '<div class="field"><label for="mediaLabel">Label (optional)</label><input id="mediaLabel" class="input" maxlength="120" placeholder="e.g. Conference slides"></div>' +
      '<div><button class="btn" id="mediaSubmit" type="submit" disabled>Upload and scan</button></div></form></section>';
  } else {
    html += '<div class="grid grid-2"><section class="card"><h3>Upload a findings file</h3><p class="card-subtext">The JSON written by <span class="mono">opsec-scan --json-output</span>. Redacted and revealed exports both work; revealed values are redacted on arrival.</p>' +
      '<form id="importForm" class="form-grid section"><label class="dropzone" id="importDrop" for="importFile"><strong>Choose a findings .json</strong><span class="small faint">Up to ' + L.import_max_mb + " MB, " + L.import_max_findings + ' findings</span></label><input id="importFile" class="sr-only" type="file" accept=".json,application/json"><div id="importName" class="hint"></div>' +
      '<div class="field"><label for="importLabel">Target label</label><input id="importLabel" class="input" maxlength="120" placeholder="Use the same label each time to track changes"></div><div><button id="importSubmit" class="btn" type="submit" disabled>Import</button></div></form></section>' +
      '<section class="card"><h3>Upload straight from the CLI</h3><p class="card-subtext">Create a <a class="link-button" href="#/tokens">CLI access token</a>, then:</p>' +
      '<pre class="code section">export OPSEC_PLATFORM_TOKEN=opsec_pat_…\nopsec-scan --repo . \\\n  --report-activity ' + esc(location.origin) + ' \\\n  --upload-findings \\\n  --target-label my-repo</pre><p class="hint section">Scanning stays on your machine; only redacted findings are uploaded.</p></section></div>';
  }
  view().innerHTML = html;
  view().querySelectorAll("[data-tab]").forEach((b) => b.addEventListener("click", () => { location.hash = "#/new/" + b.dataset.tab; }));
  bindRepoForm();
  bindMediaForm(L);
  bindImportForm();
}

function bindRepoForm() {
  const form = $("repoForm");
  if (!form) return;
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const button = form.querySelector("button[type=submit]");
    button.disabled = true; button.textContent = "Starting…";
    try {
      const body = { url: $("repoUrl").value.trim(), depth: Number($("repoDepth").value) || undefined, label: $("repoLabel").value.trim() || undefined };
      const scan = await api("/scans/git", { method: "POST", body: JSON.stringify(body) });
      location.hash = "#/scan/" + scan.id;
    } catch (error) { notice("error", error.message); button.disabled = false; button.textContent = "Start scan"; }
  });
}

function bindMediaForm(L) {
  const form = $("mediaForm");
  if (!form) return;
  let files = [];
  const input = $("mediaFiles"), zone = $("dropzone");
  const render = () => {
    const total = files.reduce((a, f) => a + f.size, 0);
    $("fileList").innerHTML = files.map((f, i) => '<div class="file-item"><span>' + esc(f.name) + '</span><span class="faint">' + (f.size / 1024 / 1024).toFixed(2) + ' MB <button type="button" class="link-button" data-remove="' + i + '">Remove</button></span></div>').join("") +
      (files.length ? '<p class="hint">' + files.length + " file(s), " + (total / 1024 / 1024).toFixed(2) + " MB</p>" : "");
    $("fileList").querySelectorAll("[data-remove]").forEach((b) => b.addEventListener("click", () => { files.splice(Number(b.dataset.remove), 1); render(); }));
    $("mediaSubmit").disabled = !files.length;
  };
  const add = (list) => {
    for (const f of list) {
      if (files.length >= L.media_max_files) { notice("error", "At most " + L.media_max_files + " files per scan."); break; }
      if (f.size > L.media_max_file_mb * 1024 * 1024) { notice("error", f.name + " is larger than " + L.media_max_file_mb + " MB."); continue; }
      files.push(f);
    }
    render();
  };
  input.addEventListener("change", () => { add(input.files); input.value = ""; });
  ["dragenter", "dragover"].forEach((ev) => zone.addEventListener(ev, (e) => { e.preventDefault(); zone.classList.add("drag"); }));
  ["dragleave", "drop"].forEach((ev) => zone.addEventListener(ev, (e) => { e.preventDefault(); zone.classList.remove("drag"); }));
  zone.addEventListener("drop", (e) => add(e.dataTransfer.files));
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const fd = new FormData();
    files.forEach((f) => fd.append("files", f, f.name));
    const label = $("mediaLabel").value.trim();
    if (label) fd.append("label", label);
    $("mediaSubmit").disabled = true; $("mediaSubmit").textContent = "Uploading…";
    try {
      const scan = await api("/scans/media", { method: "POST", body: fd });
      location.hash = "#/scan/" + scan.id;
    } catch (error) { notice("error", error.message); $("mediaSubmit").disabled = false; $("mediaSubmit").textContent = "Upload and scan"; }
  });
}

function bindImportForm() {
  const form = $("importForm");
  if (!form) return;
  const input = $("importFile");
  input.addEventListener("change", () => {
    const f = input.files[0];
    $("importName").textContent = f ? f.name + " · " + (f.size / 1024).toFixed(1) + " KB" : "";
    $("importSubmit").disabled = !f;
    if (f && !$("importLabel").value) $("importLabel").value = f.name.replace(/\.json$/i, "");
  });
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const fd = new FormData();
    fd.append("file", input.files[0]);
    const label = $("importLabel").value.trim();
    $("importSubmit").disabled = true; $("importSubmit").textContent = "Importing…";
    try {
      const scan = await api("/scans/import" + (label ? "?label=" + encodeURIComponent(label) : ""), { method: "POST", body: fd });
      location.hash = "#/scan/" + scan.id;
    } catch (error) { notice("error", error.message); $("importSubmit").disabled = false; $("importSubmit").textContent = "Import"; }
  });
}

// ------------------------------------------------------------------ scan detail + findings explorer

const explorer = { scanId: null, risk: new Set(), category: "", rule: "", q: "", status: "", sort: "risk", order: "desc", offset: 0, limit: 50, open: new Set() };

async function renderScan(scanId) {
  if (!scanId) { location.hash = "#/scans"; return; }
  const scan = await api("/scans/" + encodeURIComponent(scanId));
  if (explorer.scanId !== scanId) Object.assign(explorer, { scanId, risk: new Set(), category: "", rule: "", q: "", status: "", sort: "risk", order: "desc", offset: 0, open: new Set() });
  const own = scan.user_id === state.user?.id;
  let html = pageHead(SOURCE_LABEL[scan.source] || "Scan", scan.target_label,
    statusPill(scan.status) + " &nbsp;·&nbsp; " + esc(fmtDate(scan.created_at)) + (scan.owner_email && !own ? " &nbsp;·&nbsp; " + esc(scan.owner_email) : ""),
    scan.status === "completed" ? '<a class="secondary compact" href="/scans/' + esc(scan.id) + '/export?format=json">JSON</a><a class="secondary compact" href="/scans/' + esc(scan.id) + '/export?format=csv">CSV</a><a class="secondary compact" href="/scans/' + esc(scan.id) + '/export?format=sarif">SARIF</a>' + (own ? '<button class="danger" type="button" id="deleteScan">Delete</button>' : "") :
      (scan.status === "failed" && own ? '<button class="danger" type="button" id="deleteScan">Delete</button>' : ""));

  if (scan.status === "queued" || scan.status === "running") {
    view().innerHTML = html + '<section class="card empty-state"><h3>' + (scan.status === "queued" ? "Waiting to start" : "Scanning…") + '</h3><p>This page updates on its own. Large repositories can take a minute or two.</p><div class="skeleton"></div></section>';
    schedule(() => { if (location.hash === "#/scan/" + scanId) renderScan(scanId).catch(() => {}); }, 2500);
    return;
  }
  if (scan.status === "failed") {
    view().innerHTML = html + '<div class="notice show error">' + esc(scan.error || "The scan failed.") + "</div>" + emptyState("No results", "Fix the problem above and run the scan again.", '<a class="btn" href="#/new">New scan</a>');
    bindDelete(scan);
    return;
  }

  const st = scan.stats || {};
  const statItems = [
    ["Findings", scan.total_findings], ["Max risk", scan.max_risk_score.toFixed(1)],
    st.commits_scanned !== undefined && ["Commits scanned", st.commits_scanned],
    st.media_files_scanned !== undefined && ["Files scanned", st.media_files_scanned],
    st.scan_mode && ["Mode", st.scan_mode],
    scan.completed_at && ["Completed", fmtDate(scan.completed_at)],
  ].filter(Boolean);
  html += '<div class="grid grid-4"><div class="tile crit"><span>Critical</span><strong>' + scan.critical_count + '</strong></div><div class="tile high"><span>High</span><strong>' + scan.high_count + '</strong></div><div class="tile med"><span>Medium</span><strong>' + scan.medium_count + '</strong></div><div class="tile low"><span>Low</span><strong>' + scan.low_count + "</strong></div></div>";
  html += '<div class="grid grid-wide section"><section class="card"><h3>Scan details</h3><div class="kv-grid">' + statItems.map(([k, v]) => "<div><span>" + esc(k) + "</span><strong>" + esc(v) + "</strong></div>").join("") + "</div>" +
    (Array.isArray(st.notes) && st.notes.length ? '<p class="hint section">' + st.notes.map(esc).join("<br>") + "</p>" : "") + "</section>" +
    '<section class="card" id="diffCard"><h3>Compared with previous scan</h3><div class="skeleton"></div></section></div>';
  html += '<section class="section"><div id="explorer"></div></section>';
  view().innerHTML = html;
  bindDelete(scan);
  loadDiff(scan.id);
  await loadFindings();
}

function bindDelete(scan) {
  $("deleteScan")?.addEventListener("click", async () => {
    if (!window.confirm("Delete this scan and its findings? This cannot be undone.")) return;
    try { await api("/scans/" + encodeURIComponent(scan.id), { method: "DELETE" }); notice("success", "Scan deleted."); location.hash = "#/scans"; } catch (error) { notice("error", error.message); }
  });
}

async function loadDiff(scanId) {
  const card = $("diffCard");
  try {
    const d = await api("/scans/" + encodeURIComponent(scanId) + "/diff");
    if (!d.previous_scan_id) { card.innerHTML = '<h3>Compared with previous scan</h3><p class="hint section">This is the first completed scan for this target label. Scan it again later to see what changed.</p>'; return; }
    const list = (items, title) => items.length ? '<div class="section"><div class="small faint">' + title + '</div>' + items.slice(0, 6).map((f) => '<div class="small section">' + sev(f.risk_label) + ' <span class="mono">' + esc(f.rule_id) + '</span> <span class="preview">' + esc(f.preview) + '</span><div class="cell-sub">' + esc(f.origin || "") + "</div></div>").join("") + (items.length > 6 ? '<div class="hint">and ' + (items.length - 6) + " more</div>" : "") + "</div>" : "";
    card.innerHTML = '<h3>Compared with previous scan</h3><p class="card-subtext">Previous: <a class="link-button" href="#/scan/' + esc(d.previous_scan_id) + '">' + esc(fmtDate(d.previous_created_at)) + '</a></p><div class="diff-summary section"><span><b>' + d.new.length + "</b> new</span><span><b>" + d.resolved.length + "</b> resolved</span><span><b>" + d.still_open + "</b> still open</span></div>" + list(d.new, "New") + list(d.resolved, "Resolved");
  } catch { card.innerHTML = '<h3>Compared with previous scan</h3><p class="hint">Could not load the comparison.</p>'; }
}

async function loadFindings() {
  const host = $("explorer");
  if (!host) return;
  const q = new URLSearchParams({ sort: explorer.sort, order: explorer.order, limit: String(explorer.limit), offset: String(explorer.offset) });
  if (explorer.risk.size) q.set("risk", [...explorer.risk].join(","));
  if (explorer.category) q.set("category", explorer.category);
  if (explorer.rule) q.set("rule", explorer.rule);
  if (explorer.q) q.set("q", explorer.q);
  if (explorer.status) q.set("status", explorer.status);
  const data = await api("/scans/" + encodeURIComponent(explorer.scanId) + "/findings?" + q);
  const f = data.facets;
  const opt = (obj, current, all) => '<option value="">' + all + "</option>" + Object.entries(obj).sort((a, b) => b[1] - a[1]).map(([k, n]) => '<option value="' + esc(k) + '"' + (k === current ? " selected" : "") + ">" + esc(k) + " (" + n + ")</option>").join("");
  let html = '<div class="card-head"><div><h3>Findings explorer</h3><p class="card-subtext">Values are redacted. Use the origin and context to locate each finding.</p></div></div>';
  html += '<div class="filters section">' + LABELS.map((l) => '<button type="button" class="chip' + (explorer.risk.has(l) ? " on" : "") + '" data-risk="' + l + '" aria-pressed="' + explorer.risk.has(l) + '">' + l.toLowerCase() + '<span class="n">' + (f.risk[l] || 0) + "</span></button>").join("") +
    '<select class="select" id="fCategory" aria-label="Category">' + opt(f.category, explorer.category, "All categories") + "</select>" +
    '<select class="select" id="fRule" aria-label="Rule">' + opt(f.rule, explorer.rule, "All rules") + "</select>" +
    '<select class="select" id="fStatus" aria-label="Status">' + opt(f.status || {}, explorer.status, "Any status") + "</select>" +
    '<input class="input grow" id="fSearch" type="search" placeholder="Search origin, context, rule" value="' + esc(explorer.q) + '" aria-label="Search findings">' +
    '<select class="select" id="fSort" aria-label="Sort"><option value="risk:desc">Highest risk</option><option value="risk:asc">Lowest risk</option><option value="rule:asc">Rule A–Z</option><option value="category:asc">Category</option><option value="origin:asc">Origin</option></select></div>';
  if (!data.items.length) {
    html += emptyState(data.total === 0 && !explorer.risk.size && !explorer.q && !explorer.category && !explorer.rule && !explorer.status ? "No findings" : "Nothing matches these filters", data.total === 0 && !explorer.q ? "No detection rule matched anything in this scan." : "Clear a filter to see more.");
  } else {
    html += findingsTable(data.items, explorer.open, false);
    html += pager(data.offset, data.items.length, data.total);
  }
  host.innerHTML = html;
  $("fSort").value = explorer.sort + ":" + explorer.order;
  host.querySelectorAll("[data-risk]").forEach((b) => b.addEventListener("click", () => { explorer.risk.has(b.dataset.risk) ? explorer.risk.delete(b.dataset.risk) : explorer.risk.add(b.dataset.risk); explorer.offset = 0; loadFindings(); }));
  $("fCategory").addEventListener("change", (e) => { explorer.category = e.target.value; explorer.offset = 0; loadFindings(); });
  $("fRule").addEventListener("change", (e) => { explorer.rule = e.target.value; explorer.offset = 0; loadFindings(); });
  $("fSort").addEventListener("change", (e) => { [explorer.sort, explorer.order] = e.target.value.split(":"); explorer.offset = 0; loadFindings(); });
  let timer;
  $("fSearch").addEventListener("input", (e) => { clearTimeout(timer); timer = setTimeout(() => { explorer.q = e.target.value.trim(); explorer.offset = 0; loadFindings().then(() => { const s = $("fSearch"); s.focus(); s.setSelectionRange(s.value.length, s.value.length); }); }, 300); });
  $("fStatus").addEventListener("change", (e) => { explorer.status = e.target.value; explorer.offset = 0; loadFindings(); });
  bindFindingsTable(host, explorer.open, loadFindings);
  $("pgPrev")?.addEventListener("click", () => { explorer.offset = Math.max(0, explorer.offset - explorer.limit); loadFindings(); });
  $("pgNext")?.addEventListener("click", () => { explorer.offset += explorer.limit; loadFindings(); });
}

// ------------------------------------------------------------------ identity profile

async function renderProfile() {
  const p = await api("/profile/identity");
  const area = (id, label, values, hint) => '<div class="field"><label for="' + id + '">' + label + '</label><textarea id="' + id + '" class="input" rows="3">' + esc((values || []).join("\n")) + '</textarea><p class="hint">' + hint + "</p></div>";
  view().innerHTML = pageHead("Scanner", "Identity profile", "Findings that mention these identities score higher than generic matches. This is the web version of the CLI's <span class=\"mono\">target_profile.yaml</span>; it applies to scans you start from now on.") +
    '<section class="card"><form id="profileForm" class="form-grid">' +
    '<div class="field"><label for="pName">Name</label><input id="pName" class="input" maxlength="120" required value="' + esc(p.name) + '"></div>' +
    '<div class="grid grid-2">' + area("pAliases", "Aliases and handles", p.aliases, "One per line. Matched as whole words.") + area("pEmails", "Email addresses", p.emails, "One per line.") +
    area("pDomains", "Domains", p.domains, "Company or internal domains, e.g. acme.internal.") + area("pGithub", "GitHub handles", p.github_handles, "One per line.") + "</div>" +
    '<div class="form-row"><div class="field"><label for="pCoords">Home or office coordinates (optional)</label><input id="pCoords" class="input" placeholder="12.97, 77.59" value="' + esc(p.home_coordinates ? p.home_coordinates.join(", ") : "") + '"><p class="hint">Photos with GPS within 5 km score higher.</p></div></div>' +
    '<div><button class="btn" type="submit">Save profile</button></div></form></section>';
  $("profileForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const lines = (id) => $(id).value.split(/[\n,]/).map((s) => s.trim()).filter(Boolean);
    let coords = null;
    const raw = $("pCoords").value.trim();
    if (raw) {
      const parts = raw.split(/[,\s]+/).map(Number);
      if (parts.length !== 2 || parts.some(Number.isNaN)) { notice("error", "Coordinates must be 'latitude, longitude'."); return; }
      coords = parts;
    }
    try {
      await api("/profile/identity", { method: "PUT", body: JSON.stringify({ name: $("pName").value.trim(), aliases: lines("pAliases"), emails: lines("pEmails"), domains: lines("pDomains"), github_handles: lines("pGithub"), home_coordinates: coords }) });
      notice("success", "Identity profile saved.");
    } catch (error) { notice("error", error.message); }
  });
}

// ------------------------------------------------------------------ tokens

async function renderTokens() {
  const tokens = await api("/auth/tokens");
  let html = pageHead("Account", "CLI access tokens", "Tokens let the CLI upload redacted findings and report scan activity. They cannot sign in, change your account or manage sessions. The token is shown once.");
  html += '<div class="grid grid-wide"><section class="card"><h3>Active tokens</h3>' +
    (tokens.length ? '<div class="members">' + tokens.map((t) => '<div class="member-row"><div class="member-main"><strong>' + esc(t.name) + "</strong><span>" + esc(t.prefix) + "… · created " + esc(fmtDate(t.created_at)) + " · expires " + esc(fmtDate(t.expires_at)) + " · " + (t.last_used_at ? "last used " + esc(ago(t.last_used_at)) : "never used") + '</span></div><div class="member-actions"><button class="danger" type="button" data-revoke-token="' + esc(t.id) + '">Revoke</button></div></div>').join("") + "</div>" : '<p class="hint section">No tokens yet.</p>') +
    '</section><section class="card"><h3>Create a token</h3><form id="tokenForm" class="form-grid section"><div class="field"><label for="tName">Name</label><input id="tName" class="input" maxlength="80" required placeholder="e.g. laptop, CI pipeline"></div>' +
    '<div class="field"><label for="tDays">Expires after</label><select id="tDays" class="select"><option value="30">30 days</option><option value="90" selected>90 days</option><option value="180">180 days</option><option value="365">1 year</option></select></div>' +
    '<div><button class="btn" type="submit">Create token</button></div></form><div id="newToken"></div></section></div>';
  view().innerHTML = html;
  view().querySelectorAll("[data-revoke-token]").forEach((b) => b.addEventListener("click", async () => {
    if (!window.confirm("Revoke this token? Anything using it will stop working.")) return;
    try { await api("/auth/tokens/" + encodeURIComponent(b.dataset.revokeToken), { method: "DELETE" }); notice("success", "Token revoked."); renderTokens(); } catch (error) { notice("error", error.message); }
  }));
  $("tokenForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    try {
      const t = await api("/auth/tokens", { method: "POST", body: JSON.stringify({ name: $("tName").value.trim(), expires_in_days: Number($("tDays").value) }) });
      await renderTokens();
      $("newToken").innerHTML = '<div class="secret-once section"><strong>Copy this token now. It will not be shown again.</strong><pre class="code" id="tokenValue">' + esc(t.token) + '</pre><div class="button-row"><button class="secondary compact" type="button" id="copyToken">Copy</button></div><pre class="code">export OPSEC_PLATFORM_TOKEN=' + esc(t.token) + "\nopsec-scan --repo . --report-activity " + esc(location.origin) + " --upload-findings</pre></div>";
      $("copyToken").addEventListener("click", async () => { try { await navigator.clipboard.writeText(t.token); notice("success", "Token copied."); } catch { notice("info", "Select the token and copy it manually."); } });
    } catch (error) { notice("error", error.message); }
  });
}

// ------------------------------------------------------------------ account

function activityBadge(type) {
  if (/success|created|reported|imported|linked/.test(type)) return "good";
  if (/failed|limited|revoked|deleted/.test(type)) return "warn";
  return "";
}

async function renderAccount() {
  const [user, activity, sessions] = await Promise.all([api("/auth/me"), api("/activity/me?limit=25"), api("/auth/sessions")]);
  state.user = user;
  let html = pageHead("Account", "Account & sessions", "Your identity, active sign-ins and recent activity.");
  html += '<div class="grid grid-2"><section class="card"><h3>Identity</h3><div class="kv">' +
    [["Email", user.email], ["Display name", user.display_name || "—"], ["Organization", user.org_name ? user.org_name + (user.is_org_admin ? " (admin)" : "") : "Not in an organization"], ["Sign-in method", user.auth_provider], ["Member since", fmtDate(user.created_at)], ["Last sign-in", fmtDate(user.last_login_at)]]
      .map(([k, v]) => '<div class="kv-row"><span>' + esc(k) + "</span><strong>" + esc(v) + "</strong></div>").join("") + "</div></section>";
  html += '<section class="card"><div class="card-head"><div><h3>Active sessions</h3><p class="card-subtext">Browsers and devices currently signed in.</p></div><button id="revokeOthers" class="secondary compact" type="button"' + (sessions.length > 1 ? "" : " disabled") + '>Sign out other sessions</button></div><div class="sessions">' +
    (sessions.length ? sessions.map((s) => '<div class="session"><div class="session-meta"><strong>' + esc(s.user_agent || "Unknown browser") + "</strong><span>" + esc(s.ip_address || "Unknown IP") + " · signed in " + esc(fmtDate(s.created_at)) + (s.current ? " · this browser" : "") + "</span></div>" + (s.current ? '<span class="badge good">Current</span>' : '<button class="danger" type="button" data-revoke="' + esc(s.id) + '">Revoke</button>') + "</div>").join("") : '<div class="empty">No active sessions.</div>') + "</div></section></div>";
  html += '<section class="card section"><h3>Recent activity</h3><div class="activity">' +
    (activity.length ? activity.map((a) => '<div class="activity-item"><div class="activity-main"><span><span class="badge ' + activityBadge(a.event_type) + '">' + esc(a.event_type.replaceAll("_", " ")) + '</span></span><span class="activity-time">' + esc(fmtDate(a.timestamp)) + "</span></div>" + (a.detail ? '<div class="activity-detail">' + esc(a.detail) + "</div>" : "") + "</div>").join("") : '<div class="empty">No activity yet.</div>') + "</div></section>";
  view().innerHTML = html;
  view().querySelectorAll("[data-revoke]").forEach((b) => b.addEventListener("click", async () => {
    try { await api("/auth/sessions/" + encodeURIComponent(b.dataset.revoke), { method: "DELETE" }); notice("success", "Session revoked."); renderAccount(); } catch (error) { notice("error", error.message); }
  }));
  $("revokeOthers").addEventListener("click", async () => {
    try { const r = await api("/auth/sessions/revoke-others", { method: "POST" }); notice("success", r.revoked ? r.revoked + " other session(s) signed out." : "No other sessions."); renderAccount(); } catch (error) { notice("error", error.message); }
  });
}

// ------------------------------------------------------------------ organization

async function renderOrg() {
  if (!state.user?.is_org_admin) { view().innerHTML = emptyState("Administrators only", "Only organization administrators can manage members."); return; }
  const members = await api("/auth/org/members");
  let html = pageHead("Account", "Organization", "Add members, manage administrator access and deactivate accounts. Admins can also view members' scans from the Operations Center and Scan history.");
  html += '<div class="grid grid-wide"><section class="card"><h3>Members</h3><div class="members">' + members.map((m) => '<div class="member-row"><div class="member-main"><strong>' + esc(m.display_name || m.email) + "</strong><span>" + esc(m.email) + " · " + (m.is_org_admin ? "Admin" : "Member") + (m.is_active ? "" : " · inactive") + '</span></div><div class="member-actions">' +
    (m.id === state.user.id ? '<span class="badge good">You</span>' : '<button class="secondary compact" type="button" data-member-admin="' + esc(m.id) + '" data-next="' + !m.is_org_admin + '">' + (m.is_org_admin ? "Remove admin" : "Make admin") + '</button><button class="danger" type="button" data-member-active="' + esc(m.id) + '" data-next="' + !m.is_active + '">' + (m.is_active ? "Deactivate" : "Reactivate") + "</button>") + "</div></div>").join("") + "</div></section>";
  html += '<section class="card"><h3>Add a member</h3><p class="card-subtext">Creates a password account in your organization. Share the temporary password privately.</p><form id="addMember" class="form-grid section"><div class="field"><label for="mEmail">Email</label><input id="mEmail" class="input" type="email" required maxlength="254"></div><div class="field"><label for="mPassword">Temporary password</label><input id="mPassword" class="input" type="password" minlength="8" maxlength="72" required autocomplete="new-password"></div><div><button class="btn" type="submit">Add member</button></div></form></section></div>';
  view().innerHTML = html;
  view().querySelectorAll("[data-member-admin],[data-member-active]").forEach((b) => b.addEventListener("click", async () => {
    const id = b.dataset.memberAdmin || b.dataset.memberActive;
    const body = b.dataset.memberAdmin ? { is_org_admin: b.dataset.next === "true" } : { is_active: b.dataset.next === "true" };
    b.disabled = true;
    try { await api("/auth/org/members/" + encodeURIComponent(id), { method: "PATCH", body: JSON.stringify(body) }); notice("success", "Member updated."); renderOrg(); } catch (error) { notice("error", error.message); b.disabled = false; }
  }));
  $("addMember").addEventListener("submit", async (e) => {
    e.preventDefault();
    try {
      await api("/auth/register", { method: "POST", body: JSON.stringify({ email: $("mEmail").value.trim(), password: $("mPassword").value, org_name: state.user.org_name || "" }) });
      notice("success", "Member added.");
      renderOrg();
    } catch (error) { notice("error", error.message); }
  });
}

// ------------------------------------------------------------------ shared findings table + triage

const STATUS_LABEL = { open: "Open", in_review: "In review", resolved: "Resolved", suppressed: "Suppressed", false_positive: "False positive" };

function mitreTag(id) {
  if (!id) return "";
  const path = id.replace(".", "/");
  return '<a class="tag mitre" href="https://attack.mitre.org/techniques/' + esc(path) + '/" target="_blank" rel="noopener noreferrer">' + esc(id) + "</a>";
}

function statusSelect(x) {
  return '<select class="select compact-select" data-triage="' + x.id + '" aria-label="Triage status">' +
    Object.entries(STATUS_LABEL).map(([k, v]) => '<option value="' + k + '"' + (k === x.status ? " selected" : "") + ">" + v + "</option>").join("") + "</select>";
}

function findingsTable(items, openSet, showTarget) {
  return '<div class="table-wrap"><table><thead><tr><th>Risk</th><th>Rule</th><th>Value</th><th>Where</th><th>Status</th><th class="num">Seen</th></tr></thead><tbody>' +
    items.map((x) => {
      const open = openSet.has(x.id);
      return '<tr class="clickable' + (["resolved", "suppressed", "false_positive"].includes(x.status) ? " dim" : "") + '" data-finding="' + x.id + '" aria-expanded="' + open + '"><td>' + sev(x.risk_label) + '<div class="cell-sub mono">' + Number(x.risk_score).toFixed(2) + '</div></td>' +
        '<td><div class="cell-main mono small">' + esc(x.rule_id) + '</div><div class="cell-sub">' + esc(x.category) + " " + mitreTag(x.mitre) + '</div></td>' +
        '<td><span class="preview">' + esc(x.preview) + '</span><div class="cell-sub">' + x.matched_length + ' chars</div></td>' +
        '<td>' + (showTarget && x.target_label ? '<div class="cell-sub"><a class="link-button" href="#/scan/' + esc(x.scan_id) + '">' + esc(x.target_label) + "</a></div>" : "") + '<div class="small">' + esc(x.origin || "—") + '</div><div class="cell-sub">' + esc(x.context || "") + '</div></td>' +
        '<td data-stop="1">' + statusSelect(x) + '</td><td class="num">' + x.occurrence_count + "×</td></tr>" +
        (open ? '<tr class="detail-row"><td colspan="6"><dl class="detail-grid">' + (x.description ? "<dt>Rule</dt><dd>" + esc(x.description) + "</dd>" : "") + '<dt>Identity correlation</dt><dd>' + esc(x.identity_reason || "—") + " (×" + (x.identity_confidence ?? "—") + ')</dd><dt>Exposure</dt><dd>' + esc((x.exposure_level || "—").replaceAll("_", " ")) + '</dd><dt>Base severity</dt><dd>' + esc(x.base_severity ?? "—") + '</dd><dt>Entropy</dt><dd>' + esc(x.entropy_score === null || x.entropy_score === undefined ? "not checked" : Number(x.entropy_score).toFixed(2)) + '</dd><dt>Source</dt><dd>' + esc((x.source_type || "—").replaceAll("_", " ")) + '</dd><dt>MITRE ATT&amp;CK</dt><dd>' + (mitreTag(x.mitre) || "—") + '</dd><dt>Fingerprint</dt><dd class="mono">' + esc(x.fingerprint) + "</dd></dl></td></tr>" : "");
    }).join("") + "</tbody></table></div>";
}

function pager(offset, count, total) {
  const end = Math.min(offset + count, total);
  return '<div class="pager"><span>' + (total ? offset + 1 : 0) + "–" + end + " of " + total + '</span><span class="button-row"><button class="secondary compact" type="button" id="pgPrev"' + (offset ? "" : " disabled") + '>Previous</button><button class="secondary compact" type="button" id="pgNext"' + (end < total ? "" : " disabled") + ">Next</button></span></div>";
}

function bindFindingsTable(host, openSet, rerender) {
  host.querySelectorAll("tr[data-finding]").forEach((tr) => {
    tr.tabIndex = 0;
    const toggle = (e) => { if (e.target.closest("[data-stop]")) return; const id = Number(tr.dataset.finding); openSet.has(id) ? openSet.delete(id) : openSet.add(id); rerender(); };
    tr.addEventListener("click", toggle);
    tr.addEventListener("keydown", (e) => { if ((e.key === "Enter" || e.key === " ") && !e.target.closest("[data-stop]")) { e.preventDefault(); toggle(e); } });
  });
  host.querySelectorAll("[data-triage]").forEach((sel) => sel.addEventListener("change", async () => {
    sel.disabled = true;
    try {
      await api("/findings/" + sel.dataset.triage + "/status", { method: "PATCH", body: JSON.stringify({ status: sel.value }) });
      notice("success", "Marked " + STATUS_LABEL[sel.value].toLowerCase() + ". The status carries over to future scans of this target.");
      rerender();
    } catch (error) { notice("error", error.message); sel.disabled = false; }
  }));
}

// ------------------------------------------------------------------ global findings

const gf = { q: "", risk: new Set(), status: "open,in_review", mitre: "", category: "", offset: 0, limit: 50, open: new Set() };

async function renderFindings() {
  view().innerHTML = pageHead("Scanner", "Findings", "Every open finding across the latest scan of each target. Triage here: the status follows the finding into future scans.") + '<div id="gfHost"></div>';
  await loadGlobalFindings();
}

async function loadGlobalFindings() {
  const host = $("gfHost");
  if (!host) return;
  const q = new URLSearchParams({ limit: String(gf.limit), offset: String(gf.offset) });
  if (gf.q) q.set("q", gf.q);
  if (gf.risk.size) q.set("risk", [...gf.risk].join(","));
  if (gf.status) q.set("status", gf.status);
  if (gf.mitre) q.set("mitre", gf.mitre);
  if (gf.category) q.set("category", gf.category);
  const [data, rules] = await Promise.all([api("/findings?" + q), state.rules ? Promise.resolve(state.rules) : api("/rules")]);
  state.rules = rules;
  const mitres = [...new Set(rules.map((r) => r.mitre).filter(Boolean))].sort();
  const cats = [...new Set(rules.map((r) => r.category))].sort();
  let html = '<div class="filters">' + LABELS.map((l) => '<button type="button" class="chip' + (gf.risk.has(l) ? " on" : "") + '" data-grisk="' + l + '" aria-pressed="' + gf.risk.has(l) + '">' + l.toLowerCase() + "</button>").join("") +
    '<select class="select" id="gStatus" aria-label="Status"><option value="open,in_review">Open + in review</option><option value="">Any status</option>' + Object.entries(STATUS_LABEL).map(([k, v]) => '<option value="' + k + '">' + v + "</option>").join("") + "</select>" +
    '<select class="select" id="gCat" aria-label="Category"><option value="">All categories</option>' + cats.map((c) => "<option" + (c === gf.category ? " selected" : "") + ">" + esc(c) + "</option>").join("") + "</select>" +
    '<select class="select" id="gMitre" aria-label="MITRE technique"><option value="">All techniques</option>' + mitres.map((m) => "<option" + (m === gf.mitre ? " selected" : "") + ">" + esc(m) + "</option>").join("") + "</select>" +
    '<input class="input grow" id="gSearch" type="search" placeholder="Search origin, context, rule, value preview" value="' + esc(gf.q) + '" aria-label="Search findings"></div>';
  html += data.items.length ? findingsTable(data.items, gf.open, true) + pager(gf.offset, data.items.length, data.total)
    : emptyState("Nothing here", gf.q || gf.risk.size || gf.mitre || gf.category ? "No finding matches these filters." : "No open findings. Run a scan or change the status filter.");
  host.innerHTML = html;
  $("gStatus").value = gf.status;
  host.querySelectorAll("[data-grisk]").forEach((b) => b.addEventListener("click", () => { gf.risk.has(b.dataset.grisk) ? gf.risk.delete(b.dataset.grisk) : gf.risk.add(b.dataset.grisk); gf.offset = 0; loadGlobalFindings(); }));
  $("gStatus").addEventListener("change", (e) => { gf.status = e.target.value; gf.offset = 0; loadGlobalFindings(); });
  $("gCat").addEventListener("change", (e) => { gf.category = e.target.value; gf.offset = 0; loadGlobalFindings(); });
  $("gMitre").addEventListener("change", (e) => { gf.mitre = e.target.value; gf.offset = 0; loadGlobalFindings(); });
  let timer;
  $("gSearch").addEventListener("input", (e) => { clearTimeout(timer); timer = setTimeout(() => { gf.q = e.target.value.trim(); gf.offset = 0; loadGlobalFindings().then(() => { const s = $("gSearch"); s.focus(); s.setSelectionRange(s.value.length, s.value.length); }); }, 300); });
  bindFindingsTable(host, gf.open, loadGlobalFindings);
  $("pgPrev")?.addEventListener("click", () => { gf.offset = Math.max(0, gf.offset - gf.limit); loadGlobalFindings(); });
  $("pgNext")?.addEventListener("click", () => { gf.offset += gf.limit; loadGlobalFindings(); });
}

// ------------------------------------------------------------------ executive summary

function gauge(value) {
  const pct = Math.max(0, Math.min(10, value)) / 10;
  const r = 52, c = 2 * Math.PI * r, color = value >= 9 ? "#ff7a75" : value >= 6.5 ? "#f5a35c" : value >= 4 ? "#e8d26a" : "#7ed6ad";
  return '<svg class="gauge" viewBox="0 0 130 130" role="img" aria-label="Exposure index ' + value + ' out of 10"><circle cx="65" cy="65" r="' + r + '" fill="none" stroke="#1a232b" stroke-width="12"/>' +
    '<circle cx="65" cy="65" r="' + r + '" fill="none" stroke="' + color + '" stroke-width="12" stroke-linecap="round" stroke-dasharray="' + (c * pct).toFixed(1) + " " + c.toFixed(1) + '" transform="rotate(-90 65 65)"/>' +
    '<text x="65" y="70" text-anchor="middle" class="gauge-num">' + value.toFixed(1) + '</text><text x="65" y="90" text-anchor="middle" class="gauge-sub">/ 10</text></svg>';
}

async function renderSummary() {
  const d = await api("/reports/summary");
  let html = pageHead("Reports", "Executive summary", "Computed from the latest scan of every target, excluding findings you resolved, suppressed or marked false positive.",
    '<a class="secondary compact" href="/reports/summary.pdf">Download PDF</a><a class="secondary compact" href="/reports/summary.txt">Download TXT</a>');
  if (!d.targets) { view().innerHTML = html + emptyState("Nothing to summarise yet", "Run a scan first.", '<a class="btn" href="#/new">New scan</a>'); return; }
  html += '<div class="grid grid-wide"><section class="card summary-hero">' + gauge(d.exposure_index) + '<div><h3>Exposure index</h3><p class="hint">Worst open finding × 0.7, plus up to 3 points for volume (critical 1.0, high 0.5, medium 0.15, low 0.03 each).</p>' +
    '<div class="counts section">' + LABELS.map((l) => '<span class="sev ' + l + '">' + d.counts[l] + " " + l.toLowerCase() + "</span>").join(" ") + '</div><p class="small muted section">' + d.open_findings + " open finding(s) across " + d.targets + " target(s)</p></div></section>" +
    '<section class="card"><h3>Recommended actions</h3>' + (d.recommendations.length ? '<ol class="recs">' + d.recommendations.map((r) => "<li><strong>" + esc(r.category.replaceAll("_", " ")) + "</strong> — " + esc(r.text) + "</li>").join("") + "</ol>" : '<p class="hint section">No open findings.</p>') + "</section></div>";
  if (d.narrative) html += '<section class="card section"><h3>Summary</h3><p class="narrative">' + esc(d.narrative) + '</p><p class="hint">Written by an AI model from aggregate, redacted counts.</p></section>';
  html += '<section class="section"><h3>Top risks</h3><div class="table-wrap section"><table><thead><tr><th>Risk</th><th>Finding</th><th>Where</th><th>ATT&amp;CK</th></tr></thead><tbody>' +
    d.top_findings.map((f) => '<tr class="clickable" data-href="#/scan/' + esc(f.scan_id) + '"><td>' + sev(f.risk_label) + '<div class="cell-sub mono">' + f.risk_score.toFixed(2) + '</div></td><td><div class="cell-main mono small">' + esc(f.rule_id) + '</div><div class="cell-sub">' + esc(f.description || f.category) + '</div></td><td class="small">' + esc(f.origin || "") + "</td><td>" + mitreTag(f.mitre) + "</td></tr>").join("") + "</tbody></table></div></section>";
  html += '<div class="grid grid-3 section"><section class="card"><h3>By target</h3>' + hbars(d.by_target.map((t) => ({ target: t.target + " · " + t.index, count: t.open })), "target") + '</section><section class="card"><h3>By category</h3>' + hbars(d.categories, "category") + '</section><section class="card"><h3>MITRE ATT&amp;CK</h3>' + hbars(d.mitre, "technique") + "</section></div>";
  view().innerHTML = html;
  applyBarWidths(view());
  bindRowLinks();
}

// ------------------------------------------------------------------ monitoring targets

const KIND_LABEL = { domain: "Domain", url: "Web page / URL", email: "Email address", github_handle: "GitHub handle" };
const KIND_HINT = {
  domain: "Crawls the site, checks for exposed .git/.env/backups, DNS, SPF/DMARC, certificate-log subdomains, WHOIS/RDAP and IP owners.",
  url: "Crawls this page and its links on the same site. Its domain must be verified first.",
  email: "Breach and paste exposure (HaveIBeenPwned) and public code mentions. Only your account email can be added.",
  github_handle: "Scans the handle's public gists and its three most recently pushed repositories.",
};

async function renderTargets() {
  const [targets, caps] = await Promise.all([api("/targets"), state.caps ? Promise.resolve(state.caps) : api("/scans/capabilities")]);
  state.caps = caps;
  let html = pageHead("Monitoring", "Monitored targets", "Collection modules only run on things you prove you own. Add a target, verify it, then scan it now or on a schedule.");
  html += '<div class="grid grid-wide"><section class="card"><h3>Targets</h3>' + (targets.length ? '<div class="members">' + targets.map(targetRow).join("") + "</div>" : '<p class="hint section">No targets yet.</p>') + "</section>" +
    '<section class="card"><h3>Add a target</h3><form id="targetForm" class="form-grid section"><div class="field"><label for="tKind">Type</label><select id="tKind" class="select">' +
    Object.entries(KIND_LABEL).map(([k, v]) => '<option value="' + k + '">' + v + "</option>").join("") + '</select></div><p class="hint" id="tKindHint"></p>' +
    '<div class="field"><label for="tValue">Value</label><input id="tValue" class="input" required maxlength="500" placeholder="example.com"></div>' +
    '<div class="field"><label for="tSchedule">Re-scan</label><select id="tSchedule" class="select"><option value="none">Manually</option><option value="daily">Daily</option><option value="weekly">Weekly</option></select></div>' +
    '<div><button class="btn" type="submit">Add target</button></div></form></section></div>';
  view().innerHTML = html;
  const kindHint = () => { $("tKindHint").textContent = KIND_HINT[$("tKind").value]; $("tValue").placeholder = { domain: "example.com", url: "https://example.com/team", email: state.user.email, github_handle: "your-username" }[$("tKind").value]; };
  $("tKind").addEventListener("change", kindHint); kindHint();
  $("targetForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    try { await api("/targets", { method: "POST", body: JSON.stringify({ kind: $("tKind").value, value: $("tValue").value.trim(), schedule: $("tSchedule").value }) }); notice("success", "Target added."); renderTargets(); }
    catch (error) { notice("error", error.message); }
  });
  view().querySelectorAll("[data-verify]").forEach((b) => b.addEventListener("click", async () => {
    b.disabled = true; b.textContent = "Checking…";
    try { await api("/targets/" + b.dataset.verify + "/verify", { method: "POST", body: "{}" }); notice("success", "Ownership verified."); renderTargets(); }
    catch (error) { notice("error", error.message); b.disabled = false; b.textContent = "Verify now"; }
  }));
  view().querySelectorAll("[data-tscan]").forEach((b) => b.addEventListener("click", async () => {
    b.disabled = true;
    try { const scan = await api("/targets/" + b.dataset.tscan + "/scan", { method: "POST" }); location.hash = "#/scan/" + scan.id; }
    catch (error) { notice("error", error.message); b.disabled = false; }
  }));
  view().querySelectorAll("[data-tsched]").forEach((sel) => sel.addEventListener("change", async () => {
    try { await api("/targets/" + sel.dataset.tsched, { method: "PATCH", body: JSON.stringify({ schedule: sel.value }) }); notice("success", "Schedule updated."); }
    catch (error) { notice("error", error.message); }
  }));
  view().querySelectorAll("[data-tdel]").forEach((b) => b.addEventListener("click", async () => {
    if (!window.confirm("Stop monitoring this target? Past scans are kept.")) return;
    try { await api("/targets/" + b.dataset.tdel, { method: "DELETE" }); renderTargets(); } catch (error) { notice("error", error.message); }
  }));
  view().querySelectorAll("[data-copy]").forEach((b) => b.addEventListener("click", async () => {
    try { await navigator.clipboard.writeText(b.dataset.copy); notice("success", "Copied."); } catch { notice("info", "Select the text and copy it manually."); }
  }));
}

function targetRow(t) {
  const sched = '<select class="select compact-select" data-tsched="' + esc(t.id) + '" aria-label="Schedule">' + ["none", "daily", "weekly"].map((s) => '<option value="' + s + '"' + (s === t.schedule ? " selected" : "") + ">" + (s === "none" ? "Manual" : s) + "</option>").join("") + "</select>";
  let body = '<div class="member-row target-row"><div class="member-main"><strong>' + esc(t.value) + "</strong><span>" + esc(KIND_LABEL[t.kind]) + " · " +
    (t.verified ? '<span class="ok">verified (' + esc((t.verification_method || "").replaceAll("_", " ")) + ")</span>" : '<span class="warn">not verified</span>') +
    (t.last_scan_at ? ' · last scan <a class="link-button" href="#/scan/' + esc(t.last_scan_id) + '">' + esc(ago(t.last_scan_at)) + "</a>" : "") +
    (t.next_run_at && t.schedule !== "none" ? " · next " + esc(fmtDate(t.next_run_at)) : "") + '</span></div><div class="member-actions">' +
    (t.verified ? sched + '<button class="btn" type="button" data-tscan="' + esc(t.id) + '">Scan now</button>' : '<button class="btn" type="button" data-verify="' + esc(t.id) + '">Verify now</button>') +
    '<button class="danger" type="button" data-tdel="' + esc(t.id) + '">Remove</button></div></div>';
  if (!t.verified && t.verification) {
    body += '<div class="verify-box">' + t.verification.methods.map((m) => "<div><strong>" + esc(m.summary) + "</strong>" +
      (m.record ? '<pre class="code">' + esc(m.record) + '</pre><button class="link-button" type="button" data-copy="' + esc(m.record) + '">Copy record</button>' : "") +
      (m.content && !m.record ? '<pre class="code">' + esc(m.content) + '</pre><button class="link-button" type="button" data-copy="' + esc(m.content) + '">Copy token</button>' : "") + "</div>").join("") + "</div>";
  }
  return body;
}

// ------------------------------------------------------------------ domain & infra

async function renderInfra() {
  const rows = await api("/intel/domains");
  let html = pageHead("Monitoring", "Domain & infrastructure", "Public records gathered for your verified domains: DNS, mail security, certificate-transparency subdomains, registration data and IP ownership.");
  if (!rows.length) { view().innerHTML = html + emptyState("No domains yet", "Add and verify a domain under Monitored targets.", '<a class="btn" href="#/targets">Add a domain</a>'); return; }
  html += rows.map((d) => {
    const i = d.intel || {};
    const dns = i.dns || {};
    const list = (arr) => (arr && arr.length ? arr.map((v) => '<div class="mono small">' + esc(v) + "</div>").join("") : '<span class="faint small">none</span>');
    return '<section class="card section"><div class="card-head"><div><h3>' + esc(d.domain) + '</h3><p class="card-subtext">' + (d.scanned_at ? "Scanned " + esc(fmtDate(d.scanned_at)) + ' · <a class="link-button" href="#/scan/' + esc(d.scan_id) + '">open findings</a>' : d.verified ? "Not scanned yet" : "Not verified") + "</p></div></div>" +
      (d.scanned_at ? '<div class="grid grid-3 section"><div><div class="small faint">A / AAAA</div>' + list((dns.A || []).concat(dns.AAAA || [])) + '</div><div><div class="small faint">MX</div>' + list(dns.MX) + '</div><div><div class="small faint">NS</div>' + list(dns.NS) + "</div>" +
        '<div><div class="small faint">SPF</div>' + list(i.spf ? [i.spf] : []) + '</div><div><div class="small faint">DMARC</div>' + list(i.dmarc ? [i.dmarc] : []) + '</div><div><div class="small faint">Registration (RDAP)</div>' + list(i.rdap ? ["Registrar: " + (i.rdap.registrar || "?"), "Expires: " + (i.rdap.expires || "?")] : []) + "</div></div>" +
        '<div class="grid grid-2 section"><div><div class="small faint">IP owners</div>' + list((i.ips || []).map((x) => x.ip + " — " + (x.network || "?") + " " + (x.country || ""))) + (i.services && i.services.length ? '<div class="small faint section">Open ports (Shodan)</div>' + list(i.services.map((s) => s.ip + ":" + s.port)) : "") + "</div>" +
        '<div><div class="small faint">Subdomains from certificate logs (' + (i.subdomains || []).length + ")</div>" + '<div class="scroll-box">' + list((i.subdomains || []).slice(0, 200)) + "</div></div></div>" +
        (d.notes && d.notes.length ? '<p class="hint section">' + d.notes.map(esc).join("<br>") + "</p>" : "") : "") + "</section>";
  }).join("");
  view().innerHTML = html;
}

// ------------------------------------------------------------------ identity graph

async function renderGraph() {
  const g = await api("/identity/graph");
  const layers = { person: 0, email: 1, domain: 1, handle: 1, alias: 1, target: 2, scan: 3, finding: 4 };
  const cols = [[], [], [], [], []];
  g.nodes.forEach((n) => cols[layers[n.kind] ?? 4].push(n));
  const W = 1100, colW = W / 5, rowH = 54;
  const H = Math.max(260, Math.max(...cols.map((c) => c.length)) * rowH + 60);
  const pos = {};
  cols.forEach((col, ci) => col.forEach((n, ri) => { pos[n.id] = { x: 20 + ci * colW, y: 40 + ri * rowH + (H - 60 - col.length * rowH) / 2 }; }));
  const color = { person: "#73b7ff", email: "#8ce0bd", domain: "#8ce0bd", handle: "#8ce0bd", alias: "#8ce0bd", target: "#b39dff", scan: "#91a0ab" };
  const sevColor = { CRITICAL: "#ff7a75", HIGH: "#f5a35c", MEDIUM: "#e8d26a", LOW: "#7fb3d9" };
  const nodeW = colW - 40;
  let svg = '<svg class="graph" viewBox="0 0 ' + W + " " + H + '" role="img" aria-label="Identity graph">';
  g.edges.forEach((e) => {
    const a = pos[e.from], b = pos[e.to];
    if (!a || !b) return;
    const x1 = a.x + nodeW, y1 = a.y + 18, x2 = b.x, y2 = b.y + 18, mx = (x1 + x2) / 2;
    svg += '<path d="M' + x1 + "," + y1 + " C" + mx + "," + y1 + " " + mx + "," + y2 + " " + x2 + "," + y2 + '" fill="none" stroke="' + (e.label === "correlates" ? "#73b7ff" : "#2c3944") + '" stroke-width="' + (e.label === "correlates" ? 2 : 1.2) + '"><title>' + esc(e.label) + "</title></path>";
  });
  g.nodes.forEach((n) => {
    const p = pos[n.id];
    const stroke = n.kind === "finding" ? sevColor[n.risk_label] || "#7fb3d9" : color[n.kind] || "#91a0ab";
    const label = n.label.length > 26 ? n.label.slice(0, 25) + "…" : n.label;
    const sub = n.kind === "finding" ? (n.risk_label || "") + " · " + n.count + "×" + (n.correlated ? " · correlated" : "") : n.kind === "target" ? (n.verified ? "verified target" : "unverified target") : n.kind;
    svg += '<g class="gnode' + (n.scan_id ? " link" : "") + '"' + (n.scan_id ? ' data-href="#/scan/' + esc(n.scan_id) + '"' : "") + '><rect x="' + p.x + '" y="' + p.y + '" width="' + nodeW + '" height="38" rx="8" fill="#0d1318" stroke="' + stroke + '"/>' +
      '<text x="' + (p.x + 10) + '" y="' + (p.y + 16) + '" class="gl">' + esc(label) + '</text><text x="' + (p.x + 10) + '" y="' + (p.y + 30) + '" class="gs">' + esc(sub) + "</text><title>" + esc(n.label) + "</title></g>";
  });
  svg += "</svg>";
  view().innerHTML = pageHead("Monitoring", "Identity graph", "How your identity anchors (profile), monitored targets, scans and finding groups connect. Blue links mark findings that matched one of your identities.") +
    (g.nodes.length > 1 ? '<section class="card graph-card">' + svg + '</section><div class="legend"><span><i class="c"></i>Critical</span><span><i class="h"></i>High</span><span><i class="m"></i>Medium</span><span><i class="l"></i>Low</span></div>'
      : emptyState("Graph is empty", "Fill in your identity profile and run a scan.", '<a class="btn" href="#/profile">Identity profile</a>'));
  view().querySelectorAll(".gnode.link").forEach((n) => n.addEventListener("click", () => { location.hash = n.dataset.href; }));
}

// ------------------------------------------------------------------ integrations

const INTEGRATION_FIELDS = {
  slack: [["webhook_url", "Incoming webhook URL", "https://hooks.slack.com/services/…"]],
  discord: [["webhook_url", "Channel webhook URL", "https://discord.com/api/webhooks/…"]],
  telegram: [["bot_token", "Bot token", "123456:ABC…"], ["chat_id", "Chat id", "-1001234567890"]],
  webhook: [["url", "HTTPS endpoint (SIEM / SOAR / custom)", "https://siem.example.com/ingest"], ["secret", "Signing secret (optional, HMAC-SHA256 in X-OPSEC-Signature)", ""]],
  github_issues: [["repo", "Repository (owner/name)", "you/security-alerts"], ["token", "Token with issues: write", "github_pat_…"]],
  email: [],
};
const INTEGRATION_LABEL = { slack: "Slack", discord: "Discord", telegram: "Telegram", webhook: "Webhook (SIEM / SOAR)", github_issues: "GitHub Issues", email: "Email (your account address)" };

async function renderIntegrations() {
  const rows = await api("/integrations");
  let html = pageHead("Configuration", "Alerts & integrations", "Send new findings from any scan to chat, a ticket tracker or your SIEM. Messages contain redacted previews only. Credentials are stored encrypted and never shown again.");
  html += '<div class="grid grid-wide"><section class="card"><h3>Destinations</h3>' + (rows.length ? '<div class="members">' + rows.map((i) =>
    '<div class="member-row"><div class="member-main"><strong>' + esc(i.name) + "</strong><span>" + esc(INTEGRATION_LABEL[i.kind]) + " · " + esc(i.hint || "") + " · " + esc(i.min_severity.toLowerCase()) + "+" + (i.only_new ? " · new only" : " · all") + (i.last_status ? " · " + esc(i.last_status) + " " + esc(ago(i.last_sent_at)) : "") + '</span></div><div class="member-actions">' +
    '<button class="secondary compact" type="button" data-itest="' + esc(i.id) + '">Send test</button><button class="secondary compact" type="button" data-itoggle="' + esc(i.id) + '" data-next="' + !i.enabled + '">' + (i.enabled ? "Pause" : "Resume") + '</button><button class="danger" type="button" data-idel="' + esc(i.id) + '">Delete</button></div></div>').join("") + "</div>" : '<p class="hint section">No destinations yet.</p>') + "</section>" +
    '<section class="card"><h3>Add a destination</h3><form id="intForm" class="form-grid section"><div class="field"><label for="iKind">Type</label><select id="iKind" class="select">' + Object.entries(INTEGRATION_LABEL).map(([k, v]) => '<option value="' + k + '">' + v + "</option>").join("") + "</select></div>" +
    '<div class="field"><label for="iName">Name</label><input id="iName" class="input" required maxlength="80" placeholder="Security channel"></div><div id="iFields" class="form-grid"></div>' +
    '<div class="form-row"><div class="field"><label for="iSev">Minimum severity</label><select id="iSev" class="select"><option>CRITICAL</option><option selected>HIGH</option><option>MEDIUM</option><option>LOW</option></select></div><div class="field"><label for="iNew">Send</label><select id="iNew" class="select"><option value="true">New findings only</option><option value="false">Every matching finding</option></select></div></div>' +
    '<div><button class="btn" type="submit">Save destination</button></div></form></section></div>';
  view().innerHTML = html;
  const fields = () => { $("iFields").innerHTML = INTEGRATION_FIELDS[$("iKind").value].map(([k, label, ph]) => '<div class="field"><label for="if_' + k + '">' + esc(label) + '</label><input id="if_' + k + '" data-cfg="' + k + '" class="input" placeholder="' + esc(ph) + '" autocomplete="off"' + (k === "secret" ? "" : " required") + "></div>").join("") || '<p class="hint">Uses the server\'s SMTP settings and sends to ' + esc(state.user.email) + ".</p>"; };
  $("iKind").addEventListener("change", fields); fields();
  $("intForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const config = {};
    view().querySelectorAll("[data-cfg]").forEach((inp) => { if (inp.value.trim()) config[inp.dataset.cfg] = inp.value.trim(); });
    try { await api("/integrations", { method: "POST", body: JSON.stringify({ kind: $("iKind").value, name: $("iName").value.trim(), config, min_severity: $("iSev").value, only_new: $("iNew").value === "true" }) }); notice("success", "Destination saved."); renderIntegrations(); }
    catch (error) { notice("error", error.message); }
  });
  view().querySelectorAll("[data-itest]").forEach((b) => b.addEventListener("click", async () => {
    b.disabled = true;
    try { const r = await api("/integrations/" + b.dataset.itest + "/test", { method: "POST" }); notice(r.last_status.startsWith("test sent") ? "success" : "error", r.last_status); renderIntegrations(); }
    catch (error) { notice("error", error.message); b.disabled = false; }
  }));
  view().querySelectorAll("[data-itoggle]").forEach((b) => b.addEventListener("click", async () => {
    try { await api("/integrations/" + b.dataset.itoggle, { method: "PATCH", body: JSON.stringify({ enabled: b.dataset.next === "true" }) }); renderIntegrations(); } catch (error) { notice("error", error.message); }
  }));
  view().querySelectorAll("[data-idel]").forEach((b) => b.addEventListener("click", async () => {
    if (!window.confirm("Delete this destination?")) return;
    try { await api("/integrations/" + b.dataset.idel, { method: "DELETE" }); renderIntegrations(); } catch (error) { notice("error", error.message); }
  }));
}

// ------------------------------------------------------------------ detection rules

async function renderRules() {
  const rules = state.rules || (state.rules = await api("/rules"));
  const byCat = {};
  rules.forEach((r) => (byCat[r.category] = byCat[r.category] || []).push(r));
  view().innerHTML = pageHead("Configuration", "Detection rules", rules.length + " rules: pattern rules run over every collected text; check rules come from the monitoring modules. Each maps to a MITRE ATT&amp;CK technique.") +
    Object.entries(byCat).sort().map(([cat, list]) => '<section class="section"><h3>' + esc(cat.replaceAll("_", " ")) + '</h3><div class="table-wrap section"><table><thead><tr><th>Rule</th><th>Description</th><th class="num">Base severity</th><th>ATT&amp;CK</th></tr></thead><tbody>' +
      list.map((r) => '<tr><td class="mono small">' + esc(r.id) + "</td><td class=\"small\">" + esc(r.description) + '</td><td class="num">' + Number(r.base_severity).toFixed(1) + "</td><td>" + mitreTag(r.mitre) + "</td></tr>").join("") + "</tbody></table></div></section>").join("");
}

// ------------------------------------------------------------------ boot

async function boot() {
  $("navToggle").addEventListener("click", () => {
    const open = $("wsNav").classList.toggle("open");
    $("navToggle").setAttribute("aria-expanded", String(open));
  });
  $("logoutButton").addEventListener("click", async () => {
    try { await api("/auth/logout", { method: "POST" }); } catch { /* signed out either way */ }
    window.location.assign("/login");
  });
  try {
    state.user = await api("/auth/me");
  } catch { return; }
  $("userEmail").textContent = state.user.email;
  $("userRole").textContent = state.user.is_org_admin ? "Organization admin" : (state.user.org_id ? "Member" : "Personal account");
  $("orgNav").hidden = !state.user.is_org_admin;
  window.addEventListener("hashchange", route);
  if (!location.hash) history.replaceState(null, "", "#/overview");
  route();
}

boot();
