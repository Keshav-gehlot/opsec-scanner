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
const SOURCE_LABEL = { cli_upload: "CLI upload", json_import: "JSON import", media_upload: "Media upload", git_url: "Repository" };
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
    '<a class="btn" href="#/new">New scan</a>');
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

const explorer = { scanId: null, risk: new Set(), category: "", rule: "", q: "", sort: "risk", order: "desc", offset: 0, limit: 50, open: new Set() };

async function renderScan(scanId) {
  if (!scanId) { location.hash = "#/scans"; return; }
  const scan = await api("/scans/" + encodeURIComponent(scanId));
  if (explorer.scanId !== scanId) Object.assign(explorer, { scanId, risk: new Set(), category: "", rule: "", q: "", sort: "risk", order: "desc", offset: 0, open: new Set() });
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
  const data = await api("/scans/" + encodeURIComponent(explorer.scanId) + "/findings?" + q);
  const f = data.facets;
  const opt = (obj, current, all) => '<option value="">' + all + "</option>" + Object.entries(obj).sort((a, b) => b[1] - a[1]).map(([k, n]) => '<option value="' + esc(k) + '"' + (k === current ? " selected" : "") + ">" + esc(k) + " (" + n + ")</option>").join("");
  let html = '<div class="card-head"><div><h3>Findings explorer</h3><p class="card-subtext">Values are redacted. Use the origin and context to locate each finding.</p></div></div>';
  html += '<div class="filters section">' + LABELS.map((l) => '<button type="button" class="chip' + (explorer.risk.has(l) ? " on" : "") + '" data-risk="' + l + '" aria-pressed="' + explorer.risk.has(l) + '">' + l.toLowerCase() + '<span class="n">' + (f.risk[l] || 0) + "</span></button>").join("") +
    '<select class="select" id="fCategory" aria-label="Category">' + opt(f.category, explorer.category, "All categories") + "</select>" +
    '<select class="select" id="fRule" aria-label="Rule">' + opt(f.rule, explorer.rule, "All rules") + "</select>" +
    '<input class="input grow" id="fSearch" type="search" placeholder="Search origin, context, rule" value="' + esc(explorer.q) + '" aria-label="Search findings">' +
    '<select class="select" id="fSort" aria-label="Sort"><option value="risk:desc">Highest risk</option><option value="risk:asc">Lowest risk</option><option value="rule:asc">Rule A–Z</option><option value="category:asc">Category</option><option value="origin:asc">Origin</option></select></div>';
  if (!data.items.length) {
    html += emptyState(data.total === 0 && !explorer.risk.size && !explorer.q && !explorer.category && !explorer.rule ? "No findings" : "Nothing matches these filters", data.total === 0 && !explorer.q ? "No detection rule matched anything in this scan." : "Clear a filter to see more.");
  } else {
    html += '<div class="table-wrap"><table><thead><tr><th>Risk</th><th>Rule</th><th>Value</th><th>Origin</th><th class="num">Seen</th></tr></thead><tbody>' +
      data.items.map((x) => {
        const open = explorer.open.has(x.id);
        return '<tr class="clickable" data-finding="' + x.id + '" aria-expanded="' + open + '"><td>' + sev(x.risk_label) + '<div class="cell-sub mono">' + x.risk_score.toFixed(2) + '</div></td><td><div class="cell-main mono small">' + esc(x.rule_id) + '</div><div class="cell-sub">' + esc(x.category) + '</div></td><td><span class="preview">' + esc(x.preview) + '</span><div class="cell-sub">' + x.matched_length + ' chars</div></td><td><div class="small">' + esc(x.origin || "—") + '</div><div class="cell-sub">' + esc(x.context || "") + '</div></td><td class="num">' + x.occurrence_count + "×</td></tr>" +
          (open ? '<tr class="detail-row"><td colspan="5"><dl class="detail-grid"><dt>Identity correlation</dt><dd>' + esc(x.identity_reason || "—") + " (×" + (x.identity_confidence ?? "—") + ')</dd><dt>Exposure</dt><dd>' + esc((x.exposure_level || "—").replaceAll("_", " ")) + '</dd><dt>Base severity</dt><dd>' + esc(x.base_severity ?? "—") + '</dd><dt>Entropy</dt><dd>' + esc(x.entropy_score === null ? "not checked" : Number(x.entropy_score).toFixed(2)) + '</dd><dt>Source</dt><dd>' + esc((x.source_type || "—").replaceAll("_", " ")) + '</dd><dt>Fingerprint</dt><dd class="mono">' + esc(x.fingerprint) + "</dd></dl></td></tr>" : "");
      }).join("") + "</tbody></table></div>";
    const end = Math.min(data.offset + data.items.length, data.total);
    html += '<div class="pager"><span>' + (data.offset + 1) + "–" + end + " of " + data.total + '</span><span class="button-row"><button class="secondary compact" type="button" id="pgPrev"' + (data.offset ? "" : " disabled") + '>Previous</button><button class="secondary compact" type="button" id="pgNext"' + (end < data.total ? "" : " disabled") + ">Next</button></span></div>";
  }
  host.innerHTML = html;
  $("fSort").value = explorer.sort + ":" + explorer.order;
  host.querySelectorAll("[data-risk]").forEach((b) => b.addEventListener("click", () => { explorer.risk.has(b.dataset.risk) ? explorer.risk.delete(b.dataset.risk) : explorer.risk.add(b.dataset.risk); explorer.offset = 0; loadFindings(); }));
  $("fCategory").addEventListener("change", (e) => { explorer.category = e.target.value; explorer.offset = 0; loadFindings(); });
  $("fRule").addEventListener("change", (e) => { explorer.rule = e.target.value; explorer.offset = 0; loadFindings(); });
  $("fSort").addEventListener("change", (e) => { [explorer.sort, explorer.order] = e.target.value.split(":"); explorer.offset = 0; loadFindings(); });
  let timer;
  $("fSearch").addEventListener("input", (e) => { clearTimeout(timer); timer = setTimeout(() => { explorer.q = e.target.value.trim(); explorer.offset = 0; loadFindings().then(() => { const s = $("fSearch"); s.focus(); s.setSelectionRange(s.value.length, s.value.length); }); }, 300); });
  host.querySelectorAll("tr[data-finding]").forEach((tr) => {
    tr.tabIndex = 0;
    const toggle = () => { const id = Number(tr.dataset.finding); explorer.open.has(id) ? explorer.open.delete(id) : explorer.open.add(id); loadFindings(); };
    tr.addEventListener("click", toggle);
    tr.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); toggle(); } });
  });
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
