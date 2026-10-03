"use strict";
// Sign-in / registration page. The signed-in workspace lives in app.html +
// workspace.js; the server redirects between the two, so neither page ever
// renders the other's markup.
const $ = (id) => document.getElementById(id);
const state = { mode: "login", loading: false };

const providerMeta={
  google:{label:"Google",icon:'<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="#4285F4" d="M21.35 12.23c0-.68-.06-1.35-.18-1.98H12v3.75h5.23a4.48 4.48 0 0 1-1.94 2.94v2.45h3.14c1.84-1.69 2.92-4.18 2.92-7.16Z"/><path fill="#34A853" d="M12 21.7c2.63 0 4.84-.87 6.45-2.35l-3.14-2.45c-.87.58-1.98.93-3.31.93-2.54 0-4.69-1.72-5.46-4.03H3.3v2.53A9.74 9.74 0 0 0 12 21.7Z"/><path fill="#FBBC05" d="M6.54 13.8a5.85 5.85 0 0 1 0-3.6V7.67H3.3a9.73 9.73 0 0 0 0 8.66l3.24-2.53Z"/><path fill="#EA4335" d="M12 6.17c1.43 0 2.72.49 3.73 1.46l2.8-2.8C16.84 3.19 14.63 2.3 12 2.3a9.74 9.74 0 0 0-8.7 5.37l3.24 2.53C7.85 7.89 9.99 6.17 12 6.17Z"/></svg>'},
  github:{label:"GitHub",icon:'<svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M12 .7a12 12 0 0 0-3.79 23.39c.6.11.82-.26.82-.58v-2.04c-3.34.73-4.04-1.61-4.04-1.61-.55-1.39-1.34-1.76-1.34-1.76-1.09-.75.08-.73.08-.73 1.2.08 1.83 1.23 1.83 1.23 1.07 1.83 2.8 1.3 3.48.99.11-.77.42-1.3.76-1.6-2.67-.3-5.48-1.34-5.48-5.95 0-1.31.47-2.38 1.23-3.22-.12-.3-.53-1.52.12-3.17 0 0 1-.32 3.3 1.23a11.4 11.4 0 0 1 6 0c2.29-1.55 3.29-1.23 3.29-1.23.65 1.65.24 2.87.12 3.17.77.84 1.23 1.91 1.23 3.22 0 4.62-2.81 5.65-5.49 5.95.43.37.82 1.1.82 2.22v3.29c0 .32.22.69.83.58A12 12 0 0 0 12 .7Z"/></svg>'},
  microsoft:{label:"Microsoft",icon:'<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="#f35325" d="M2 2h9.5v9.5H2z"/><path fill="#81bc06" d="M12.5 2H22v9.5h-9.5z"/><path fill="#05a6f0" d="M2 12.5h9.5V22H2z"/><path fill="#ffba08" d="M12.5 12.5H22V22h-9.5z"/></svg>'},
  apple:{label:"Apple",icon:'<svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M17.05 20.28c-.98.95-2.05.8-3.09.35-1.1-.46-2.1-.48-3.26 0-1.44.62-2.2.44-3.06-.35C2.79 15.25 3.51 7.59 9.05 7.31c1.35.07 2.29.74 3.65-.84 1.54.13 2.7.73 3.5 1.8-3.18 1.9-2.43 6.07.49 7.23-.58 1.52-1.34 3.04-2.74 3.98ZM12.05 7.25C11.9 4.99 13.74 3.13 15.85 3c.29 2.61-2.36 4.55-3.8 4.25Z"/></svg>'}
};

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;" })[c]);
}
function showNotice(type, message) { const el = $("notice"); el.className = "notice show " + type; el.textContent = message; }
function clearNotice() { const el = $("notice"); el.className = "notice"; el.textContent = ""; }

async function api(url, options = {}) {
  const response = await fetch(url, {
    credentials: "same-origin",
    ...options,
    headers: { ...(options.body ? { "Content-Type": "application/json" } : {}), ...(options.headers || {}) },
  });
  const type = response.headers.get("content-type") || "";
  const body = type.includes("application/json") ? await response.json() : null;
  if (!response.ok) {
    const detail = body?.detail;
    const message = Array.isArray(detail) ? detail.map((x) => x.msg || "Invalid input").join(" ") : (detail || "Request failed.");
    const error = new Error(message);
    error.status = response.status;
    throw error;
  }
  return body;
}

function setMode(mode) {
  state.mode = mode;
  clearNotice();
  const register = mode === "register";
  $("loginTab").classList.toggle("active", !register);
  $("registerTab").classList.toggle("active", register);
  $("loginTab").setAttribute("aria-selected", String(!register));
  $("registerTab").setAttribute("aria-selected", String(register));
  $("formTitle").textContent = register ? "Create your account" : "Welcome back";
  $("formSubtext").textContent = register ? "Start a workspace. The first member becomes its administrator." : "Sign in to your OPSEC workspace.";
  $("orgField").hidden = !register;
  $("orgName").required = register;
  $("submitButton").textContent = register ? "Create account" : "Sign in";
  $("password").autocomplete = register ? "new-password" : "current-password";
  $("switchHint").textContent = register ? "Already have an account?" : "Need an account?";
  $("switchAction").textContent = register ? "Sign in" : "Create one";
}

// Length dominates: a long passphrase beats a short "complex" password.
// Obvious patterns (repeats, sequences, the word "password", the email's
// local part) cap the score.
function passwordScore(value) {
  if (!value) return 0;
  const classes = [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter((r) => r.test(value)).length;
  let score = 0;
  if (value.length >= 10) score++;
  if (value.length >= 14) score++;
  if (value.length >= 18 || (value.length >= 12 && classes >= 3)) score++;
  if (classes >= 3 && value.length >= 10) score++;
  const lower = value.toLowerCase();
  const local = ($("email").value.split("@")[0] || "").toLowerCase();
  const weak = /(.)\1{2,}/.test(value) || /(0123|1234|2345|3456|4567|5678|6789|abcd|qwer|asdf)/.test(lower) ||
    /(password|letmein|welcome|admin|qwerty)/.test(lower) || (local.length >= 3 && lower.includes(local));
  if (weak) score = Math.min(score, 1);
  if (value.length < 8) score = 0;
  return score;
}

function updateStrength() {
  const score = passwordScore($("password").value);
  document.querySelectorAll(".strength i").forEach((bar, i) => bar.classList.toggle("on", i < score));
  $("strengthText").textContent = score >= 4 ? "Strong" : score >= 3 ? "Good" : score >= 1 ? "Weak" : "Use a longer passphrase";
}

function renderProviders(providers) {
  const wrap = $("providers");
  wrap.innerHTML = "";
  if (!providers.length) { $("ssoLabel").hidden = true; $("ssoEmpty").hidden = false; return; }
  $("ssoLabel").hidden = false;
  $("ssoEmpty").hidden = true;
  providers.forEach((provider) => {
    const meta = providerMeta[provider] || { label: provider, icon: "" };
    const link = document.createElement("a");
    link.className = "provider";
    link.href = "/auth/oauth/" + encodeURIComponent(provider) + "/login";
    link.innerHTML = meta.icon + "<span>Continue with " + escapeHtml(meta.label) + "</span>";
    wrap.appendChild(link);
  });
}

async function loadHealth() {
  try {
    const data = await api("/health");
    $("statusText").textContent = data.database === "ok" ? "All systems operational" : "Limited availability";
    $("statusDot").classList.toggle("offline", data.database !== "ok");
    renderProviders(Array.isArray(data.sso_providers_configured) ? data.sso_providers_configured : []);
  } catch {
    $("statusText").textContent = "Service unavailable";
    $("statusDot").classList.add("offline");
    renderProviders([]);
  }
}

function setLoading(value) {
  state.loading = value;
  $("submitButton").disabled = value;
  $("submitButton").textContent = value ? "Working…" : (state.mode === "register" ? "Create account" : "Sign in");
}

function showSsoNotice() {
  const code = new URLSearchParams(location.search).get("sso");
  const messages = {
    link_required: "An account with this email already exists. Sign in with your password once to link Google to it.",
    failed: "Single sign-on did not complete. Try again.",
  };
  if (code && messages[code]) {
    showNotice(code === "link_required" ? "info" : "error", messages[code]);
    history.replaceState(null, "", location.pathname);
  }
}

$("loginTab").addEventListener("click", () => setMode("login"));
$("registerTab").addEventListener("click", () => setMode("register"));
$("switchAction").addEventListener("click", () => setMode(state.mode === "login" ? "register" : "login"));
$("togglePassword").addEventListener("click", () => {
  const input = $("password");
  const visible = input.type === "text";
  input.type = visible ? "password" : "text";
  $("togglePassword").textContent = visible ? "Show" : "Hide";
  $("togglePassword").setAttribute("aria-label", visible ? "Show password" : "Hide password");
});
$("password").addEventListener("input", updateStrength);
$("email").addEventListener("input", updateStrength);

$("authForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  clearNotice();
  setLoading(true);
  const payload = { email: $("email").value.trim(), password: $("password").value };
  if (state.mode === "register") {
    payload.org_name = $("orgName").value.trim();
    payload.display_name = payload.email.split("@")[0];
  }
  try {
    await api(state.mode === "register" ? "/auth/register" : "/auth/login", { method: "POST", body: JSON.stringify(payload) });
    if (state.mode === "register") {
      $("authForm").reset();
      $("email").value = payload.email;
      updateStrength();
      setMode("login");
      $("password").focus();
      showNotice("success", "Account created. Sign in with your new credentials.");
    } else {
      window.location.assign("/dashboard");
    }
  } catch (error) {
    if (error.status === 429) showNotice("error", "Too many failed attempts. Wait a few minutes and try again.");
    else if (error.status === 409) showNotice("error", "That email is already registered.");
    else if (error.status === 401) showNotice("error", "The email or password is incorrect.");
    else if (error.status === 403) showNotice("error", error.message || "This account cannot sign in.");
    else showNotice("error", error.message || "Something went wrong.");
  } finally {
    setLoading(false);
  }
});

setMode("login");
loadHealth();
showSsoNotice();
