# OPSEC Scanner Platform (web workspace, auth + activity tracking)

A separate, optional backend: a browser workspace for the scanner (Operations Center,
scan history, findings explorer, server-side scans of public repositories and uploaded
media, CLI result uploads), organization-provisioned username/password login, SSO via
Google/GitHub/Microsoft/Apple, and an activity log. This is a genuine architectural
addition, not a bolt-on — the CLI and its reports remain fully local-first and don't
require this to exist. Nothing here makes the scanner itself phone home.

## What this is and isn't

- **Is**: a real, tested auth backend (FastAPI + SQLAlchemy + SQLite/Postgres) with
  password hashing (bcrypt), JWS-signed session tokens (PyJWT), OAuth/OIDC wiring for
  four providers (Authlib), session revocation, and an activity log.
- **Isn't**: pre-connected to real Google/GitHub/Microsoft/Apple accounts out of the box.
  OAuth fundamentally requires *you* to register an app with each provider and obtain a
  client ID/secret — that's not something that can be generated on your behalf; it's tied
  to your own domain and developer account. Steps for each are below. Until you add real
  credentials, each provider's login route returns a clear "not configured" error instead
  of a broken redirect — verified by test, not just claimed.

## Quick start (local password auth, no SSO needed to try it)

```bash
pip install -e ".[platform]"
cp opsec_platform/.env.example opsec_platform/.env
# edit opsec_platform/.env: set PLATFORM_JWT_SECRET to the output of:
#   python -c "import secrets; print(secrets.token_urlsafe(64))"

# Run from the repo root, not from inside opsec_platform/ — the app uses
# absolute `opsec_platform.app.xxx` imports (same pattern as the rest of
# this project), so it needs the repo root on the Python path. Verified
# directly: `cd opsec_platform && uvicorn app.main:app` fails with
# ModuleNotFoundError; the command below is the one that actually works.
export $(cat opsec_platform/.env | grep -v '^#' | xargs)
uvicorn opsec_platform.app.main:app --reload --port 8000
```

```bash
curl -X POST http://localhost:8000/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"you@example.com","password":"a-real-password","org_name":"My Org"}'

curl -X POST http://localhost:8000/auth/login -c cookies.txt \
  -H "Content-Type: application/json" \
  -d '{"email":"you@example.com","password":"a-real-password"}'

curl http://localhost:8000/auth/me -b cookies.txt
curl http://localhost:8000/activity/me -b cookies.txt
```

Open the browser UI at http://localhost:8000/login to use the same auth flow with a
single-page login/register form and a simple post-login dashboard. It loads the current
user and recent activity from the same API endpoints above, and it shows the configured SSO
providers only when `/health` reports them as enabled.

## Setting up each SSO provider

Every provider needs a redirect/callback URL registered as **exactly**
`{PLATFORM_BASE_URL}/auth/oauth/{provider}/callback` — mismatches here are the single most
common OAuth setup failure, across every provider.

### Google
1. [Google Cloud Console](https://console.cloud.google.com/) → APIs & Services → Credentials.
2. Create an OAuth 2.0 Client ID (application type: Web application).
3. Add an authorized redirect URI: `{PLATFORM_BASE_URL}/auth/oauth/google/callback`.
4. Copy the generated Client ID and Client Secret into `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET`.
5. If this app isn't verified yet, Google will cap it at 100 test users until you submit
   for verification — fine for evaluation, not for a public launch.

### GitHub
1. GitHub → Settings → Developer settings → OAuth Apps → New OAuth App.
2. Authorization callback URL: `{PLATFORM_BASE_URL}/auth/oauth/github/callback`.
3. Copy the Client ID, generate a Client Secret, put both in `GITHUB_CLIENT_ID` / `GITHUB_CLIENT_SECRET`.
4. GitHub isn't OIDC — there's no discovery document or id_token; identity comes from a
   REST call to `/user` (and `/user/emails` if the primary email is private). Already
   handled in `oauth_routes.py`, nothing further needed here.

### Microsoft (Entra ID / Azure AD)
1. [Entra admin center](https://entra.microsoft.com/) → App registrations → New registration.
2. Supported account types: "Accounts in any organizational directory and personal
   Microsoft accounts" if you want both work/school and personal accounts to sign in
   (this is what the `common` tenant endpoint in `oauth_providers.py` expects).
3. Redirect URI (platform: Web): `{PLATFORM_BASE_URL}/auth/oauth/microsoft/callback`.
4. Certificates & secrets → New client secret. Copy the Application (client) ID and the
   secret **value** (not the secret ID) into `MICROSOFT_CLIENT_ID` / `MICROSOFT_CLIENT_SECRET`.
5. Client secrets expire (you choose 6/12/24 months at creation) — there's no way around
   a hard expiry here, only how far out it is. Put a reminder in your calendar.

### Apple ("Sign in with Apple")
The odd one out: Apple's "client secret" isn't a static string, it's a JWT you generate
yourself, signed with a private key, and it expires after **at most 6 months**.

1. [Apple Developer](https://developer.apple.com/account/) → Certificates, Identifiers &
   Profiles → Identifiers → register an App ID with "Sign In with Apple" enabled, then a
   separate Services ID (this Services ID is your `APPLE_CLIENT_ID`) configured with the
   return URL `{PLATFORM_BASE_URL}/auth/oauth/apple/callback`.
2. Keys → create a new key with "Sign In with Apple" enabled, download the `.p8` private
   key file (only downloadable once — save it securely), and note its Key ID and your Team ID.
3. Generate the client-secret JWT (needs `pyjwt` and `cryptography`):
   ```python
   import jwt, time
   with open("AuthKey_XXXXXXXXXX.p8") as f:
       private_key = f.read()
   payload = {
       "iss": "<your 10-char Team ID>",
       "iat": int(time.time()),
       "exp": int(time.time()) + 15777000,  # ~6 months, Apple's max
       "aud": "https://appleid.apple.com",
       "sub": "<your Services ID, same as APPLE_CLIENT_ID>",
   }
   token = jwt.encode(payload, private_key, algorithm="ES256",
                       headers={"kid": "<your 10-char Key ID>"})
   print(token)
   ```
4. Put that token in `APPLE_CLIENT_SECRET`. Regenerate and redeploy it before it expires —
   there's no refresh mechanism, only re-running this script.

## Security notes before using this for anything real

This is a working reference implementation, not a hardened production deployment as-is:

- **`/auth/register` authorization** — fixed since the last pass. Bootstrapping a brand-new
  org (first account) needs no authentication, since there's no one to authenticate as yet;
  that first user becomes the org's admin automatically. Adding a user to an org that
  *already has members* requires being authenticated as an admin of that specific org —
  being an admin of a different org doesn't grant authority (`is_org_admin` + `org_id`
  are both checked). There's still no fuller roles/permissions model (e.g. no way to demote
  an admin, no per-resource permissions) — this covers the one gap that was previously wide
  open, not a complete authorization system.
- **No database migrations.** Schema changes (like the `is_org_admin` column just added)
  apply automatically to a fresh database via `init_db()`, but won't alter an already-
  existing `platform.db` with data in it — this reference implementation uses
  SQLAlchemy's `create_all()`, not Alembic. Add Alembic before this holds real data across
  schema changes.
- **Login rate limiting — fixed since the last pass.** `/auth/login` now blocks after
  `PLATFORM_LOGIN_RATE_LIMIT_ATTEMPTS` (default 5) failures within
  `PLATFORM_LOGIN_RATE_LIMIT_WINDOW_MINUTES` (default 15), counted from the activity log
  itself. This is a basic per-account/per-email limiter, not a distributed or IP-based one
  — a determined attacker rotating through many target emails from one IP isn't slowed down
  by this alone. Consider adding an IP-based limiter (e.g. at a reverse-proxy layer) as a
  second, complementary layer before exposing this publicly.
- **`PLATFORM_JWT_SECRET` must be a real secret, generated once, and kept out of source
  control.** Anyone with this value can forge valid sessions for any user.
- **SSO in HTTPS deployments requires two more variables.** `PLATFORM_OAUTH_SESSION_SECRET`
  (≥32 random bytes, distinct from the JWT secret and every OAuth client secret) signs the
  OAuth state cookie, and `PLATFORM_BASE_URL` (the public `https://` origin, e.g. the Vercel
  URL) builds callback URLs — they are never derived from request headers. If either is
  missing, SSO routes return 503, `/health` reports no SSO providers, and the reason is logged
  at startup. Local `http://localhost` development needs neither.
- **`/health` reports `commit`** (from `RENDER_GIT_COMMIT` / `VERCEL_GIT_COMMIT_SHA`), which is
  how to confirm which build is actually live — `version` is a hand-maintained string.
- **HTTPS is not optional.** `PLATFORM_COOKIE_SECURE=true` (the default) requires it —
  don't flip it to `false` anywhere except local `http://localhost` development.
- **SQLite is fine for evaluation, not for concurrent production load.** Point
  `PLATFORM_DATABASE_URL` at Postgres for anything beyond a small pilot.

## Web workspace

After signing in, `/dashboard` is the workspace (`app.html` + `workspace.js`). The server
redirects `/` and `/login` to `/dashboard` for a valid session and `/dashboard` to `/login`
without one, so neither page renders the other's markup.

| Page | What it does | API |
| --- | --- | --- |
| Operations Center | Open findings by severity (latest scan per target), trend, top rules, new/resolved per target | `GET /scans/overview` |
| New scan → Public repository | Shallow-clones an allow-listed public HTTPS repo and runs the git engine | `POST /scans/git` |
| New scan → Images & documents | Uploads files and runs the media engine (PDF/Office always; EXIF needs `exiftool`, OCR needs `tesseract` on the server) | `POST /scans/media` |
| New scan → Import CLI results | Imports a `--json-output` file | `POST /scans/import` |
| Scan history / scan detail | Status, stats, diff vs the previous scan of the same label, findings explorer (filter, search, sort, paginate), JSON/CSV/SARIF export, delete | `GET /scans`, `/scans/{id}`, `/findings`, `/diff`, `/export` |
| Identity profile | Web version of `target_profile.yaml`, used to score scans started from the web | `GET/PUT /profile/identity` |
| CLI access tokens | Personal access tokens for `--report-activity` / `--upload-findings` | `GET/POST/DELETE /auth/tokens` |
| Account & sessions / Organization | Identity, sessions, activity; member management for org admins | existing `/auth/*` routes |

**Data handling.** Raw matched values are never stored. Each finding keeps a redacted
preview (a few leading/trailing characters at most), its length, origin and context, and a
keyed fingerprint (HMAC-SHA256, key from `PLATFORM_FINGERPRINT_SECRET` or derived from
`PLATFORM_JWT_SECRET`) used to compare scans. Free-form CLI metadata is dropped on import.
Uploaded files and clones live in a temp directory for the duration of the scan only.

**Server-side scan safeguards.** Git URLs must be `https://<allowed host>/<owner>/<repo>`
with no credentials, port, query or fragment; git runs with an empty environment
(`GIT_ALLOW_PROTOCOL=https`, no prompts, no redirects, no system/global config), a
shallow depth, a timeout and a size cap. Uploads are limited by type, count and size.
Each user can have two scans in flight and a daily scan quota; `PLATFORM_WEB_SCANS_ENABLED=false`
turns server-side scans off. Jobs run in a thread pool inside the API process, so a restart
orphans running jobs; they are marked failed at the next start (and when polled after 30 minutes).

**Access tokens** (`opsec_pat_…`) are stored as SHA-256 hashes, shown once, expire, and are
accepted only by scan and activity-report routes — never by account, session, token or
organization management.

**CSRF.** Unsafe requests (POST/PUT/PATCH/DELETE) whose `Origin` (or `Referer`) is not
`PLATFORM_BASE_URL`, a `PLATFORM_ALLOWED_ORIGINS` entry, or the request's own host are
rejected with 403. Non-browser clients send neither header and are unaffected.

All limits are environment variables; see `.env.example`.

## Monitoring modules (architecture: inputs → collection → processing → analysis → output → integrations)

| Layer | Implemented as | Code |
| --- | --- | --- |
| Inputs | Monitored targets: domain, URL, email, GitHub handle — each **ownership-verified** (DNS TXT / `.well-known` file, account email, public gist) | `osint/verification.py`, `/targets` |
| Collection | Crawler for verified sites (robots.txt respected, same-site only) + exposure checks (`.git`, `.env`, backups, `.DS_Store`, server-status); DNS, SPF/DMARC, certificate-transparency subdomains, RDAP/WHOIS, IP ownership, optional Shodan; GitHub code search and a handle's gists/repos; optional HaveIBeenPwned breach + paste exposure | `osint/collectors.py` |
| Processing | Line extraction, normalisation, path rewriting, deduplication, IP → network enrichment | `osint/collectors.py`, `scan_service.py` |
| Analysis | Pattern rules + checksum validators (Luhn, Verhoeff/Aadhaar, IBAN, SSN) for credentials, PII, IDs, financial data, misconfiguration; identity correlation; risk scoring; MITRE ATT&CK per rule | `rules/patterns.yaml`, `opsec_scanner/analysis/patterns.py` |
| Storage | Results DB (redacted previews + keyed fingerprints), triage state, encrypted integration configs; search over findings in Postgres | `models.py` |
| Output | Executive summary (exposure index, recommendations, optional AI paragraph), global findings search + triage, Domain & infra, identity graph, PDF/TXT/JSON/CSV/SARIF | `reports.py`, `monitor_routes.py`, `static/workspace.js` |
| Integrations | Slack, Discord, Telegram, signed JSON webhook (SIEM/SOAR), GitHub Issues, email (SMTP) | `alerts.py`, `/integrations` |
| Supporting | Scheduler for daily/weekly re-scans (multi-process safe claim), in-process job pool, JSON logs | `osint/scheduler.py`, `logging_setup.py` |

**Deliberately not implemented:** social-media and search-engine scraping, dark-web/onion crawling and scraping paste sites by name. They collect data about any person typed in, cannot be restricted to identifiers the user owns, and break those sites' terms. Breach and paste exposure for the user's own verified email comes from HaveIBeenPwned instead. Elasticsearch/Celery/Redis are not used; Postgres and the in-process pool cover this scale.

**Network safety.** Every user-influenced request goes through `osint/net.py`: http(s) only, ports 80/443, all resolved addresses must be public, the connection is pinned to the vetted IP (Host header + TLS SNI keep the name, so DNS rebinding cannot redirect it), each redirect is re-validated, bodies are capped. Webhook destinations use the same client.

## How this connects to the CLI

The CLI itself remains fully local-first and does not talk to this platform by default —
that's a deliberate, unchanged design decision, not an oversight. The one exception is
explicit and opt-in: `opsec-scan --report-activity <platform-url> --report-activity-token
<token>` POSTs a scan summary (counts by risk label, target label) to `/activity/report-scan`
after a scan completes. A token is obtained by logging into the platform separately (e.g.
via curl against `/auth/login`) — the CLI doesn't implement an interactive login flow.

```bash
opsec-scan --repo . \
  --report-activity https://platform.example.com \
  --report-activity-token "$OPSEC_PLATFORM_TOKEN" \
  --target-label my-repo
```

To see the findings themselves in the web workspace, add `--upload-findings`. Use a CLI
access token from the workspace (**CLI access tokens** page) rather than a browser session
token. Only redacted findings are sent: the matched value is replaced by the redaction
placeholder before upload.

```bash
export OPSEC_PLATFORM_TOKEN=opsec_pat_...
opsec-scan --repo . --report-activity https://platform.example.com --upload-findings --target-label my-repo
```

If the platform is unreachable, the token is invalid, or the token is missing entirely, the
CLI prints a warning and continues — reporting activity never blocks or fails the actual
local scan. Verified end-to-end against a real running platform server: a real scan's
findings showed up correctly in the platform's activity log after being reported over a
real network call.

## Running the tests

```bash
pip install -e ".[platform,dev]"
pytest tests_platform/ -v          # platform: 30 tests
pytest tests/test_platform_client.py -v   # CLI-side reporting: 6 tests
```

**Platform (30 tests)**: registration, duplicate/validation rejection, org-bootstrap vs.
admin-gated add-user authorization (including cross-org isolation — an admin of one org
has no authority in another), login success/failure (including enumeration-resistance —
a wrong password and a nonexistent email return identical errors), login rate limiting
(blocks after threshold failures including with the correct password, covers unregistered
emails too, resets after the window expires), session verification and tamper-rejection,
logout actually revoking the session server-side (not just clearing a cookie), activity
logging for every event type, and OAuth error states for all four providers.

**CLI-side (6 tests, in the main `tests/` suite)**: scan-summary formatting, successful
reporting against a real live platform server (run in a background thread over genuine
loopback HTTP, not mocked), the reported activity actually appearing in the platform's log,
invalid-token rejection, and unreachable-platform handling.

