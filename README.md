# OPSEC Leak Scanner

<p align="center">
  <strong>Find what your repositories and media files reveal about you.</strong><br>
  <sub>Local-first OPSEC auditing for Git history, secrets, metadata, identity correlation, and risk.</sub>
</p>

<p align="center">
  <img src="https://github.com/Keshav-gehlot/opsec-scanner/actions/workflows/ci.yml/badge.svg" alt="CI status">
  <img src="https://img.shields.io/badge/python-3.10%2B-3776AB" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/focus-OPSEC-a8a29e" alt="OPSEC">
</p>

> **Security first:** scan your own repositories and media. Findings are redacted by default, and the CLI stays local unless you explicitly enable activity reporting.

## Project at a glance

| Layer | What it does |
| --- | --- |
| **Git engine** | History, root commits, deleted content, reflog/dangling commits, patch diffs |
| **Media engine** | Image EXIF, PDF/Office metadata and text, OCR |
| **Detection** | Patterns, entropy, allowlists, identity correlation |
| **Risk** | Severity × identity confidence × exposure |
| **Reporting** | HTML, JSON, SARIF, PDF, Operations Center, web explorer |
| **Optional platform** | Web workspace (Operations Center, scans, findings explorer), FastAPI auth, sessions, SSO, activity tracking |

## Documentation map

| Goal | Where to look |
| --- | --- |
| Run the scanner | **Installation** → **CLI usage** |
| Understand findings | **Detection and correlation** → `rules/` |
| Explore JSON findings | `webui/findings_explorer.html` |
| Run the auth platform | `opsec_platform/README.md` |
| Configure SSO | `opsec_platform/README.md` |
| Deploy | **CI/CD and deployment** |
| Contribute | **Testing** → **Contributing** |

## Current status

The repository is continuously tested in GitHub Actions. The optional platform is configured for deployment through the project's hosting environments; deployment state should be checked in the provider dashboards because it can change independently of source code.

| Area | State |
| --- | --- |
| CLI scanner | Local-first scanner with HTML, JSON, SARIF and optional PDF output |
| Platform auth | Password auth, revocable sessions, activity logging, OAuth wiring |
| Web workspace | Public-repo and media scans, CLI result uploads, findings explorer, scan diffs, exports |
| CI | GitHub Actions matrix for Python 3.10–3.12 plus platform/web UI checks |
| Vercel | Platform entrypoint configured for production deployment |
| Render | Dedicated API service + PostgreSQL |
| Supabase | Dedicated project exists; current application does not use Supabase tables/SDK |
| Google OAuth | Provider wiring exists; credentials are deployment secrets |


Self-audit OPSEC scanner for your own Git repositories and media files. It finds accidental exposure of identity data, secrets, internal infrastructure details, and document/image metadata, then correlates findings with a target identity and scores them by risk.

The project has two deliberately separate parts:

- **CLI scanner:** local-first. It does not contact external services unless you explicitly enable activity reporting.
- **Optional platform:** a web workspace (server-side scans of public repos and uploaded media, CLI result uploads, Operations Center, findings explorer) plus FastAPI authentication, SSO, session management, and activity tracking under `opsec_platform/`.

## Current status

The repository is continuously tested in GitHub Actions and is deployable as the optional platform backend.

| Area | Current state |
| --- | --- |
| CLI scanner | Production-tested feature set with HTML, JSON, SARIF, and optional PDF output |
| Git history scanning | Full history, root commits, deleted/dangling/reflog-reachable commits, patch-level scanning |
| Media scanning | Images, PDFs, DOCX, EXIF/document metadata, OCR |
| Detection | Regex rules + entropy gating + identity correlation + allowlists |
| Risk scoring | Severity × identity confidence × exposure weight, with finding deduplication |
| Operations Center | Local historical trend/diff reporting |
| Web UI | Standalone JSON findings explorer with client-side filtering/sorting/redaction |
| Platform auth | Password auth, revocable JWT-backed sessions, activity log, OAuth provider wiring |
| CI | GitHub Actions test matrix for Python 3.10–3.12 plus platform/web UI checks |
| Vercel | Production deployment for the platform entrypoint |
| Render | Dedicated API service plus dedicated PostgreSQL instance |
| Supabase | Dedicated project exists for project infrastructure/experimentation; the current application does not use Supabase tables or SDK integration |
| Google OAuth | Provider wiring exists; real credentials are intentionally configured separately in deployment secrets |

## Features

### Git history

The scanner walks repository history rather than inspecting only the current checkout.

It can detect:

- secrets that were committed and later deleted;
- credentials in patch diffs;
- findings in root commits;
- dangling/reflog-reachable history when present;
- internal IP addresses, hostnames, domains, and other custom patterns;
- identity references in commit metadata.

For incremental workflows, use `--since-ref` to scan only a ref range.

### Media and documents

The media engine supports:

- image EXIF metadata through `exiftool`;
- PDF metadata and body text through PyMuPDF;
- Office document properties and body text;
- OCR through `pytesseract`.

Missing or invalid input paths fail loudly rather than producing a misleading clean report.

### Detection and correlation

Rules live in `rules/patterns.yaml` and can be extended with custom regexes.

The scanner also supports:

- Shannon-entropy gating for likely random secrets;
- allowlisted findings and paths through `rules/allowlist.yaml`;
- identity correlation against names, aliases, email addresses, domains, handles, and optional locations;
- finding deduplication across repeated appearances.

A malformed custom regex is skipped with a warning, while corrupt core rules/configuration fail cleanly to avoid a false-clean result.

### Risk scoring

Risk is directional rather than a promise of exploitability:

```
risk_score = base_severity × identity_confidence × exposure_weight
```

Scores are intended for triage and comparison inside your own scans. Rule weights are calibrated against project fixtures, not a universal external benchmark.

### Reports

Outputs include:

- **HTML** case-file report;
- **JSON** export;
- **SARIF 2.1.0** for CI/security tooling;
- **PDF** export via WeasyPrint;
- **Operations Center** aggregate history dashboard.

Secret values are redacted by default in shareable exports. Explicit `--reveal-in-*` flags expose them and should be reserved for personal/private use.

### Interactive findings explorer

`webui/findings_explorer.html` is a standalone browser companion for JSON exports.

It supports:

- search;
- category/risk filtering;
- sorting;
- per-finding redact/reveal interaction.

The file is local-first: the loaded findings are processed in the browser and are not uploaded by the application.

### Operations Center

Save compact scan history with:

```bash
opsec-scan \
  --repo ~/projects/my-repo \
  --save-history \
  --target-label my-repo \
  --output report.html
```

Then render the aggregate dashboard:

```bash
opsec-scan --ops-center-output ops-center.html
```

The Operations Center compares the current snapshot with the previous scan for each target and surfaces new, resolved, and still-open findings.

## Installation

### Python package

```bash
pip install -e .
```

The platform test/development extras are:

```bash
pip install -e ".[platform,dev]"
```

### System tools

Image EXIF scanning requires `exiftool`. OCR requires Tesseract.

Debian/Ubuntu:

```bash
sudo apt-get update
sudo apt-get install libimage-exiftool-perl tesseract-ocr
```

PDF output uses WeasyPrint. On systems where the Python package cannot find Pango/Cairo/GDK-Pixbuf, install the platform-specific libraries described in the [WeasyPrint installation guide](https://doc.courtbouillon.org/weasyprint/stable/first_steps.html#installation).

## CLI usage

Initialize a target identity profile:

```bash
opsec-scan --init-profile
```

Basic repository scan:

```bash
opsec-scan \
  --repo ~/projects/my-repo \
  --output report.html
```

Repository plus media directory:

```bash
opsec-scan \
  --repo ~/projects/my-repo \
  --media-dir ~/screenshots \
  --output report.html
```

Generate multiple outputs:

```bash
opsec-scan \
  --repo ~/projects/my-repo \
  --output report.html \
  --json-output findings.json \
  --sarif-output findings.sarif \
  --pdf-output report.pdf
```

CI gate:

```bash
opsec-scan \
  --repo . \
  --fail-on CRITICAL \
  --sarif-output findings.sarif \
  --no-progress
```

Incremental scan:

```bash
opsec-scan \
  --repo . \
  --since-ref origin/main
```

### CLI options

| Option | Purpose |
| --- | --- |
| `--repo PATH` | Local Git repository to scan; repeatable |
| `--media-dir PATH` | Media/documents directory to scan; repeatable |
| `--profile PATH` | Identity profile path; default `./target_profile.yaml` |
| `--config PATH` | Project config path; default `./opsec-scan.yaml` when present |
| `--since-ref REF` | Scan only `REF..HEAD` |
| `--output PATH` | HTML report |
| `--json-output PATH` | JSON findings export |
| `--sarif-output PATH` | SARIF 2.1.0 export |
| `--pdf-output PATH` | Static PDF report |
| `--reveal-in-pdf` | Include full secret values in PDF; private use only |
| `--reveal-in-json` | Include full secret values in JSON; private use only |
| `--reveal-in-sarif` | Include full secret values in SARIF; private use only |
| `--fail-on LEVEL` | Exit 1 at or above `CRITICAL`, `HIGH`, `MEDIUM`, or `LOW` |
| `--no-progress` | Disable progress output |
| `--save-history` | Save summary history for Operations Center |
| `--history-dir PATH` | History store path |
| `--target-label NAME` | History label |
| `--ops-center-output PATH` | Render aggregate Operations Center and exit |
| `--entropy-threshold N` | Shannon entropy cutoff; default 3.5 |
| `--max-patch-commits N` | Maximum commits to patch-diff; `0` means unlimited |
| `--public-repo` | Treat scan target as publicly exposed |
| `--report-activity URL` | Optional platform endpoint for posting a scan summary |
| `--upload-findings` | With `--report-activity`: upload redacted findings to the web workspace |
| `--report-activity-token TOKEN` | Token used with `--report-activity` |

## Project configuration

Use `opsec-scan.yaml` to define defaults:

```yaml
entropy_threshold: 3.5
fail_on: CRITICAL
public_repo: false
```

Command-line arguments override configuration-file values.

## Pre-push integration

The repository includes `hooks/pre-push.sh`.

Install it locally:

```bash
cp hooks/pre-push.sh .git/hooks/pre-push
chmod +x .git/hooks/pre-push
```

The sample hook is designed for incremental scanning of commits about to be pushed.

## Optional platform

The FastAPI platform lives in `opsec_platform/` and is independent from the scanner CLI.

It provides:

- username/password registration and login;
- organization bootstrap for the first account;
- admin-gated user creation for existing organizations;
- bcrypt password hashing;
- signed JWT session tokens with server-side revocation;
- activity events for login, logout, failed login, registration, and reported scans;
- OAuth/OIDC wiring for Google, GitHub, Microsoft, and Apple;
- a web workspace at `/dashboard`: Operations Center, scan history, findings explorer with
  new/resolved diffs and JSON/CSV/SARIF export, server-side scans of public git repositories
  and uploaded images/PDF/Office files, CLI result imports, identity profile, CLI access tokens,
  sessions and organization management (raw matched values are never stored);
- origin-checked CSRF protection for state-changing requests;
- a health endpoint at `/health` (includes whether the detection rules loaded).

See `opsec_platform/README.md` for the workspace, its API and its safeguards.

The CLI remains fully functional without this backend.

### Platform local setup

From the repository root:

```bash
pip install -e ".[platform,dev]"
cp opsec_platform/.env.example opsec_platform/.env
```

Generate a local JWT secret:

```bash
python -c "import secrets; print(secrets.token_urlsafe(64))"
```

Set it in `opsec_platform/.env`, then export the environment and run:

```bash
export $(cat opsec_platform/.env | grep -v '^#' | xargs)
uvicorn opsec_platform.app.main:app --reload --port 8000
```

Open:

```
http://localhost:8000/login
```

### Password-auth flow

Register the first user of a new organization:

```bash
curl -X POST http://localhost:8000/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"you@example.com","password":"a-real-password","org_name":"My Org"}'
```

Login and save the session cookie:

```bash
curl -X POST http://localhost:8000/auth/login -c cookies.txt \
  -H "Content-Type: application/json" \
  -d '{"email":"you@example.com","password":"a-real-password"}'
```

Check the current user and activity:

```bash
curl http://localhost:8000/auth/me -b cookies.txt
curl http://localhost:8000/activity/me -b cookies.txt
```

### Production deployment notes

For a real deployment:

1. Use PostgreSQL rather than SQLite.
2. Set a unique, high-entropy `PLATFORM_JWT_SECRET`.
3. Keep `PLATFORM_COOKIE_SECURE=true`.
4. Set `PLATFORM_BASE_URL` to the public HTTPS origin.
5. Configure OAuth client IDs/secrets only in the hosting provider's secret/environment-variable store.
6. Put provider callback URLs at exactly `{PLATFORM_BASE_URL}/auth/oauth/{provider}/callback`.
7. Apply database migrations before deploying schema changes to an existing populated database.

The current reference platform uses SQLAlchemy `create_all()`; it does not provide a migration framework yet.

### OAuth providers

The platform wiring supports:

- Google
- GitHub
- Microsoft Entra ID
- Apple

Real provider credentials are deployment-specific and are intentionally not committed to the repository.

Before enabling a provider in production, verify its callback URL, credential validity, and provider-specific identity verification semantics.

See [`opsec_platform/README.md`](opsec_platform/README.md) for provider-specific registration details.

## Activity reporting from the CLI

Activity reporting is opt-in.

```bash
opsec-scan \
  --repo . \
  --report-activity https://platform.example.com \
  --report-activity-token "$OPSEC_PLATFORM_TOKEN" \
  --target-label my-repo
```

A failed activity-report request does not fail the local scan.

## Architecture

```
                    ┌───────────────────────┐
                    │      OPSEC CLI        │
                    │ local-first scanning  │
                    └───────────┬───────────┘
                                │
                ┌───────────────┼────────────────┐
                │               │                │
                ▼               ▼                ▼
          Git history       Media/OCR        Config/rules
                │               │                │
                └───────────────┼────────────────┘
                                ▼
                      Pattern + entropy engine
                                │
                                ▼
                        Identity correlation
                                │
                                ▼
                           Risk scoring
                                │
                 ┌──────────────┼───────────────┐
                 ▼              ▼               ▼
              HTML/JSON       SARIF            PDF
                 │
                 ▼
          Operations Center / Web UI

Optional:
CLI ──(explicit activity report)──► FastAPI platform ──► SQL database
                                      │
                                      ├── auth/session
                                      ├── OAuth
                                      └── activity log
```

## Repository layout

```
.
├── opsec_scanner/
│   ├── analysis/
│   ├── engines/
│   ├── output/
│   ├── scoring/
│   └── ...
├── opsec_platform/
│   ├── app/
│   ├── static/
│   ├── tests/
│   └── README.md
├── tests/
├── tests_platform/
├── webui/
├── hooks/
├── rules/
└── .github/workflows/ci.yml
```

## Testing

The repository uses automated tests for both the scanner and optional platform.

Run the scanner suite:

```bash
pytest tests/ -v
```

Run the platform suite:

```bash
pytest tests_platform/ -v
```

Run the combined local test set:

```bash
pytest tests/ tests_platform/ -q
```

The CI workflow runs the supported Python matrix and the web UI/platform checks on every push/PR.

## Security and privacy principles

OPSEC Scanner is designed for auditing your own repositories and media.

Important operational rules:

- Never commit filled-in `.env` files or provider secrets.
- Keep exported findings redacted by default.
- Treat reveal flags as private-use controls.
- Do not paste deployment credentials or OAuth secrets into issues, commits, logs, or chat.
- Use a production PostgreSQL database for multi-user deployments.
- Keep HTTPS and secure cookies enabled in production.
- Review allowlist entries carefully; an overly broad allowlist can hide a genuine finding.
- Treat risk scores as triage signals, not proof of exploitability.
- Re-run scans after remediation.

## Known limitations

### Scanner limitations

- Public-web/social crawling is not part of the current local-first CLI.
- Public exposure detection is heuristic unless the caller supplies `--public-repo`.
- Identity correlation is primarily exact/substring matching rather than full NLP/NER.
- Entropy is a useful signal but cannot perfectly distinguish short human passwords from real high-entropy secrets.
- OCR can corrupt characters and cause tight-format patterns to miss a finding.
- Risk weights are fixture-calibrated and should be reviewed against real workloads.

### Platform limitations

- OAuth credentials are deployment-specific.
- The current platform uses SQLAlchemy `create_all()` rather than Alembic migrations.
- Login rate limiting is primarily account/email based; add an IP/reverse-proxy control for internet-facing deployments.
- Provider-specific email verification and identity-linking behavior should be reviewed before enabling production SSO.
- SQLite is suitable for evaluation only; use PostgreSQL for production.

## CI/CD and deployment

### GitHub Actions

`.github/workflows/ci.yml` runs:

- scanner tests;
- platform tests;
- web UI tests;
- Python 3.10, 3.11, and 3.12 coverage.

Keep CI green before merging.

### Vercel

The platform entrypoint is configured for Vercel through the project configuration. Production deployments should be verified for:

- deployment state;
- build logs;
- runtime errors;
- `/`;
- `/login`;
- `/health`;
- auth endpoint behavior.

### Render

The deployed FastAPI service uses:

```
pip install '.[platform]'
uvicorn opsec_platform.app.main:app --host 0.0.0.0 --port $PORT
```

Use a dedicated PostgreSQL database for production and keep database credentials in Render environment variables.

## Change history

### v0.9

- Added persistent login rate limiting based on the activity log.
- Added opt-in CLI scan activity reporting.
- Fixed environment-setting defaults that were evaluated too early.
- Added regression coverage for platform auth/rate limiting and CLI reporting.

### v0.8.1

- Added organization-admin authorization for adding users.
- Added explicit cross-organization authorization checks.
- Added registration/bootstrap regression tests.

### v0.8

- Added optional FastAPI auth/activity platform.
- Added password auth and SSO provider wiring.
- Added revocable server-side sessions.
- Added activity logging.
- Fixed bcrypt compatibility, SQLite test isolation, secure-cookie test behavior, and OIDC discovery error handling.

### v0.7

- Added the standalone findings explorer web UI.
- Added browser-oriented XSS/redaction regression coverage.
- Added web UI CI coverage.

### v0.6

- Hardened error handling.
- Added shared report-theme components.
- Improved accessibility and responsive behavior.
- Added GitHub Actions CI.

### v0.5

- Added Operations Center history/trend reporting.
- Fixed history snapshot collisions.

### v0.4

- Added SARIF export, CI fail thresholds, incremental scanning, parallel media processing, progress reporting, and project config.
- Fixed root-commit patch scanning.

### v0.3

- Added PDF export with secure redaction defaults.

### v0.2

- Added OCR, document-body scanning, allowlists, expanded secret rules, identity-matching fixes, and the first pytest suite.

## Contributing

Keep changes small, testable, and security-conscious.

Before opening a pull request:

```bash
pytest tests/ tests_platform/ -q
```

Also verify any deployment-specific changes against the hosting provider involved.

## License

See the repository's license file for the current licensing terms.
