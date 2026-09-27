# OPSEC Leak Scanner

Self-audit tool that scans your own git history and media files (images/PDFs/Office docs)
for accidental OPSEC leaks — personal identity in commit metadata, secrets that were
"removed" but still live in git history, GPS EXIF data, internal hostnames, and more —
then correlates findings against your known identity to cut false positives, and scores
them by risk.

## Install

```bash
pip install -e .
```

Requires `exiftool` on PATH for image EXIF scanning, and `tesseract-ocr` for OCR scanning
of text rendered inside screenshots:

```bash
# Debian/Ubuntu
sudo apt-get install libimage-exiftool-perl tesseract-ocr
```

PDF export (`--pdf-output`) uses WeasyPrint, which needs Pango/Cairo/GDK-Pixbuf on the
system. The `pip install` pulls in the Python package; if PDF rendering fails on your OS,
see [WeasyPrint's install docs](https://doc.courtbouillon.org/weasyprint/stable/first_steps.html#installation)
for the platform-specific system libraries.

## Usage

1. Create your identity profile (used for correlation/confidence scoring):

   ```bash
   opsec-scan --init-profile
   ```

   Edit the generated `target_profile.yaml` with your name, aliases, emails,
   internal domains, GitHub handles, and optionally home/office GPS coordinates.

2. Run a scan:

   ```bash
   opsec-scan --repo ~/projects/my-repo --media-dir ~/screenshots --output report.html
   ```

   Add a PDF alongside it (secrets redacted by default — safe to share):

   ```bash
   opsec-scan --repo ~/projects/my-repo --output report.html --pdf-output report.pdf
   ```

3. Open `report.html` in a browser.

### Operations Center — continuous monitoring

Every other export is a single scan's report. This is the exception: run scans regularly
with `--save-history`, and render a trend dashboard across all of them.

```bash
# Run this on a schedule (cron, CI, pre-push hook) to build a monitoring history:
opsec-scan --repo ~/projects/my-repo --save-history --target-label my-repo --output report.html

# Then, any time, render the aggregate view across everything scanned so far:
opsec-scan --ops-center-output ops-center.html
```

The Operations Center shows current status per monitored target, a trend strip of findings
over recent scans, and a new/resolved/still-open diff against each target's previous scan —
so a repeated scan tells you *what changed*, not just a fresh copy of everything found.

### Interactive web UI

The HTML/PDF reports are static snapshots. `webui/findings_explorer.html` is an interactive
companion for exploring a JSON export — search, filter by category/risk level, sort, and a
per-finding redact/reveal toggle — with no server and no build step:

```bash
opsec-scan --repo . --json-output findings.json
open webui/findings_explorer.html   # then drag findings.json onto the page, or use "Load case file"
```

It shares the exact color tokens and typography as the CLI's reports, and runs entirely in
your browser — the file never uploads your findings anywhere. See `webui/README.md` for how
it handles redaction and how to run its test suite.

### Optional: auth + activity-tracking platform

For teams that want org-provisioned login (username/password, or SSO via Google/GitHub/
Microsoft/Apple) and a queryable activity log, `opsec_platform/` is a separate FastAPI
backend — entirely optional, and the CLI above works exactly the same with or without it.
See `opsec_platform/README.md` for setup, including how to register an SSO app with each
provider (required for SSO to work — that step can't be done on your behalf).

### CI / pre-push hook use

Gate a build or block a push on CRITICAL findings:

```bash
opsec-scan --repo . --fail-on CRITICAL --sarif-output findings.sarif --no-progress
```

Install the sample pre-push hook (scans only commits about to be pushed, not full history):

```bash
cp hooks/pre-push.sh .git/hooks/pre-push
chmod +x .git/hooks/pre-push
```

### Project config

Instead of repeating flags every run, drop an `opsec-scan.yaml` at your repo root (see
`opsec-scan.example.yaml`) — any flag passed on the command line still overrides it:

```yaml
entropy_threshold: 3.5
fail_on: CRITICAL
public_repo: false
```

| Flag | Purpose |
| --- | --- |
| `--repo PATH` | Local git repo to scan (repeatable) |
| `--media-dir PATH` | Directory of images/PDFs/docx to scan (repeatable) |
| `--profile PATH` | Path to identity profile YAML (default: `./target_profile.yaml`) |
| `--config PATH` | Path to project config YAML (default: `./opsec-scan.yaml` if present) — see `opsec-scan.example.yaml` |
| `--since-ref REF` | Only scan commits in `REF..HEAD` instead of full history (pre-push hook use) |
| `--output PATH` | HTML report output path |
| `--json-output PATH` | Optional JSON export of findings |
| `--sarif-output PATH` | Optional SARIF 2.1.0 export (GitHub/GitLab PR check integration) |
| `--pdf-output PATH` | Optional static PDF export (same case-file design as the HTML report, via WeasyPrint) |
| `--reveal-in-pdf` / `--reveal-in-json` / `--reveal-in-sarif` | Show secret values in full instead of the redacted default — personal use only, do not distribute a file generated with these flags |
| `--fail-on LEVEL` | Exit with status 1 if any finding is at or above `CRITICAL`\|`HIGH`\|`MEDIUM`\|`LOW`. Default: `NONE` (never fails) |
| `--no-progress` | Disable progress bars — useful for clean CI log output |
| `--save-history` | Save this scan's summary to the local history store for Operations Center trend tracking |
| `--history-dir PATH` | Path to the history store (default: `./.opsec-scan/history/`) |
| `--target-label NAME` | Label for this scan in the history store (default: derived from `--repo`/`--media-dir`) |
| `--ops-center-output PATH` | Render the aggregate Operations Center dashboard from all saved history and exit (does not run a new scan) |
| `--entropy-threshold N` | Shannon entropy cutoff for flagging random secrets (default: 3.5) |
| `--max-patch-commits N` | Cap on commits patch-diffed for line-level secret scanning (default: 500, `0` = unlimited) |
| `--public-repo` | Mark scanned targets as already publicly exposed (forces exposure weight to 1.0×) |

## Architecture

```
Git Engine ──┐
             ├─► Pattern/Entropy Engine ─► Identity Graph ─► Risk Scoring ─► Dashboard/JSON
Media Engine ┘
```

- **`src/engines/git_engine.py`** — full commit history walk (not just HEAD), dangling/reflog
  commit recovery, line-level patch diffing so "deleted" secrets are still caught.
- **`src/engines/media_engine.py`** — EXIF via `exiftool`, PDF metadata via PyMuPDF,
  Office docProps via raw XML parsing.
- **`src/analysis/patterns.py` + `rules/patterns.yaml`** — editable regex rule set,
  with optional Shannon-entropy gating so placeholder "secrets" like `password=hunter2`
  don't score the same as a real random API key.
- **`src/analysis/identity_graph.py`** — confidence multiplier based on whether a finding
  actually correlates to your known identity (name/email/domain/handle) or GPS proximity
  to a known location, vs. being a generic/unrelated match.
- **`src/scoring/risk_engine.py`** — `risk_score = base_severity × identity_confidence × exposure_weight`,
  with deduplication so one secret touched across 10 commits doesn't show up as 10 findings.

## Known limitations / v2 ideas

- Web/social crawler (public GitHub API scanning, cross-platform handle correlation) not
  yet built — this is a local-scan-first tool by design.
- `exposure_level` inference is currently heuristic (dangling commit = hidden, everything
  else = local-only unless `--public-repo` is passed). A real "is this repo actually public"
  check via the GitHub API is the natural next step.
- No NLP/NER — identity matching is exact/substring string matching (word-boundary-aware
  for names/aliases, plain substring for emails/domains), which is cheap and catches most
  real cases but won't catch fuzzy name variants.
- **Entropy-based secret detection has a real, documented limitation**: Shannon entropy per
  character caps out at `log2(string_length)` for all-unique-character strings, meaning
  short-to-medium real secrets (16-24 chars) and "strong-looking" human-typed passwords
  overlap in entropy score. The default threshold (3.5) is tuned to catch real secrets at
  the cost of occasional false positives on human passwords — see `src/analysis/entropy.py`
  for the full calibration writeup. Production scanners (gitleaks/trufflehog) supplement
  raw entropy with charset-diversity and dictionary checks; that's the natural next fix here.
- OCR (`pytesseract`) can introduce noise (dropped/added characters, mangled punctuation)
  that fragments exact-format regexes like `AKIA[0-9A-Z]{16}`. The generic key=value rule
  still catches most of these via the `secret=`/`password=` prefix even when the value
  itself is corrupted, but tight-format rules can miss OCR'd secrets.
- Risk weights in `rules/patterns.yaml` and `EXPOSURE_WEIGHTS` were calibrated against a
  small hand-built test fixture, not a large real-world corpus — treat scores as directional,
  and tune the YAML as you run it against real repos.

## Changelog

**v0.9** — closed two more flagged gaps: login rate limiting, and the CLI-to-platform
activity loop that was previously only architecturally possible, not actually built.

- **Login rate limiting**: `PLATFORM_LOGIN_RATE_LIMIT_ATTEMPTS` (default 5) within
  `PLATFORM_LOGIN_RATE_LIMIT_WINDOW_MINUTES` (default 15), counted from the activity log
  itself rather than a separate in-memory store — persisted, auditable, and correct across
  multiple app processes. Verified that even the *correct* password gets blocked once the
  threshold is hit, that it also covers emails that were never registered (closing the
  obvious bypass of only probing unregistered addresses), and that it resets once the
  window passes.
- **Found and fixed a real latent bug while adding this**: the rate-limit settings (and,
  it turned out, the pre-existing `session_ttl_minutes`) used a plain dataclass default
  expression instead of `field(default_factory=...)` like every other setting — meaning
  the value was baked in once at module import time, and setting the environment variable
  afterward (exactly what happens in any real deployment that sets env vars after the
  process's first import) silently had no effect.
- **The CLI can now actually report scan activity to the platform** — `opsec-scan
  --report-activity <url> --report-activity-token <token>`, completing the original
  "activity on this platform can be tracked" request end-to-end rather than leaving it as
  a receiving endpoint with nothing on the sending side. Stays opt-in and never blocks or
  fails the local scan if the platform is unreachable.
- Verified genuinely end-to-end, twice over (including after an unrelated environment
  reset lost the in-progress work and required rebuilding it from scratch): ran a real
  platform server, obtained a real login token over real HTTP, ran a real `opsec-scan`
  scan against a real repo with `--report-activity` pointed at it, and confirmed the exact
  finding counts showed up correctly in the platform's activity log afterward.
- Testing this surfaced a real design decision: `httpx.ASGITransport` (which would let
  tests hit an in-process app with zero real sockets) only supports async requests, but
  the CLI correctly uses a synchronous `httpx.Client` — no reason to drag asyncio into a
  single outbound POST from a CLI tool. Rather than compromise that design for test
  convenience, the tests run a real ephemeral server in a background thread instead, over
  genuine loopback HTTP.
- 6 new CLI-side tests (`tests/test_platform_client.py`) + 5 new rate-limiting tests
  (`tests_platform/`). 131 tests total across both suites.

**v0.8.1** — closed the authorization gap the previous pass's README flagged by name
(`/auth/register` had no admin gate):

- Bootstrapping a brand-new org (its first account) still needs no authentication — there's
  no one to authenticate as yet — and that first user now becomes the org's admin
  automatically (`is_org_admin`, a new column).
- Adding a user to an org that *already has members* now requires being authenticated as an
  admin of that specific org. Both conditions are checked explicitly: being an admin
  somewhere doesn't grant authority everywhere — an admin of one org gets a clean 403
  trying to add users to a different org, verified by test, not just asserted.
- Added a `get_current_user_optional` dependency (returns `None` instead of raising) so
  `/auth/register` can tell "unauthenticated" apart from "authenticated but not authorized"
  and return the correct 401 vs. 403 rather than collapsing both into one response.
- 6 new tests covering bootstrap, unauthenticated-add-rejected, non-admin-add-rejected,
  admin-add-succeeds (as a non-admin member, matching real invite semantics), and the
  cross-org isolation case. 25 tests total in `tests_platform/`, all passing alongside the
  unchanged 95-test CLI suite.
- Documented in the README that this schema change (a new column) applies automatically to
  a fresh database but won't alter an already-populated `platform.db` — this reference
  implementation uses SQLAlchemy's `create_all()`, not Alembic, so real migrations are a
  gap to close before this holds production data across schema changes.

**v0.8** — an optional auth + activity-tracking platform (`opsec_platform/`), separate from
the CLI, which remains fully local-first and unchanged:

- Organization-provisioned username/password login (bcrypt-hashed) plus SSO for Google,
  GitHub, Microsoft (Entra ID), and Apple, via Authlib rather than hand-rolled OAuth/OIDC.
- Sessions are JWS-signed JWTs (PyJWT), each carrying a `jti` claim tied to a revocable
  server-side session row — logout actually invalidates the session, not just the cookie.
- An activity log (login/logout/failed-login/registration/scan-reported events), queryable
  per-user — "activity on this platform can be tracked" as a real, tested feature.
- **OAuth can't be pre-connected to real provider accounts** — that inherently requires
  registering an app with each provider from your own developer account and obtaining a
  client ID/secret, which isn't something that can be done on someone's behalf. Every
  provider is fully wired and tested; `opsec_platform/README.md` documents the exact setup
  steps (including Apple's unusual JWT-based client secret) for whoever owns the deployment.
- Found and fixed three real bugs during testing, not by inspection: (1) passlib's bcrypt
  backend is broken against bcrypt>=4.1 — switched to `bcrypt` directly; (2) SQLite
  `:memory:` databases are connection-scoped, so `init_db()`'s tables were invisible to
  request-time connections until pinned to a single connection via `StaticPool`; (3) the
  session cookie's `Secure` flag (correctly required for any real deployment) silently
  dropped the cookie over TestClient's plain-http test requests, breaking every
  "log in, then make an authenticated request" test — made configurable via
  `PLATFORM_COOKIE_SECURE` rather than hardcoded.
- Also found a raw-traceback gap: an OIDC provider's discovery-document fetch failing
  (network hiccup, outage, or this sandbox's restricted egress) surfaced as an unhandled
  exception instead of a clean error — fixed to return a clear 502.
- The README's own documented quick-start command was verified by actually running it, not
  just written — which caught a real bug in the instructions themselves (`cd opsec_platform
  && uvicorn app.main:app` fails; the app's absolute imports require running from the repo
  root). Every command in the README, including the full register → login → me → activity
  curl flow, was run end-to-end against a live server before being left in the docs.
- 19 new tests (`tests_platform/`), plus a `platform-test` CI job. 114 tests total across
  the CLI and platform.

**v0.7** — an interactive web UI companion, since the HTML/PDF reports are static snapshots
with no search, filter, or sort:

- `webui/findings_explorer.html` — a standalone, single-file, no-build client-side explorer
  for `--json-output` exports. Search, filter by category/risk level, sort, and a per-finding
  redact/reveal toggle. Shares the exact color tokens and stamp styling from
  `report_theme.py` so it reads as one product with the CLI's reports, not a separate tool.
- Redaction handling matches the CLI's safety-by-default design rather than a generic
  "click to view" toggle: if the loaded export was generated with `--reveal-in-json`, the
  real values are present but still shown redacted by default with an opt-in reveal button
  per finding; if the export was redacted at generation time, the real value was never
  written to the file at all, so the UI says so plainly instead of rendering a reveal
  button that would silently do nothing.
- Verified without a real browser available in this environment: wrote the core logic as
  pure functions and unit-tested them under Node (17 tests), then used jsdom to load the
  *actual shipped HTML file* and drive it like a real browser would — file loads, clicks,
  search/filter/sort, XSS payloads — rather than only testing a reimplementation (13 tests).
- One test caught a real question worth resolving rather than assuming: an XSS regression
  test initially failed on a payload appearing in a `data-key` HTML attribute. Investigated
  before concluding either way — confirmed via direct jsdom experiment that escaped text
  safely round-trips through attribute serialization without executing or becoming a real
  DOM element, so the original test's raw-substring assertion was the actual bug, not the
  escaping logic. Fixed the test to check what's actually safety-relevant (execution, real
  element creation) instead of raw text matching that can't distinguish inert serialized
  attribute text from genuinely unescaped markup.
- Added a `webui-test` job to CI so this has the same "tested on every push" guarantee as
  the Python side, instead of being a side deliverable nobody keeps working.

**v0.6** — a UX/system-design audit pass across error states, component reuse, accessibility,
and post-launch testing. Found by actually exercising realistic scenarios (typo'd paths,
corrupt config files, computed contrast ratios), not by reading code:

*Error states — previously either crashed with a raw traceback or, worse, failed silently:*

- Any invalid `--repo` path (nonexistent, not a git repo, a file instead of a directory)
  dumped a raw Python traceback. Now a clean one-line error.
- **A typo'd `--media-dir` path silently produced a "clean" 0-findings report** — the worst
  failure mode possible for a security tool, since it looks identical to "nothing was found."
  Now fails loudly instead.
- Corrupt `target_profile.yaml` / `opsec-scan.yaml` / `rules/patterns.yaml` crashed with raw
  YAML parser tracebacks. Now clean messages — and a deliberate split: the allowlist degrades
  gracefully (it's a false-positive filter, not core detection), while the profile/config/rules
  files hard-fail, since silently continuing there risks a false "all clean" scan.
- A single typo'd regex in a custom rule crashed the whole tool. Now skipped with a warning,
  the rest of the rule set keeps working.

*Component reuse / visual consistency — CSS tokens were hand-duplicated across reports:*

- `dashboard.py` and `ops_center.py` each independently defined the same color tokens, the
  `.stamp` badge styling, the HTML-escaping function, and the Google Fonts loading logic —
  and they'd already drifted (ops_center's stamps rendered at a different size than
  dashboard's). Extracted into `report_theme.py`, a single source of truth every report
  now imports from, so a future change can't silently apply to only one report.
- Found the same "same color, three independent hardcoded copies" pattern a second and third
  time (a warning banner, a diff chip) even after the initial extraction — fixed those to
  reference the shared token too, and added a regression test that fails if the old
  hardcoded value ever reappears anywhere in either file.

*Accessibility — computed actual WCAG contrast ratios instead of eyeballing:*

- `--muted-dim` (used for field labels, rule IDs, and entry numbers throughout every report)
  measured 2.87:1 against the dark background — well below WCAG AA's 4.5:1 minimum for
  normal text. Corrected to `#727c83` (4.50:1), same hue, same three-tier text hierarchy.
- The CRITICAL stamp color measured 3.76:1 — the small bold badge text doesn't qualify for
  WCAG's "large text" 3:1 exception. Corrected to `#c75854` (4.53:1), still clearly red.
- `ops_center.py` was missing the `prefers-reduced-motion` and print-media handling that
  `dashboard.py` already had — another visible symptom of the same duplication problem,
  fixed by the same `report_theme.py` consolidation.

*Post-launch testing:*

- The project's own repo had no CI. Added `.github/workflows/ci.yml` running the full test
  suite across Python 3.10–3.12 on every push/PR, plus a regression check that the installed
  `opsec-scan` console command actually works when invoked from outside the repo — a direct
  guard against the exact packaging bug found earlier in this project's history.

Added 26 new regression tests across error handling, visual consistency, and accessibility.
Full suite: 95 passing.

**v0.5.1** — removed an unnecessary external network dependency from unattended report generation:

- Both `dashboard.py` and `ops_center.py` always fetched Google Fonts over the network at
  render time via a `<link>` tag — harmless for the interactive HTML report (opened in a
  real browser), but a real reliability risk for PDF export via WeasyPrint, which is exactly
  the output format most likely to run unattended (CI, a cron'd Operations Center scan, a
  pre-push hook). Different networks fail differently — some fast-fail, some hang until a
  connection timeout — and a local-first tool shouldn't need an external CDN at all for this.
- Fixed: PDF/static export modes now render with zero external requests, using the existing
  system-font fallback stack (already defined, just previously unused unless the CDN fetch
  failed). The interactive HTML report keeps the Google Fonts link as a progressive
  enhancement, since a browser will have normal internet access.
- Measured before fixing rather than assuming: in this environment the blocked fetch failed
  fast rather than hanging (no dramatic timeout), but removing it dropped PDF generation time
  from ~2.7s to ~0.8s and eliminated the dependency regardless of how a given network handles
  a blocked/rate-limited request to `fonts.googleapis.com`.
- Confirmed the fix doesn't visually break anything by rendering a PDF and inspecting it —
  layout, stamps, and redaction bars are unaffected with the system monospace fallback.

**v0.5** — Operations Center: continuous monitoring instead of one-shot scans.

- Every scan so far was a single point-in-time report. `--save-history` appends a lightweight
  summary snapshot (counts by risk label, per-finding fingerprints, timestamp) to a local
  history store (`./.opsec-scan/history/` by default — no database, no server, same
  local-first design as everything else).
- `--ops-center-output` renders an aggregate dashboard across all saved history: current
  status per monitored target, a trend strip showing findings-over-time, and a new/resolved/
  still-open diff against each target's previous scan — the actual "continuous monitoring"
  behavior a SOC/operations-center concept implies, versus a single report.
- **Found and fixed a real bug while testing this**: snapshot filenames used second-resolution
  timestamps, so two scans run back-to-back (e.g. scanning multiple repos in one invocation)
  silently overwrote each other's history file. Fixed with microsecond resolution plus a
  content-hash suffix.
- Reuses the existing case-file visual language (same fonts, stamps, tokens) rather than
  introducing a new design for this view.

**v0.4.1** — two packaging bugs found by actually testing the documented install path, which
had never been verified end-to-end before (everything had been run via `python3 -m ...`):

- **The `opsec-scan` console command was completely broken.** The package was named `src` —
  fine for `python3 -m src.main` from inside the repo, but fragile/ambiguous for an installed
  console script. Renamed the package to `opsec_scanner` throughout.
- **`pip install -e .` failed outright** after the rename with a "multiple top-level packages"
  error — setuptools' auto-discovery got confused by `hooks/` and `rules/` sitting at the repo
  root alongside the package. Fixed with an explicit `[tool.setuptools.packages.find]` include
  list instead of relying on auto-discovery.
- Verified the fix properly: ran `opsec-scan --help` and a full scan from `/tmp`, completely
  outside the project directory, not just re-running the existing `python -m` invocations.
- **Fixed a real timeout gap**: `exiftool` calls had a 15s timeout guard, but the OCR pass
  (`pytesseract.image_to_string`) had none at all — a pathological or malformed image could
  hang a scan indefinitely, and matters more now that media scanning runs in a thread pool,
  since a hung OCR call ties up a worker slot rather than just blocking a single sequential run.
- Checked (rather than assumed) whether binary files committed to a repo cause garbage patch
  findings or hangs during diffing — verified they don't; git's own binary detection already
  handles this correctly, so no fix was needed there.

**v0.4** — CI/CD integration, performance, and a real bug found along the way:

- **Fixed a redaction gap**: JSON export always dumped secrets in plaintext with no
  redaction option, while PDF export had already been fixed to redact by default. JSON
  now matches — `export_json(..., reveal=False)` by default, same as PDF.
- **SARIF 2.1.0 export** (`--sarif-output`) — the original architecture diagram called for
  this and only plain JSON was ever built. GitHub/GitLab render SARIF natively as inline PR
  annotations.
- **CI exit codes** (`--fail-on CRITICAL|HIGH|MEDIUM|LOW`) — the tool previously always
  exited 0, so it couldn't gate a build or block a push.
- **Incremental scanning** (`--since-ref`) — scans only `since_ref..HEAD` instead of full
  history, making the tool usable as an automatic pre-push hook rather than something run
  manually for occasional audits. See `hooks/pre-push.sh` for a drop-in example.
- **Found and fixed a real detection bug while building the incremental-scan tests**: patch
  diffing skipped root commits (commits with no parent) entirely, on the assumption their
  diff was "just noise." That meant a secret committed in a repo's very first commit was
  completely invisible to scanning — not an edge case, a common real pattern. Fixed by
  diffing root commits against git's empty tree instead of skipping them.
- **Parallel media scanning** — `scan_media_dir` now uses a thread pool instead of scanning
  files one at a time; exiftool/tesseract subprocess calls are I/O-bound enough for this to
  give a real speedup without a full asyncio rewrite.
- **Progress bars** (`rich`, which had been a dependency since the first build but was never
  actually used) for both git patch-diffing and media scanning — the two slowest stages.
  `--no-progress` disables them for clean CI log output.
- **Report scan-scope footer** — the case-file report now states how many commits/media
  files were actually scanned, not just how many findings resulted.
- **Project config file** (`opsec-scan.yaml`, see `opsec-scan.example.yaml`) so a repo can
  set defaults once instead of repeating 8+ flags every run; explicit CLI flags still
  override the config file.

**v0.3** — added PDF export:

- `--pdf-output` renders the same case-file design to PDF via WeasyPrint (one HTML source of
  truth, no separate reportlab layout to maintain).
- The interactive HTML report's click-to-reveal secret disclosure has no equivalent in a
  static file, so this was made an explicit decision rather than silently broken or unsafe:
  PDFs redact secret values by default (safe to share/archive/print), with `--reveal-in-pdf`
  as an opt-in for a personal-use copy that carries a visible "do not distribute" banner.
- Verified programmatically (not just by eye) that the redacted PDF never contains plaintext
  secrets and the revealed variant does — see `tests/test_pdf_export.py`.
- Also fixed a bug from the previous pass where a partially-applied edit had left
  `dashboard.py` in a broken state (a function with a `-> str` signature that also tried to
  write to an undefined file path, and a missing `render_dashboard` entrypoint).

**v0.2** — addressed gaps from the initial build:

- Added OCR scanning (`pytesseract`) for text rendered inside screenshots — the original
  design called for this and the first build skipped it entirely.
- Added document *body* text scanning for PDFs and `.docx` (previously only metadata fields
  were scanned; a password pasted directly into a doc body was invisible to the scanner).
- Added an allowlist/ignore mechanism (`rules/allowlist.yaml`) for known vendor placeholders
  and excluded paths (`node_modules/`, `vendor/`, test fixtures) — explicitly called for in
  the original design and missing from the first build.
- Fixed a false-positive bug in identity matching: short aliases (e.g. "sam") were matching
  as substrings inside unrelated words ("sample", "username"). Now word-boundary-aware for
  names/handles.
- Fixed a mismatch between the entropy threshold (4.5) and realistic secret lengths — real
  16-24 character secrets were being silently filtered out by the credential-entropy gate.
  Recalibrated to 3.5 with the tradeoff documented above.
- Expanded the regex rule set from 12 to 20 rules — added GitHub PAT, Slack, Stripe, Google/GCP,
  Azure, npm, generic Bearer token, and SSH key filename patterns.
- Added a real `pytest` suite (28 tests) covering entropy, pattern matching, identity
  correlation, git extraction, and risk scoring — replacing ad-hoc manual bash verification.
