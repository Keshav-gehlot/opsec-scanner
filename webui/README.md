# OPSEC Findings Explorer (web UI)

A standalone, interactive companion to the CLI's `--json-output`. The CLI's HTML/PDF reports
are static snapshots; this is an interactive explorer for filtering, searching, and reviewing
findings from a JSON export — no server, no build step, no install.

## Usage

1. Generate a JSON export:
   ```bash
   opsec-scan --repo . --json-output findings.json
   ```
2. Open `findings_explorer.html` in any browser (double-click it, or `open findings_explorer.html`).
3. Load `findings.json` via the "Load case file" button or by dragging it onto the page.

Everything happens client-side — the HTML file never sends your findings anywhere. That's
also why it can't run a fresh scan itself; it only explores a JSON file you already generated.

## Redaction behavior

Matches the CLI's safety-by-default design:

- If the JSON was exported with `--json-output` alone (the default), values are already
  redacted at generation time — the real secret was never written to the file, so the UI
  shows a plain "redacted at export time" note instead of a reveal button that would do nothing.
- If the JSON was exported with `--reveal-in-json`, real values are present in the file, and
  the UI defaults to showing them redacted anyway with a per-finding "reveal" toggle — the
  same opt-in-to-view pattern as the PDF/HTML reports, not a blanket dump.

## Design

Shares the exact color tokens, stamp component, and typography (IBM Plex Mono/Sans) as
`opsec_scanner/output/report_theme.py`, so this and the CLI-generated reports read as one
product. If you change a color or the stamp styling in `report_theme.py`, update the
`:root` block and `.stamp` rules at the top of `findings_explorer.html` to match.

## Development / testing

The interactive logic (parsing, filtering, sorting, the redaction-safety check) is
unit-tested under Node before being embedded in the HTML file, and separately
integration-tested against the actual shipped file via jsdom (simulating real file loads,
clicks, and filter interactions against the real DOM, not a reimplementation of it).

```bash
npm install
npm test
```

- `core.js` / `core.test.js` — pure-function unit tests for the core logic
- `dom.test.js` — loads `findings_explorer.html` directly via jsdom and drives it like a
  real browser would (file load, search/filter/sort, reveal/hide, XSS-safety checks)

If you edit the embedded `<script>` in `findings_explorer.html`, re-run `npm test` — the
DOM test suite exercises the actual shipped file, so it will catch drift between `core.js`
and the embedded copy, or any regression in the redaction-safety logic.
