"""
Shared report design system.

dashboard.py and ops_center.py previously hand-duplicated their CSS
tokens, stamp colors, HTML-escaping function, and Google Fonts loading
logic — verbatim, in two places. That's not just untidy: it's the exact
mechanism that caused a real bug earlier (the Google Fonts network
dependency got fixed in one file and had to be separately remembered
and fixed in the second file). Every report-rendering module should
import from here instead of redefining its own copy, so a future change
to the color system, escaping rules, or font loading only has to happen
once and can't drift between reports.

This intentionally holds *shared primitives*, not full page layouts —
each report still owns its own structure and content-specific CSS
(the "case file" layout in dashboard.py vs. the "target card" grid in
ops_center.py are legitimately different enough not to force into one
shape). What belongs here is anything that must stay visually identical
across every report for the tool to look like one coherent product.
"""

from __future__ import annotations

# Risk-label -> stamp color. Used by every report that shows a
# CRITICAL/HIGH/MEDIUM/LOW badge.
# Risk-label -> stamp color. Used by every report that shows a
# CRITICAL/HIGH/MEDIUM/LOW badge. Checked against the --ink background
# for WCAG AA contrast (4.5:1 for normal text) rather than picked by
# eye — stamp text is small (10px bold) and doesn't qualify for WCAG's
# "large text" 3:1 exception, so it needs the full 4.5:1. CRITICAL was
# originally #c0433f at 3.76:1 (a real failure); #c75854 hits 4.53:1
# while staying recognizably red. HIGH/MEDIUM/LOW already passed as-is.
STAMP_COLORS = {
    "CRITICAL": "#c75854",
    "HIGH": "#c07f3f",
    "MEDIUM": "#b8a13f",
    "LOW": "#3f8f6e",
}

# Core color/typography tokens shared by every report. Kept as a plain
# dict (not pre-baked CSS) so callers can still assemble their own
# :root block with an f-string in whatever layout they need, without
# risking the values themselves drifting between reports.
TOKENS = {
    "ink": "#0d0f12",
    "panel": "#15181a",
    "panel_raised": "#191d20",
    "line": "#262b2e",
    "text": "#dde1e3",
    "muted": "#7a8288",
    # WCAG AA requires 4.5:1 contrast for normal-size text. The original
    # value here (#565d62) measured 2.87:1 against the --ink background —
    # found by actually computing contrast ratios, not eyeballing — and
    # this color is used for real content (field labels, rule IDs, entry
    # numbers), not just decoration. #727c83 hits 4.5:1 exactly while
    # keeping the same hue, preserving the three-tier text hierarchy
    # (text > muted > muted_dim) instead of collapsing it to fix contrast.
    "muted_dim": "#727c83",
    "mono": "'IBM Plex Mono', ui-monospace, Consolas, monospace",
    "sans": "'IBM Plex Sans', -apple-system, 'Segoe UI', sans-serif",
}


def root_css_vars() -> str:
    """Renders the shared :root {} custom-property block. Every report
    includes this verbatim rather than retyping the hex values.

    Uses single braces (not the doubled {{ }} f-string-escape syntax) —
    this function's return value gets inserted into callers' f-strings
    via normal {expr} interpolation, not written as literal source text
    inside their f-string bodies, so it must not carry escaping meant
    for a different context."""
    t = TOKENS
    return (
        "  :root {\n"
        f"    --ink: {t['ink']};\n"
        f"    --panel: {t['panel']};\n"
        f"    --panel-raised: {t['panel_raised']};\n"
        f"    --line: {t['line']};\n"
        f"    --text: {t['text']};\n"
        f"    --muted: {t['muted']};\n"
        f"    --muted-dim: {t['muted_dim']};\n"
        f"    --mono: {t['mono']};\n"
        f"    --sans: {t['sans']};\n"
        "  }"
    )


def esc(s: object) -> str:
    """HTML-escapes a value for safe interpolation into a report
    template. Every report must run scanned content (which is
    attacker-influenceable — it's text pulled from a repo/media file
    someone else wrote) through this before templating it in."""
    return (
        str(s)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def google_fonts_link_html(include: bool) -> str:
    """
    Builds the Google Fonts <link> tags, or an empty string.

    include should be True only when the HTML will be opened in a real
    browser with normal internet access (the interactive report).
    Static renders (PDF via WeasyPrint, or any other unattended/headless
    render) should pass False — that's the exact case that runs in CI,
    cron jobs, and pre-push hooks, where depending on an external CDN
    is a real reliability risk, not just a cosmetic one. Every report
    that loads fonts must go through this one function so that decision
    can't be made differently (or forgotten) in one report but not another.
    """
    if not include:
        return ""
    return (
        '<link rel="preconnect" href="https://fonts.googleapis.com">\n'
        '<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600;700'
        '&family=IBM+Plex+Sans:wght@400;500;600&display=swap" rel="stylesheet">'
    )


def stamp_html(risk_label: str, extra_class: str = "") -> str:
    """Renders one CRITICAL/HIGH/MEDIUM/LOW stamp badge — the same
    visual element appears in the evidence log, the docket tallies, and
    the Ops Center diff list. One function so it can't visually diverge
    between those three contexts."""
    color = STAMP_COLORS.get(risk_label, "#6b7280")
    cls = f"stamp {extra_class}".strip()
    return f'<span class="{cls}" style="--stamp-color:{color}">{esc(risk_label)}</span>'


# Shared CSS for the .stamp component itself, since stamp_html() above
# assumes this class exists in whatever report includes it.
STAMP_CSS = """
  .stamp {
    font-family: var(--mono);
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 0.08em;
    color: var(--stamp-color);
    border: 1.5px solid var(--stamp-color);
    border-radius: 2px;
    padding: 2px 7px;
    transform: rotate(-1deg);
    display: inline-block;
  }
"""

# Shared accessibility/robustness media queries — every report should
# respect reduced-motion preferences and render sensibly on mobile and
# in print. Previously only dashboard.py had the full set; ops_center.py
# had a partial one that had drifted out of sync (mobile breakpoint only,
# no reduced-motion or print handling).
ACCESSIBILITY_CSS = """
  @media (prefers-reduced-motion: reduce) {
    html { scroll-behavior: auto; }
    * { transition: none !important; animation: none !important; }
  }

  @media print {
    body { padding-bottom: 40px; }
  }
"""
