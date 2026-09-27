"""
Accessibility regression tests.

Computes actual WCAG contrast ratios rather than eyeballing colors —
this is how the muted_dim (2.87:1) and CRITICAL stamp (3.76:1) contrast
failures were originally found. Both are real WCAG AA failures for
normal-size text (4.5:1 minimum; the 3:1 "large text" exception doesn't
apply to any text size used in these reports).
"""

import colorsys

from opsec_scanner.output.report_theme import TOKENS, STAMP_COLORS


def _relative_luminance(hex_color: str) -> float:
    hex_color = hex_color.lstrip("#")
    r, g, b = int(hex_color[0:2], 16) / 255, int(hex_color[2:4], 16) / 255, int(hex_color[4:6], 16) / 255

    def adj(c):
        return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4

    r, g, b = adj(r), adj(g), adj(b)
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def _contrast_ratio(c1: str, c2: str) -> float:
    l1, l2 = _relative_luminance(c1), _relative_luminance(c2)
    lighter, darker = max(l1, l2), min(l1, l2)
    return (lighter + 0.05) / (darker + 0.05)


WCAG_AA_NORMAL_TEXT = 4.5


def test_text_tokens_meet_wcag_aa_against_ink_background():
    bg = TOKENS["ink"]
    for token_name in ("text", "muted", "muted_dim"):
        ratio = _contrast_ratio(TOKENS[token_name], bg)
        assert ratio >= WCAG_AA_NORMAL_TEXT, (
            f"--{token_name} ({TOKENS[token_name]}) on --ink ({bg}) is {ratio:.2f}:1, "
            f"below WCAG AA's {WCAG_AA_NORMAL_TEXT}:1 minimum for normal-size text"
        )


def test_all_stamp_colors_meet_wcag_aa_against_ink_background():
    # Stamp text is small (10px bold) and does not qualify for WCAG's
    # "large text" 3:1 exception (which requires ~18.7px bold or larger),
    # so every risk-label color needs the full 4.5:1.
    bg = TOKENS["ink"]
    for label, color in STAMP_COLORS.items():
        ratio = _contrast_ratio(color, bg)
        assert ratio >= WCAG_AA_NORMAL_TEXT, (
            f"{label} stamp color ({color}) on --ink ({bg}) is {ratio:.2f}:1, "
            f"below WCAG AA's {WCAG_AA_NORMAL_TEXT}:1 minimum"
        )


def test_no_hardcoded_critical_color_outside_the_shared_token():
    # Regression test for the actual bug pattern found three times in
    # one session: the same color existing as an independent hardcoded
    # hex string in multiple files instead of one shared token. If a
    # future edit changes STAMP_COLORS["CRITICAL"] without this test,
    # a hardcoded copy elsewhere would silently go stale and mismatch.
    import inspect
    from opsec_scanner.output import dashboard, ops_center

    old_critical_red = "#c0433f"  # the pre-fix value; must never reappear anywhere
    for module in (dashboard, ops_center):
        source = inspect.getsource(module)
        assert old_critical_red not in source, f"{module.__name__} still has a hardcoded reference to the old, low-contrast CRITICAL color"
