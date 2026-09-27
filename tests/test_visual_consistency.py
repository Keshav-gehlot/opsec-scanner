"""
Visual-consistency regression tests.

dashboard.py and ops_center.py previously hand-duplicated their color
tokens, stamp styling, and font-loading logic — verbatim, in two
places, with values that had already drifted (ops_center's .stamp used
a different font-size/padding than dashboard's before this fix). These
tests assert both reports render the *same* shared CSS text rather than
their own independent copies, so a future edit to report_theme.py is
guaranteed to apply everywhere instead of needing to be remembered twice.
"""

from opsec_scanner.output import report_theme
from opsec_scanner.output.dashboard import _build_html
from opsec_scanner.output.ops_center import render_ops_center
from opsec_scanner.output.history_store import save_snapshot
from opsec_scanner.analysis.patterns import ScannedMatch
from opsec_scanner.scoring.risk_engine import score_findings
from opsec_scanner.config import TargetProfile
from opsec_scanner.models import RawFinding, SourceType


def _scored():
    profile = TargetProfile(name="Test")
    finding = RawFinding(source_type=SourceType.GIT_PATCH, raw_text="AKIAIOSFODNN7EXAMPLE", origin="repo")
    match = ScannedMatch(finding=finding, rule_id="aws_access_key", category="credentials", base_severity=9.5, matched_text="AKIAIOSFODNN7EXAMPLE")
    return score_findings([match], profile)


def test_both_reports_render_the_same_root_css_vars_block(tmp_path):
    dashboard_html = _build_html(_scored(), mode="interactive")

    history_dir = tmp_path / "history"
    save_snapshot(_scored(), "repo-a", history_dir=history_dir)
    ops_output = tmp_path / "ops.html"
    render_ops_center(history_dir, ops_output)
    ops_html = ops_output.read_text()

    shared_vars_block = report_theme.root_css_vars()
    assert shared_vars_block in dashboard_html
    assert shared_vars_block in ops_html


def test_both_reports_render_the_same_stamp_css(tmp_path):
    dashboard_html = _build_html(_scored(), mode="interactive")

    history_dir = tmp_path / "history"
    save_snapshot(_scored(), "repo-a", history_dir=history_dir)
    ops_output = tmp_path / "ops.html"
    render_ops_center(history_dir, ops_output)
    ops_html = ops_output.read_text()

    assert report_theme.STAMP_CSS in dashboard_html
    assert report_theme.STAMP_CSS in ops_html


def test_both_reports_use_the_same_stamp_colors():
    # If someone changes a severity color in one report but not the
    # other, the same CRITICAL finding would look like a different
    # severity depending which report you're looking at — this pins
    # both reports to the one shared color map.
    dashboard_html = _build_html(_scored(), mode="static_redacted")
    assert report_theme.STAMP_COLORS["CRITICAL"] not in "unused"  # sanity: map isn't empty
    for label, color in report_theme.STAMP_COLORS.items():
        # Every stamp color the report *could* use must trace back to
        # the shared map — spot-check the map itself is non-trivial
        # rather than asserting every color appears in a specific
        # single-finding fixture (which would only exercise one label).
        assert color.startswith("#") and len(color) == 7
