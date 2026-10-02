"""
Error-state regression tests.

Found by manually exercising realistic user mistakes (typo'd paths,
hand-edited config files) rather than just reading the code — every
case here previously either dumped a raw Python traceback at the user
or, worse, silently produced a misleading "clean" report. A security
tool that fails silently on a broken input is more dangerous than one
that fails loudly, since a silent failure looks identical to "nothing
was found."
"""

import subprocess
import sys
import textwrap

import pytest
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent


def _run_cli(args):
    return subprocess.run(
        [sys.executable, "-m", "opsec_scanner.main"] + args,
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=30,
    )


def _make_profile(tmp_path):
    profile = tmp_path / "profile.yaml"
    profile.write_text("name: Test\naliases: []\nemails: []\ndomains: []\ngithub_handles: []\n")
    return profile


def test_nonexistent_repo_path_fails_cleanly_no_traceback(tmp_path):
    profile = _make_profile(tmp_path)
    result = _run_cli([
        "--repo", str(tmp_path / "does-not-exist"), "--profile", str(profile),
        "--output", str(tmp_path / "r.html"), "--no-progress",
    ])
    assert result.returncode == 1
    assert "Traceback" not in result.stdout
    assert "Traceback" not in result.stderr
    assert "does not exist" in result.stdout


def test_non_git_directory_fails_cleanly_no_traceback(tmp_path):
    not_a_repo = tmp_path / "not_a_repo"
    not_a_repo.mkdir()
    (not_a_repo / "file.txt").write_text("hello")
    profile = _make_profile(tmp_path)

    result = _run_cli([
        "--repo", str(not_a_repo), "--profile", str(profile),
        "--output", str(tmp_path / "r.html"), "--no-progress",
    ])
    assert result.returncode == 1
    assert "Traceback" not in result.stdout
    assert "Traceback" not in result.stderr


def test_nonexistent_media_dir_fails_loudly_not_silent_clean(tmp_path):
    # Regression test for the worst bug in this batch: a typo'd
    # --media-dir path previously produced a "0 findings, clean report"
    # result with zero indication anything was wrong — a false negative
    # a self-audit tool must never produce silently.
    profile = _make_profile(tmp_path)
    result = _run_cli([
        "--media-dir", str(tmp_path / "does-not-exist-media"), "--profile", str(profile),
        "--output", str(tmp_path / "r.html"), "--no-progress",
    ])
    assert result.returncode == 1
    assert "does not exist" in result.stdout
    assert not (tmp_path / "r.html").exists()  # no misleading report should be written


def test_media_dir_pointing_to_a_file_fails_cleanly(tmp_path):
    profile = _make_profile(tmp_path)
    a_file = tmp_path / "im_a_file.txt"
    a_file.write_text("not a directory")

    result = _run_cli([
        "--media-dir", str(a_file), "--profile", str(profile),
        "--output", str(tmp_path / "r.html"), "--no-progress",
    ])
    assert result.returncode == 1
    assert "not a directory" in result.stdout


def test_corrupt_profile_yaml_fails_cleanly_no_traceback(tmp_path):
    corrupt = tmp_path / "corrupt_profile.yaml"
    corrupt.write_text("not: valid: yaml: [[[")

    result = _run_cli([
        "--repo", str(tmp_path), "--profile", str(corrupt),
        "--output", str(tmp_path / "r.html"), "--no-progress",
    ])
    assert result.returncode == 1
    assert "Traceback" not in result.stdout
    assert "Traceback" not in result.stderr
    assert "not valid YAML" in result.stdout or "not valid YAML" in result.stderr


def test_corrupt_config_yaml_fails_cleanly_no_traceback(tmp_path):
    profile = _make_profile(tmp_path)
    corrupt_config = tmp_path / "opsec-scan.yaml"
    corrupt_config.write_text("not: valid: [[[")

    result = _run_cli([
        "--repo", str(tmp_path), "--profile", str(profile),
        "--config", str(corrupt_config),
        "--output", str(tmp_path / "r.html"), "--no-progress",
    ])
    assert result.returncode == 1
    assert "Traceback" not in result.stdout
    assert "Traceback" not in result.stderr


def test_negative_scan_bounds_are_rejected():
    from opsec_scanner.main import build_arg_parser

    parser = build_arg_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["--max-patch-commits", "-1"])
    with pytest.raises(SystemExit):
        parser.parse_args(["--entropy-threshold", "-0.1"])
    with pytest.raises(SystemExit):
        parser.parse_args(["--entropy-threshold", "nan"])
