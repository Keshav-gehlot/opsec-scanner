"""pre-commit hook entry point (opsec_scanner/hook.py)."""

import subprocess

from opsec_scanner import hook


def _repo(tmp_path):
    def git(*a):
        return subprocess.run(["git", *a], cwd=tmp_path, check=True, capture_output=True, text=True).stdout.strip()
    git("init", "-q")
    git("config", "user.email", "t@example.com")
    git("config", "user.name", "T")
    (tmp_path / "a").write_text("x")
    git("add", ".")
    git("commit", "-q", "-m", "one")
    return git("rev-parse", "HEAD")


def test_since_ref_uses_pushed_range_and_ignores_new_branch_zeros(tmp_path, monkeypatch):
    sha = _repo(tmp_path)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PRE_COMMIT_FROM_REF", sha)
    assert hook.since_ref() == sha
    monkeypatch.setenv("PRE_COMMIT_FROM_REF", "0" * 40)  # new branch: nothing to diff against
    assert hook.since_ref() is None
    monkeypatch.setenv("PRE_COMMIT_FROM_REF", "deadbeef")  # unknown ref
    assert hook.since_ref() is None


def test_report_goes_inside_git_dir_not_the_working_tree(tmp_path, monkeypatch):
    _repo(tmp_path)
    monkeypatch.chdir(tmp_path)
    path = hook.report_path()
    assert path.replace("\\", "/").startswith(".git/opsec-scan/")
    status = subprocess.run(["git", "status", "--porcelain"], cwd=tmp_path, capture_output=True, text=True).stdout
    assert status == ""


def test_bundled_rules_load_from_the_package():
    from opsec_scanner.analysis.patterns import DEFAULT_RULES_PATH, load_rules
    assert DEFAULT_RULES_PATH.parent.parent.name == "opsec_scanner"
    assert len(load_rules()) > 20
