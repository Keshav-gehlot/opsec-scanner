"""Entry point for the pre-commit framework (see .pre-commit-hooks.yaml).

pre-commit runs hooks without a shell, so environment variables cannot be
expanded in `entry`. On pre-push it exposes the range being pushed as
PRE_COMMIT_FROM_REF / PRE_COMMIT_TO_REF; scan only those commits. On any
other stage (or a new branch, where FROM_REF is all zeros) fall back to the
upstream branch if one exists, else full history.
"""

from __future__ import annotations

import os
import subprocess
import sys

# Pushed commits are about to leave the machine, so score them as exposed
# (--public-repo). Without a matching identity profile a real AWS key or
# private key scores MEDIUM, so MEDIUM is the lowest threshold that reliably
# blocks credentials; raise it with `args: [--fail-on, HIGH]` if too noisy.
DEFAULT_ARGS = ["--repo", ".", "--no-progress", "--public-repo", "--fail-on", "MEDIUM"]


def _ref_exists(ref: str) -> bool:
    return subprocess.run(["git", "rev-parse", "--verify", "--quiet", ref + "^{commit}"],
                          capture_output=True).returncode == 0


def since_ref() -> str | None:
    from_ref = os.environ.get("PRE_COMMIT_FROM_REF", "").strip()
    if from_ref and set(from_ref) != {"0"} and _ref_exists(from_ref):
        return from_ref
    upstream = subprocess.run(["git", "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{upstream}"],
                              capture_output=True, text=True)
    if upstream.returncode == 0 and upstream.stdout.strip():
        return upstream.stdout.strip()
    return None


def report_path() -> str:
    """Inside .git/, so the hook never modifies the working tree (pre-commit
    marks a hook that changes files as failed)."""
    git_dir = subprocess.run(["git", "rev-parse", "--git-dir"], capture_output=True, text=True).stdout.strip() or ".git"
    out = os.path.join(git_dir, "opsec-scan")
    os.makedirs(out, exist_ok=True)
    return os.path.join(out, "pre-push-report.html")


def main(argv: list[str] | None = None) -> None:
    from opsec_scanner.main import cli

    args = list(DEFAULT_ARGS) + ["--output", report_path()]
    ref = since_ref()
    if ref:
        args += ["--since-ref", ref]
    # Arguments from the user's .pre-commit-config.yaml `args:` win.
    sys.argv = ["opsec-scan"] + args + list(argv if argv is not None else sys.argv[1:])
    cli()


if __name__ == "__main__":
    main()
