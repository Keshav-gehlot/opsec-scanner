"""
Regex pattern engine.

Loads the rule set from rules/patterns.yaml and scans RawFinding.raw_text
against every rule. Rules flagged requires_entropy_check get a second
pass through entropy.py before being accepted — this is what stops
"password=hunter2"-style low-entropy placeholders from scoring as
critical alongside actual random secrets.

Output here is a ScannedMatch: a RawFinding plus which rule(s) it hit,
still unscored by risk/identity — that happens in scoring/risk_engine.py.
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from opsec_scanner.analysis.entropy import calculate_entropy, is_high_entropy
from opsec_scanner.models import RawFinding

DEFAULT_RULES_PATH = Path(__file__).parent.parent.parent / "rules" / "patterns.yaml"
DEFAULT_ALLOWLIST_PATH = Path(__file__).parent.parent.parent / "rules" / "allowlist.yaml"


@dataclass
class Allowlist:
    ignore_patterns: list[str] = field(default_factory=list)
    ignore_paths: list[str] = field(default_factory=list)

    def is_ignored(self, matched_text: str, origin: str) -> bool:
        if any(p in origin for p in self.ignore_paths):
            return True
        if any(p == matched_text or p in matched_text for p in self.ignore_patterns):
            return True
        return False


def load_allowlist(path: Path | str | None = None) -> Allowlist:
    p = Path(path) if path else DEFAULT_ALLOWLIST_PATH
    if not p.exists():
        return Allowlist()
    with open(p, "r", encoding="utf-8") as f:
        try:
            raw = yaml.safe_load(f) or {}
        except yaml.YAMLError as e:
            print(f"[patterns] '{p}' is not valid YAML: {e}. Proceeding with an empty allowlist.", file=sys.stderr)
            return Allowlist()
    return Allowlist(
        ignore_patterns=raw.get("ignore_patterns", []),
        ignore_paths=raw.get("ignore_paths", []),
    )


@dataclass
class Rule:
    id: str
    category: str
    pattern: re.Pattern
    base_severity: float
    requires_entropy_check: bool
    description: str


@dataclass
class ScannedMatch:
    finding: RawFinding
    rule_id: str
    category: str
    base_severity: float
    matched_text: str
    entropy_score: float | None = None  # populated only if the rule required an entropy check


def load_rules(path: Path | str | None = None) -> list[Rule]:
    p = Path(path) if path else DEFAULT_RULES_PATH
    with open(p, "r", encoding="utf-8") as f:
        try:
            raw = yaml.safe_load(f)
        except yaml.YAMLError as e:
            # Unlike the allowlist, the rule set is core detection —
            # silently falling back here would mean scanning with zero
            # rules and reporting a false "all clean," which is worse
            # than crashing. Fail loudly instead.
            print(f"[patterns] '{p}' is not valid YAML: {e}", file=sys.stderr)
            sys.exit(1)

    rules = []
    for r in (raw or {}).get("rules", []):
        rule_id = r.get("id", "<unnamed rule>")
        try:
            rules.append(
                Rule(
                    id=r["id"],
                    category=r["category"],
                    pattern=re.compile(r["regex"]),
                    base_severity=float(r["base_severity"]),
                    requires_entropy_check=bool(r.get("requires_entropy_check", False)),
                    description=r.get("description", ""),
                )
            )
        except (re.error, KeyError, ValueError) as e:
            # A single malformed custom rule (typo'd regex, missing field)
            # shouldn't take down detection for every other rule — warn
            # and skip it instead of crashing the whole scan.
            print(f"[patterns] Skipping malformed rule '{rule_id}' in '{p}': {e}", file=sys.stderr)

    if not rules:
        print(f"[patterns] WARNING: zero valid rules loaded from '{p}' — a scan run now would report false 'clean' results.", file=sys.stderr)

    return rules


def scan_findings(
    findings: list[RawFinding],
    rules: list[Rule] | None = None,
    entropy_threshold: float = 3.5,
    allowlist: Allowlist | None = None,
) -> list[ScannedMatch]:
    """
    Runs every rule against every finding's raw_text. A single finding
    can produce multiple ScannedMatch objects if it trips more than one
    rule (e.g. a connection string that also contains a personal path).

    Findings matching the allowlist (known vendor placeholders, excluded
    paths like vendored deps/test fixtures) are suppressed before scoring.
    """
    if rules is None:
        rules = load_rules()
    if allowlist is None:
        allowlist = load_allowlist()

    matches: list[ScannedMatch] = []

    for finding in findings:
        if any(p in finding.origin for p in allowlist.ignore_paths):
            continue

        text = finding.raw_text
        for rule in rules:
            m = rule.pattern.search(text)
            if not m:
                continue

            matched_text = m.group(0)

            if allowlist.is_ignored(matched_text, finding.origin):
                continue

            # If the rule defines a capture group, entropy checks should run
            # against just that group (e.g. the secret value, not the
            # "password=" prefix) — otherwise the prefix dilutes the score.
            entropy_subject = m.group(1) if rule.requires_entropy_check and m.lastindex else matched_text

            entropy_score = None
            if rule.requires_entropy_check:
                entropy_score = calculate_entropy(entropy_subject)
                if not is_high_entropy(entropy_subject, threshold=entropy_threshold):
                    # Low entropy on a "generic key=value" style rule usually
                    # means a placeholder/test value — downgrade by skipping,
                    # rather than dropping the finding, we simply don't emit
                    # a match at full severity here.
                    continue

            matches.append(
                ScannedMatch(
                    finding=finding,
                    rule_id=rule.id,
                    category=rule.category,
                    base_severity=rule.base_severity,
                    matched_text=matched_text,
                    entropy_score=entropy_score,
                )
            )

    return matches
