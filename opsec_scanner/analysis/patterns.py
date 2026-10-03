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

def _rules_dir() -> Path:
    """The repo-level rules/ directory. Found next to the package for a
    source checkout or editable install; a regular (non-editable) install
    copies only the package into site-packages, so fall back to ./rules in
    the working directory (how hosted deployments run from the checkout)."""
    beside_package = Path(__file__).parent.parent.parent / "rules"
    if (beside_package / "patterns.yaml").exists():
        return beside_package
    in_cwd = Path.cwd() / "rules"
    if (in_cwd / "patterns.yaml").exists():
        return in_cwd
    return beside_package


DEFAULT_RULES_PATH = _rules_dir() / "patterns.yaml"
DEFAULT_ALLOWLIST_PATH = _rules_dir() / "allowlist.yaml"


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
    validator: str | None = None        # name in VALIDATORS; match dropped if it fails
    mitre: str | None = None            # MITRE ATT&CK technique id, e.g. T1552.001


@dataclass
class ScannedMatch:
    finding: RawFinding
    rule_id: str
    category: str
    base_severity: float
    matched_text: str
    entropy_score: float | None = None  # populated only if the rule required an entropy check


# ---------------------------------------------------------------------------
# Validators: structural checks that cut false positives for number-shaped
# data (card numbers, national IDs) where a regex alone is far too loose.
# ---------------------------------------------------------------------------

def _digits(text: str) -> str:
    return "".join(ch for ch in text if ch.isdigit())


def luhn_valid(text: str) -> bool:
    digits = _digits(text)
    if not 13 <= len(digits) <= 19 or len(set(digits)) == 1:
        return False
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


_VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5], [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7], [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3], [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]
_VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4], [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7], [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]


def aadhaar_valid(text: str) -> bool:
    """Aadhaar: 12 digits, first digit 2-9, Verhoeff checksum."""
    digits = _digits(text)
    if len(digits) != 12 or digits[0] in "01" or len(set(digits)) == 1:
        return False
    c = 0
    for i, ch in enumerate(reversed(digits)):
        c = _VERHOEFF_D[c][_VERHOEFF_P[i % 8][int(ch)]]
    return c == 0


def iban_valid(text: str) -> bool:
    value = "".join(text.split()).upper()
    if not 15 <= len(value) <= 34 or not value[:2].isalpha() or not value[2:4].isdigit():
        return False
    rearranged = value[4:] + value[:4]
    try:
        number = "".join(str(int(ch, 36)) for ch in rearranged)
    except ValueError:
        return False
    return int(number) % 97 == 1


def ssn_valid(text: str) -> bool:
    digits = _digits(text)
    if len(digits) != 9:
        return False
    area, group, serial = digits[:3], digits[3:5], digits[5:]
    return area not in ("000", "666") and not area.startswith("9") and group != "00" and serial != "0000"


VALIDATORS = {"luhn": luhn_valid, "aadhaar": aadhaar_valid, "iban": iban_valid, "ssn": ssn_valid}


def _validator_name(name):
    if name is None:
        return None
    if name not in VALIDATORS:
        raise KeyError(f"unknown validator '{name}'")
    return name


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
                    validator=_validator_name(r.get("validator")),
                    mitre=r.get("mitre"),
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
            if rule.validator and not VALIDATORS[rule.validator](matched_text):
                # Try the remaining matches in this text before giving up:
                # the first number-shaped hit is often not the real one.
                matched_text = next(
                    (other.group(0) for other in rule.pattern.finditer(text, m.end())
                     if VALIDATORS[rule.validator](other.group(0))),
                    None,
                )
                if matched_text is None:
                    continue

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
