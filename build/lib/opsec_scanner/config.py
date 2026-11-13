"""
Target identity profile loader.

The identity profile is the anchor the whole pipeline correlates against.
Every finding gets scored higher or lower depending on how strongly it
matches (or fails to match) this profile — this is what keeps a generic
fork of some unrelated repo from lighting up as a critical finding.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass
class TargetProfile:
    name: str
    aliases: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    github_handles: list[str] = field(default_factory=list)
    home_coordinates: tuple[float, float] | None = None  # (lat, lon), optional, for GPS proximity scoring

    def all_identity_strings(self) -> set[str]:
        """Flat set of every string that should be treated as 'this is me' for matching."""
        out = {self.name.lower()}
        out.update(a.lower() for a in self.aliases)
        out.update(e.lower() for e in self.emails)
        out.update(d.lower() for d in self.domains)
        out.update(h.lower() for h in self.github_handles)
        return out


DEFAULT_PROFILE_PATH = Path("target_profile.yaml")


def load_target_profile(path: Path | str | None = None) -> TargetProfile:
    p = Path(path) if path else DEFAULT_PROFILE_PATH
    if not p.exists():
        print(
            f"[config] No target profile found at '{p}'. "
            f"Run with --init-profile to create a template, or pass --profile <path>.",
            file=sys.stderr,
        )
        sys.exit(1)

    with open(p, "r", encoding="utf-8") as f:
        try:
            raw = yaml.safe_load(f) or {}
        except yaml.YAMLError as e:
            print(
                f"[config] '{p}' is not valid YAML: {e}\n"
                f"[config] Fix the file, or run --init-profile to regenerate a clean template.",
                file=sys.stderr,
            )
            sys.exit(1)

    if not isinstance(raw, dict):
        print(f"[config] '{p}' must contain a YAML mapping/object.", file=sys.stderr)
        sys.exit(1)

    def _string_list(key: str) -> list[str]:
        value = raw.get(key, [])
        if value is None:
            return []
        if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
            print(f"[config] '{p}' field '{key}' must be a list of strings.", file=sys.stderr)
            sys.exit(1)
        return value

    name = raw.get("name", "")
    if not isinstance(name, str) or not name.strip():
        print(f"[config] '{p}' field 'name' must be a non-empty string.", file=sys.stderr)
        sys.exit(1)

    coords = raw.get("home_coordinates")
    if coords is None:
        home_coordinates = None
    elif (
        isinstance(coords, (list, tuple))
        and len(coords) == 2
        and all(isinstance(value, (int, float)) and not isinstance(value, bool) for value in coords)
        and -90 <= float(coords[0]) <= 90
        and -180 <= float(coords[1]) <= 180
    ):
        home_coordinates = (float(coords[0]), float(coords[1]))
    else:
        print(f"[config] '{p}' field 'home_coordinates' must be [latitude, longitude] within valid ranges.", file=sys.stderr)
        sys.exit(1)

    return TargetProfile(
        name=name.strip(),
        aliases=_string_list("aliases"),
        emails=_string_list("emails"),
        domains=_string_list("domains"),
        github_handles=_string_list("github_handles"),
        home_coordinates=home_coordinates,
    )


def write_template_profile(path: Path | str = DEFAULT_PROFILE_PATH) -> None:
    template = {
        "name": "Your Name",
        "aliases": ["handle1", "handle2"],
        "emails": ["you@example.com", "you@work.com"],
        "domains": ["yourcompany.internal", "yourcompany.local"],
        "github_handles": ["your-github-username"],
        "home_coordinates": None,  # e.g. [37.7749, -122.4194] — optional, enables GPS proximity scoring
    }
    p = Path(path)
    with open(p, "w", encoding="utf-8") as f:
        yaml.safe_dump(template, f, sort_keys=False)
    print(f"[config] Template profile written to '{p}'. Edit it, then re-run the scan.")
