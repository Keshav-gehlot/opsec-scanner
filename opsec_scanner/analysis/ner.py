"""
Named-entity pass over extracted free text (documents, OCR, web pages,
search snippets, commit messages).

  real_name_exposure         the target's own name (profile name or a
                             multi-word alias) appears in the text.
  third_party_name_exposure  another person's full name appears in document
                             or web text (colleagues, clients, signatories).
                             Only with spaCy, since that needs real NER;
                             capped per scan because it is noisy by nature.

With spaCy and an English model (pip install '.[nlp]' and
python -m spacy download en_core_web_sm), PERSON entities are used, so
"Prepared by K. Gehlot" style variants and other people's names are found.
Without it, the profile name is matched exactly (case-insensitive, word
boundaries). Emails and phone numbers are already covered by the regex
rules, so they are not duplicated here.
"""

from __future__ import annotations

import functools
import os
import re

from opsec_scanner.analysis.patterns import ScannedMatch
from opsec_scanner.models import RawFinding, SourceType

NER_RULES = {
    # id: (category, base_severity, mitre, description)
    "real_name_exposure": ("identity", 4.0, "T1589.003", "Your real name appears in published text"),
    "third_party_name_exposure": ("personal", 2.0, "T1589.003", "Another person's full name appears in a published document"),
}
NER_REMEDIATION = {
    "real_name_exposure": "Remove or generalise your name where it is not needed (document author fields, footers, "
                          "commit messages), or accept it consciously if this identity is meant to be public.",
    "third_party_name_exposure": "Check whether that person agreed to be named; redact names from published documents "
                                 "and strip author/creator metadata before sharing.",
}
TEXT_SOURCES = {SourceType.MEDIA_DOC, SourceType.MEDIA_EXIF, SourceType.WEB_CONTENT, SourceType.SEARCH_RESULT,
                SourceType.CODE_SEARCH, SourceType.GIT_COMMIT_META, SourceType.GIT_PATCH}
THIRD_PARTY_SOURCES = {SourceType.MEDIA_DOC, SourceType.WEB_CONTENT}
MAX_THIRD_PARTY = 20
MAX_TEXT = 5000


@functools.lru_cache(maxsize=1)
def _nlp():
    if os.environ.get("OPSEC_NER", "").strip().lower() in ("0", "false", "off"):
        return None
    try:
        import spacy

        return spacy.load(os.environ.get("OPSEC_NER_MODEL", "en_core_web_sm"), disable=["lemmatizer", "parser"])
    except Exception:
        return None


def ner_backend() -> str:
    return "spacy" if _nlp() is not None else "name-match"


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip().casefold()


def _profile_names(profile) -> list[str]:
    names = [getattr(profile, "name", "") or ""] + list(getattr(profile, "aliases", []) or [])
    return [n for n in {_norm(n) for n in names} if len(n.split()) >= 2]


def _matches_profile(person: str, names: list[str]) -> bool:
    p = _norm(person)
    if p in names:
        return True
    # "K. Gehlot" / "Gehlot, Keshav": same surname and a matching first initial.
    tokens = [t.strip(".,") for t in re.split(r"[\s,]+", p) if t.strip(".,")]
    for name in names:
        first, *_, last = name.split()
        if last in tokens and any(t == first or (len(t) == 1 and t == first[0]) for t in tokens if t != last):
            return True
    return False


def _match(raw: RawFinding, rule: str, text: str) -> ScannedMatch:
    category, severity, _, _ = NER_RULES[rule]
    found = RawFinding(source_type=raw.source_type, raw_text=text, context=raw.context, origin=raw.origin,
                       metadata={**(raw.metadata or {}), "ner": ner_backend()})
    return ScannedMatch(finding=found, rule_id=rule, category=category, base_severity=severity, matched_text=text)


def ner_matches(raw_findings: list[RawFinding], profile) -> list[ScannedMatch]:
    names = _profile_names(profile)
    nlp = _nlp()
    out: list[ScannedMatch] = []
    seen: set[tuple[str, str, str]] = set()
    third_party = 0
    patterns = [re.compile(r"\b" + re.escape(n).replace(r"\ ", r"\s+") + r"\b", re.I) for n in names]

    for raw in raw_findings:
        if raw.source_type not in TEXT_SOURCES:
            continue
        if raw.source_type == SourceType.GIT_COMMIT_META:
            # Commit author/committer names: compare directly (no sentence context for NER).
            if (raw.metadata or {}).get("role") and "@" not in raw.raw_text and names and _matches_profile(raw.raw_text, names):
                key = ("real_name_exposure", _norm(raw.raw_text), raw.origin)
                if key not in seen:
                    seen.add(key)
                    out.append(_match(raw, "real_name_exposure", raw.raw_text))
            continue
        text = f"{raw.raw_text}\n{raw.context}"[:MAX_TEXT]
        if nlp is not None:
            people = {ent.text.strip() for ent in nlp(text).ents if ent.label_ == "PERSON" and len(ent.text.split()) >= 2}
            for person in people:
                if names and _matches_profile(person, names):
                    rule = "real_name_exposure"
                elif raw.source_type in THIRD_PARTY_SOURCES and third_party < MAX_THIRD_PARTY:
                    rule = "third_party_name_exposure"
                    third_party += 1
                else:
                    continue
                key = (rule, _norm(person), raw.origin)
                if key not in seen:
                    seen.add(key)
                    out.append(_match(raw, rule, person))
        else:
            for pattern in patterns:
                hit = pattern.search(text)
                if hit:
                    key = ("real_name_exposure", _norm(hit.group(0)), raw.origin)
                    if key not in seen:
                        seen.add(key)
                        out.append(_match(raw, "real_name_exposure", hit.group(0)))
    return out
