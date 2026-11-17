"""Name detection pass (opsec_scanner/analysis/ner.py)."""

import pytest

from opsec_scanner.analysis import ner
from opsec_scanner.config import TargetProfile
from opsec_scanner.models import RawFinding, SourceType

PROFILE = TargetProfile(name="Keshav Gehlot", aliases=["kg0998"], emails=[], domains=[])


def _doc(text, origin="report.pdf"):
    return RawFinding(source_type=SourceType.MEDIA_DOC, raw_text=text, origin=origin)


@pytest.fixture
def name_match_only(monkeypatch):
    monkeypatch.setenv("OPSEC_NER", "off")
    ner._nlp.cache_clear()
    yield
    ner._nlp.cache_clear()


def _spacy_ready():
    ner._nlp.cache_clear()
    return ner._nlp() is not None


def test_fallback_finds_profile_name_case_insensitively(name_match_only):
    assert ner.ner_backend() == "name-match"
    out = ner.ner_matches([_doc("Prepared by KESHAV   gehlot for the board"), _doc("nothing here")], PROFILE)
    assert [(m.rule_id, m.matched_text) for m in out] == [("real_name_exposure", "KESHAV   gehlot")]


def test_commit_author_name_is_flagged_without_ner(name_match_only):
    raw = RawFinding(source_type=SourceType.GIT_COMMIT_META, raw_text="Keshav Gehlot", origin="repo",
                     context="abc123 (author name)", metadata={"role": "author"})
    other = RawFinding(source_type=SourceType.GIT_COMMIT_META, raw_text="Someone Else", origin="repo",
                       metadata={"role": "author"})
    out = ner.ner_matches([raw, raw, other], PROFILE)
    assert [m.rule_id for m in out] == ["real_name_exposure"]  # deduplicated per repo


def test_no_profile_name_means_no_real_name_findings(name_match_only):
    assert ner.ner_matches([_doc("Keshav Gehlot")], TargetProfile(name="unknown")) == []


@pytest.mark.skipif(not _spacy_ready(), reason="spaCy model en_core_web_sm not installed")
def test_spacy_finds_own_and_third_party_names():
    ner._nlp.cache_clear()
    out = ner.ner_matches([_doc("Prepared by Keshav Gehlot and reviewed by Priya Sharma at Acme Labs in Chennai.")], PROFILE)
    found = {(m.rule_id, m.matched_text) for m in out}
    assert ("real_name_exposure", "Keshav Gehlot") in found
    assert ("third_party_name_exposure", "Priya Sharma") in found
    assert all(m.finding.metadata["ner"] == "spacy" for m in out)


def test_ner_findings_have_remediation():
    from opsec_scanner.analysis.patterns import remediation_for

    assert remediation_for("real_name_exposure", "identity").startswith("Remove or generalise")


def test_initial_and_reversed_forms_count_as_the_profile_name():
    names = ner._profile_names(PROFILE)
    assert ner._matches_profile("K. Gehlot", names) and ner._matches_profile("Gehlot, Keshav", names)
    assert not ner._matches_profile("R. Gehlot", names) and not ner._matches_profile("Keshav Sharma", names)
