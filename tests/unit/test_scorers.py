"""Metric scorers are pure functions in the independent ``metrics`` package."""
from metrics.scorers import exact_match, presence, set_f1, token_f1


def test_exact_match_normalize():
    assert exact_match.normalize("  Hello   World ") == "hello world"
    assert exact_match.normalize(None) == ""


def test_exact_match_score_case_insensitive():
    assert exact_match.score("High", "high") == 1.0
    assert exact_match.score("a", "b") == 0.0


def test_token_f1_identical_is_one():
    assert token_f1.score("foo bar baz", "foo bar baz") == 1.0


def test_token_f1_disjoint_is_zero():
    assert token_f1.score("foo", "bar") == 0.0


def test_set_f1_extract_cve_ids():
    cves = set_f1.extract_cve_ids("affected by CVE-2021-1234 and CVE-2020-99999")
    assert "CVE-2021-1234" in cves
    assert "CVE-2020-99999" in cves


def test_presence_is_populated():
    assert presence.is_populated("something") is True
    assert presence.is_populated("") is False
    assert presence.is_populated(None) is False
