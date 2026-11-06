"""Tests for domain_grammar.py, driven by domain_grammar_fixtures.txt."""
import pathlib
import sys

import pytest

THIS_DIR = pathlib.Path(__file__).parent
sys.path.insert(0, str(THIS_DIR))
import domain_grammar as g  # noqa: E402


def _fixtures():
    out = []
    for ln in (THIS_DIR / "domain_grammar_fixtures.txt").read_text().splitlines():
        if not ln.strip() or ln.startswith("#"):
            continue
        verdict, pattern = ln.split(" ", 1)
        out.append((verdict, pattern))
    return out


@pytest.mark.parametrize("verdict,pattern", _fixtures())
def test_fixture(verdict, pattern):
    assert g.is_restricted_pattern(pattern) is (verdict == "ACCEPT")


def test_fixture_file_has_both_verdicts():
    assert {v for v, _ in _fixtures()} == {"ACCEPT", "REJECT"}


def test_overlong_pattern_is_rejected():
    assert not g.is_restricted_pattern("a" * 150 + "b" * 51)


def test_non_string_is_rejected():
    assert not g.is_restricted_pattern(None)


def test_matches_host_suffix_is_label_bounded():
    assert g.matches_host("suffix", "google.com", "www.google.com")
    assert g.matches_host("suffix", "google.com", "google.com")
    assert not g.matches_host("suffix", "google.com", "notgoogle.com")


def test_matches_host_label():
    assert g.matches_host("label", "google", "www.google.com")
    assert not g.matches_host("label", "goog", "www.google.com")


def test_matches_host_pattern_full_or_label_bounded_suffix():
    assert g.matches_host("pattern", r"mt[0-9]*\.google\.cn", "mt1.google.cn")
    assert g.matches_host("pattern", r"mt[0-9]*\.google\.cn", "x.mt1.google.cn")
    assert not g.matches_host("pattern", r"mt[0-9]*\.google\.cn", "xmt1.google.cn")


def test_matches_host_invalid_pattern_never_matches():
    assert not g.matches_host("pattern", "(a+)+$", "aaaa.com")


def test_field_checks():
    c = g.FIELD_CHECKS
    assert c["prefix"]("com.flurry") and not c["prefix"]("com.foo-bar.sdk")
    assert c["segment"]("sizmek") and not c["segment"]("LigatusManager")
    assert c["suffix"]("app-measurement.com") and not c["suffix"]("fidzup")
    assert c["label"]("fidzup") and not c["label"]("ad.server")
    assert c["pattern"](r"mt[0-9]*\.google\.cn") and not c["pattern"]("(a+)+$")


def test_first_party_hosts_file_loads():
    hosts = g.load_first_party_hosts()
    assert "www.google.com" in hosts and "www.hicloud.com" in hosts and len(hosts) == 12
