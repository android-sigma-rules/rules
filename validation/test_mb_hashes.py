"""Tests for mb_hashes.py: which hashes does fetch-feed-dumps.sh send to MalwareBazaar?"""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent))
import mb_hashes  # noqa: E402

H1, H2, H3 = "a" * 64, "b" * 64, "c" * 64


def entry(ind, source="malwarebazaar"):
    return f"  - indicator: {ind}\n    family: X\n    source: {source}\n"


def repo(tmp_path, body):
    d = tmp_path / "repo" / "ioc-data"
    d.mkdir(parents=True)
    (d / "malware-hashes.yml").write_text("entries:\n" + body)
    return tmp_path / "repo"


def cands(tmp_path):
    d = tmp_path / "cands"
    d.mkdir()
    return d


def test_existing_hashes_only(tmp_path):
    r = repo(tmp_path, entry(H1) + entry(H2, "threatfox"))
    assert mb_hashes.collect_mb_hashes(r) == [H1]


def test_candidates_are_added_after_existing(tmp_path):
    r = repo(tmp_path, entry(H1))
    c = cands(tmp_path)
    (c / "malware-hashes.yml").write_text("entries:\n" + entry(H3))
    assert mb_hashes.collect_mb_hashes(r, c) == [H1, H3]


def test_duplicates_removed_order_kept(tmp_path):
    r = repo(tmp_path, entry(H2) + entry(H1))
    c = cands(tmp_path)
    (c / "a.yml").write_text("entries:\n" + entry(H1) + entry(H3) + entry(H3))
    assert mb_hashes.collect_mb_hashes(r, c) == [H2, H1, H3]


def test_non_malwarebazaar_candidates_ignored(tmp_path):
    r = repo(tmp_path, entry(H1))
    c = cands(tmp_path)
    (c / "a.yml").write_text("entries:\n" + entry(H2, "threatfox") + entry(H3, "amnesty-investigations"))
    assert mb_hashes.collect_mb_hashes(r, c) == [H1]


def test_malformed_candidate_files_ignored(tmp_path):
    r = repo(tmp_path, entry(H1))
    c = cands(tmp_path)
    (c / "bad.yml").write_text("entries: [unclosed\n")
    (c / "list.yml").write_text("- indicator: x\n")
    (c / "noentries.yml").write_text("other: 1\n")
    (c / "scalar.yml").write_text("entries: 5\n")
    (c / "tag.yml").write_text("entries: !!python/object/apply:os.system ['true']\n")
    (c / "good.yml").write_text("entries:\n" + entry(H3))
    assert mb_hashes.collect_mb_hashes(r, c) == [H1, H3]
