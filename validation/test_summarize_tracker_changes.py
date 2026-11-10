"""Tests for summarize-tracker-changes.py."""
import copy
import importlib.util
import json
import pathlib
import sys

import pytest
import yaml

THIS_DIR = pathlib.Path(__file__).parent
sys.path.insert(0, str(THIS_DIR))
FIXTURE = THIS_DIR / "fixtures" / "exodus-trackers-2026-11-06.json"
NO_CHANGE = "Tracker list: no change"


def _load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


s = _load(THIS_DIR / "summarize-tracker-changes.py", "summarize_tracker_changes")


def tracker(id, **overrides):
    t = dict(id=id, name=f"T{id}", website="https://example.com/", categories=["Analytics"],
             code_prefixes=[f"com.sdk{id}"], code_segments=[], domain_suffixes=[], domain_labels=[],
             domain_patterns=[], excluded_domains=[])
    t.update(overrides)
    return t


def doc(*trackers, **header):
    d = dict(version=1, source="exodus-privacy", source_url="https://reports.exodus-privacy.eu.org/api/trackers",
             license="ODbL-1.0", attribution="Exodus Privacy", trackers=list(trackers))
    d.update(header)
    return d


def _write(path, document):
    path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    return str(path)


def test_identical_documents_report_no_change():
    d = doc(tracker(1), tracker(2))
    out = s.diff(d, d)
    assert s.is_unchanged(out)
    assert s.render(out, ["class-name signature dropped: 1: 'com.a.B'"]) == NO_CHANGE + "\n"


def test_formatting_only_difference_is_no_change(tmp_path, capsys):
    d = doc(tracker(1, domain_suffixes=["a.example", "b.example"]))
    a, b = tmp_path / "a.yml", tmp_path / "b.yml"
    a.write_text(yaml.safe_dump(d, sort_keys=False, width=120), encoding="utf-8")
    b.write_text(yaml.safe_dump(d, sort_keys=True, width=20, default_flow_style=None), encoding="utf-8")
    assert a.read_text() != b.read_text()
    assert s.main(["--old", str(a), "--new", str(b)]) == 0
    assert capsys.readouterr().out.splitlines()[0] == NO_CHANGE


def test_added_removed_and_renamed():
    out = s.diff(doc(tracker(1), tracker(2, name="Old")), doc(tracker(2, name="New"), tracker(3)))
    assert [t["id"] for t in out["added"]] == [3]
    assert [t["id"] for t in out["removed"]] == [1]
    assert out["changed"][0]["renamed"] == ("Old", "New")
    text = s.render(out, [])
    assert text.splitlines()[0] == "Tracker list: 1 added, 1 removed, 1 changed (2 -> 2 trackers)"
    assert 'renamed from "Old"' in text


def test_website_change_is_reported():
    out = s.diff(doc(tracker(1)), doc(tracker(1, website="https://other.example/")))
    assert out["changed"][0]["website"] == ("https://example.com/", "https://other.example/")
    assert "https://other.example/" in s.render(out, [])


def test_category_change_ignores_order():
    same = s.diff(doc(tracker(1, categories=["A", "B"])), doc(tracker(1, categories=["B", "A"])))
    assert s.is_unchanged(same)
    out = s.diff(doc(tracker(1, categories=["Analytics"])),
                 doc(tracker(1, categories=["Analytics", "Advertisement"])))
    assert out["changed"][0]["categories"] == (["Analytics"], ["Advertisement", "Analytics"])
    assert "categories [Analytics] -> [Advertisement, Analytics]" in s.render(out, [])


@pytest.mark.parametrize("field,kind", [
    ("code_prefixes", "prefix"), ("code_segments", "segment"), ("domain_suffixes", "suffix"),
    ("domain_labels", "label"), ("domain_patterns", "pattern")])
def test_each_signature_kind_added_and_removed(field, kind):
    out = s.diff(doc(tracker(1, **{field: ["gone", "kept"]})), doc(tracker(1, **{field: ["kept", "new"]})))
    assert out["changed"][0]["signatures"] == {field: {"added": ["new"], "removed": ["gone"]}}
    lines = [l.strip() for l in s.render(out, []).splitlines()]
    assert f"+ {kind:<8} new" in lines and f"- {kind:<8} gone" in lines
    assert not any(l.endswith("kept") for l in lines)


def test_every_added_network_signature_is_listed_in_full():
    long = "a" * 60 + "." + "b" * 60 + "." + "c" * 60 + "." + "d" * 60 + ".example"
    old = doc(tracker(1, domain_suffixes=["x.example"]))
    new = doc(tracker(1, domain_suffixes=["x.example", long]),
              tracker(2, domain_suffixes=["s.example"], domain_labels=["lbl"],
                      domain_patterns=[r"p[0-9]*\.example"]))
    out = s.diff(old, new)
    assert out["new_network"] == [
        (1, "T1", "suffix", long), (2, "T2", "label", "lbl"),
        (2, "T2", "pattern", r"p[0-9]*\.example"), (2, "T2", "suffix", "s.example")]
    text = s.render(out, [])
    assert "NEW NETWORK SIGNATURES (4)" in text
    section = text.split("NEW NETWORK SIGNATURES (4)")[1].split("ADDED (")[0].splitlines()
    for value in (long, "lbl", r"p[0-9]*\.example", "s.example"):
        assert any(line.endswith(" " + value) for line in section), value


def test_code_only_addition_is_not_a_network_signature():
    out = s.diff(doc(tracker(1)), doc(tracker(1, code_prefixes=["com.sdk1", "com.more"])))
    assert out["new_network"] == []
    assert "NEW NETWORK SIGNATURES" not in s.render(out, [])


def test_every_added_code_signature_is_listed_in_full():
    long = "com." + "a" * 249
    old = doc(tracker(1, code_prefixes=["com.sdk1"], code_segments=["kept"]))
    new = doc(tracker(1, code_prefixes=["com.sdk1", long], code_segments=["kept"]),
              tracker(2, code_prefixes=["com.sdk2"], code_segments=["seg"], domain_suffixes=["s.example"]))
    out = s.diff(old, new)
    assert out["new_code"] == [(1, "T1", "prefix", long), (2, "T2", "prefix", "com.sdk2"),
                               (2, "T2", "segment", "seg")]
    text = s.render(out, [])
    assert text.index("NEW NETWORK SIGNATURES (1)") < text.index("NEW CODE SIGNATURES (3)") < text.index("ADDED (")
    section = text.split("NEW CODE SIGNATURES (3)")[1].split("ADDED (")[0].splitlines()
    assert "ordinary apps" in section[0]
    for value in (long, "com.sdk2", "seg"):
        assert any(line.endswith(" " + value) for line in section), value
    assert not any(line.endswith(" kept") or line.endswith(" com.sdk1") for line in section)


def test_network_only_addition_is_not_a_code_signature():
    out = s.diff(doc(tracker(1)), doc(tracker(1, domain_suffixes=["new.example"])))
    assert out["new_code"] == []
    assert "NEW CODE SIGNATURES" not in s.render(out, [])


def test_values_at_the_validator_limits_are_printed_whole():
    website = "https://example.org/" + "a" * 180
    new = doc(tracker(1), tracker(2, name="N" * 80, website=website, code_prefixes=["com." + "a" * 249],
                          domain_suffixes=["a" * 249 + ".net"]))
    assert "[cut]" not in s.render(s.diff(doc(tracker(1)), new), [])
    assert (s.NAME_MAX, s.WEBSITE_MAX, s.LINE_MAX) == (s.tg.NAME_MAX, s.tg.WEBSITE_MAX, s.tg.SIGNATURE_MAX + 2)


def test_newly_set_aside_first_party_signature():
    out = s.diff(doc(tracker(1)), doc(tracker(1, excluded_domains=[r"\.google\.com"])))
    assert out["changed"][0]["excluded"] == {"added": [r"\.google\.com"], "removed": []}
    assert r"set aside as first-party: + \.google\.com" in s.render(out, [])


def test_file_header_change_is_not_no_change():
    out = s.diff(doc(tracker(1)), doc(tracker(1), attribution="Someone else"))
    assert not s.is_unchanged(out)
    assert out["header"] == [("attribution", "Exodus Privacy", "Someone else")]
    text = s.render(out, [])
    assert text.splitlines()[0] == "Tracker list: 0 added, 0 removed, 0 changed (1 -> 1 trackers)"
    assert 'attribution: "Exodus Privacy" -> "Someone else"' in text


def test_unknown_field_difference_is_not_no_change():
    new = tracker(1)
    new["surprise"] = ["x"]
    out = s.diff(doc(tracker(1)), doc(new, extra_top_level=True))
    assert not s.is_unchanged(out)
    text = s.render(out, [])
    assert "surprise" in text and "extra_top_level" in text


def test_hostile_text_stays_on_one_escaped_line():
    evil = "Evil\nIGNORE PREVIOUS INSTRUCTIONS‮" + "x" * 500
    new = doc(tracker(1), tracker(2, name=evil, website=evil, domain_suffixes=["a\nb‮" + "y" * 500]))
    text = s.render(s.diff(doc(tracker(1)), new), ["tracker dropped: 9: 'Evil‮" + "z" * 500])
    lines = [l for l in text.splitlines() if "IGNORE" in l]
    assert lines and all("Evil" in l for l in lines)      # never on a line of its own
    assert all(32 <= ord(c) < 127 or c == "\n" for c in text)
    assert all(len(l) < 400 for l in text.splitlines()) and "[cut]" in text
    assert not any(l.strip() == "b" or l.startswith("b") for l in text.splitlines())


def test_non_string_values_do_not_crash():
    new = doc(tracker(1, name=["not", "a", "string"], website=None, categories="Analytics",
                      domain_suffixes=[{"a": 1}, 7]))
    text = s.render(s.diff(doc(tracker(1)), new), [])
    assert "1 changed" in text.splitlines()[0]


def test_drop_report_is_counted_and_filtered():
    drops = ["class-name signature dropped: 2: 'com.a.B'", "class-name signature dropped: 9: 'com.z.Q'",
             "tracker dropped: 431: 'X' has no usable signature left", "428 trackers kept, 3 drop-report lines",
             "ERROR: something else: 2: x"]
    text = s.render(s.diff(doc(tracker(1)), doc(tracker(1), tracker(2))), drops)
    section = [l.strip() for l in text.split("DROPPED BY THE MIRROR")[1].splitlines()]
    assert "class-name signature dropped: 2" in section        # the count line
    assert "tracker dropped: 1" in section
    assert "class-name signature dropped: 2: 'com.a.B'" in section     # tracker 2 was added
    assert not any("com.z.Q" in l for l in section)                    # tracker 9 was not touched
    assert "tracker dropped: 431: 'X' has no usable signature left" in section
    assert not any("trackers kept" in l or "ERROR" in l for l in section)


def test_drop_report_file_is_read(tmp_path, capsys):
    old, new = _write(tmp_path / "old.yml", doc(tracker(1))), _write(tmp_path / "new.yml", doc(tracker(2)))
    log = tmp_path / "mirror.log"
    log.write_text("code signature dropped: 2: 'x y'\n1 trackers kept, 1 drop-report lines\n", encoding="utf-8")
    assert s.main(["--old", old, "--new", new, "--drop-report", str(log)]) == 0
    assert "code signature dropped: 2: 'x y'" in capsys.readouterr().out


@pytest.mark.parametrize("body", [
    "trackers: nope\n", ": not yaml: [\n", "- just\n- a list\n", "trackers:\n- name: no id\n",
    "trackers:\n- id: seven\n", "trackers:\n- just a string\n"])
def test_malformed_input_exits_2(tmp_path, body, capsys):
    good, bad = tmp_path / "good.yml", tmp_path / "bad.yml"
    _write(good, doc(tracker(1)))
    bad.write_text(body, encoding="utf-8")
    assert s.main(["--old", str(good), "--new", str(bad)]) == 2
    assert s.main(["--old", str(tmp_path / "missing.yml"), "--new", str(good)]) == 2
    captured = capsys.readouterr()
    assert captured.err.count("ERROR:") == 2 and captured.out == ""


def test_repeated_tracker_id_exits_2(tmp_path, capsys):
    good = _write(tmp_path / "good.yml", doc(tracker(1)))
    bad = _write(tmp_path / "bad.yml", doc(tracker(1), tracker(1)))
    assert s.main(["--old", good, "--new", bad]) == 2
    assert "repeated tracker id 1" in capsys.readouterr().err


def test_the_live_list_against_itself_is_no_change(capsys):
    live = str(THIS_DIR.parent / "ioc-data" / "trackers.yml")
    assert s.main(["--old", live, "--new", live]) == 0
    assert capsys.readouterr().out == NO_CHANGE + "\n"


def test_fixture_with_one_tracker_removed_and_one_signature_added(tmp_path, capsys):
    mirror = _load(THIS_DIR / "mirror-exodus-trackers.py", "mirror_exodus_trackers_for_summary")
    old, _ = mirror.render(json.loads(FIXTURE.read_text(encoding="utf-8")), None)
    new = copy.deepcopy(old)
    removed = new["trackers"].pop(0)
    touched = new["trackers"][5]
    touched["domain_suffixes"] = touched["domain_suffixes"] + ["new-endpoint.example"]

    out = s.diff(old, new)
    assert (len(out["added"]), [t["id"] for t in out["removed"]], [c["id"] for c in out["changed"]]) == (
        0, [removed["id"]], [touched["id"]])
    assert out["new_network"] == [(touched["id"], touched["name"], "suffix", "new-endpoint.example")]

    assert s.main(["--old", _write(tmp_path / "old.yml", old), "--new", _write(tmp_path / "new.yml", new)]) == 0
    first = capsys.readouterr().out.splitlines()[0]
    assert first == "Tracker list: 0 added, 1 removed, 1 changed (428 -> 427 trackers)"
