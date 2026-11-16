"""Tests for mirror-exodus-trackers.py."""
import importlib.util
import json
import pathlib
import sys

import pytest
import yaml

THIS_DIR = pathlib.Path(__file__).parent
sys.path.insert(0, str(THIS_DIR))
SCRIPT = THIS_DIR / "mirror-exodus-trackers.py"
FIXTURE = THIS_DIR / "fixtures" / "exodus-trackers-2026-11-06.json"


def _load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


mirror = _load(SCRIPT, "mirror_exodus_trackers")
render = mirror.render


def _one(id=1, code="", net="", cats=("Analytics",), name=None, website="https://example.com/"):
    return dict(id=id, name=name or f"T{id}", website=website, categories=list(cats),
                code_signature=code, network_signature=net)


def api(code="", net="", cats=("Analytics",), id=1, **kw):
    return api_many([dict(id=id, code=code, net=net, cats=cats, **kw)])


def api_many(specs):
    trackers = {}
    for s in specs:
        s = dict(s)
        t = _one(id=s["id"], code=s.get("code", ""), net=s.get("net", ""),
                 cats=s.get("cats", ("Analytics",)), website=s.get("website", "https://example.com/"))
        if "name" in s:
            t["name"] = s["name"]
        trackers[str(s["id"])] = t
    return {"trackers": trackers}


def test_class_name_signature_becomes_its_package():
    doc, _ = render(api(code="com.adobe.mobile.Analytics|com.adobe.mobile.Config."), None)
    assert doc["trackers"][0]["code_prefixes"] == ["com.adobe.mobile"]


def test_class_name_whose_package_is_a_parent_of_another_signature_is_dropped():
    doc, report = render(api(code="org.mozilla.fenix.GleanMetrics|org.mozilla.fenix.components.metrics"), None)
    assert doc["trackers"][0]["code_prefixes"] == ["org.mozilla.fenix.components.metrics"]
    assert any("GleanMetrics" in r for r in report)


def test_facebook_class_name_never_widens_to_com_facebook():
    doc, _ = render(api(code="com.facebook.appevents|com.facebook.marketing.|com.facebook.CampaignTrackingReceiver"), None)
    assert doc["trackers"][0]["code_prefixes"] == ["com.facebook.appevents", "com.facebook.marketing"]


def test_derived_values_failing_the_field_checks_are_dropped():
    doc, report = render(api(code="com.foo-bar.sdk.Cls|com.ok.sdk", net="\\.ad\\.server\\.|ok\\.example\\.com"), None)
    t = doc["trackers"][0]
    assert t["code_prefixes"] == ["com.ok.sdk"] and t["domain_labels"] == [] and t["domain_patterns"] == []
    assert len(report) == 2


def test_pattern_caps_keep_the_first_four_in_exodus_order():
    pats = [f"{c}[0-9]*\\.ex\\.com" for c in "fbdaec"]
    doc, report = render(api(code="com.x.y", net="|".join(pats)), None)
    assert doc["trackers"][0]["domain_patterns"] == pats[:4] and len(report) == 2


def test_pattern_cap_per_file_keeps_the_first_64_in_id_order():
    ids = list(range(33, 0, -1))
    doc, report = render(api_many([dict(id=i, code="com.x.y", net=f"a{i}[0-9]*\\.ex\\.com|b{i}[0-9]*\\.ex\\.com") for i in ids]), None)
    by_id = {t["id"]: t for t in doc["trackers"]}
    assert all(len(by_id[i]["domain_patterns"]) == 2 for i in range(1, 33))
    assert by_id[33]["domain_patterns"] == [] and by_id[33]["code_prefixes"] == ["com.x.y"] and len(report) == 2


def test_class_name_with_a_two_segment_package_is_dropped():
    doc, report = render(api(code="com.baidu.BaiduMap|com.baidu.mapapi"), None)
    assert doc["trackers"][0]["code_prefixes"] == ["com.baidu.mapapi"] and report


def test_dot_led_signature_becomes_a_segment():
    doc, _ = render(api(code=".sizmek."), None)
    assert doc["trackers"][0]["code_segments"] == ["sizmek"]


def test_upper_case_dot_led_signature_is_dropped():
    doc, report = render(api(code=".LigatusManager|com.ligatus.sdk"), None)
    assert doc["trackers"][0]["code_segments"] == [] and report


def test_hyphenated_signature_is_dropped_and_reported():
    doc, report = render(api(code="com.github.backtrace-labs.|io.backtrace."), None)
    assert doc["trackers"][0]["code_prefixes"] == ["io.backtrace"] and any("backtrace-labs" in r for r in report)


def test_escaped_dots_and_hyphens_become_plain_suffixes():
    doc, _ = render(api(net="app-measurement\\.com|\\.flurry\\.com|cdn\\-lb\\.vungle\\.com|.*\\.estimote\\.com"), None)
    assert doc["trackers"][0]["domain_suffixes"] == ["app-measurement.com", "cdn-lb.vungle.com", "estimote.com", "flurry.com"]


def test_dot_bounded_and_single_label_signatures_become_labels():
    doc, _ = render(api(net="\\.alimama\\.|fidzup"), None)
    assert doc["trackers"][0]["domain_labels"] == ["alimama", "fidzup"]


def test_a_real_pattern_in_the_grammar_is_kept():
    doc, _ = render(api(net="mst[0-9]*\\.is\\.autonavi\\.com"), None)
    assert doc["trackers"][0]["domain_patterns"] == ["mst[0-9]*\\.is\\.autonavi\\.com"]


def test_a_url_signature_is_dropped():
    doc, report = render(api(code="com.x.y", net="54\\.243\\.73\\.253:8080/SilverPush/"), None)
    assert doc["trackers"][0]["domain_patterns"] == [] and report


def test_broad_signatures_are_excluded_per_signature():
    doc, _ = render(api(net="\\.google\\.com|googleadservices\\.com"), None)
    t = doc["trackers"][0]
    assert t["domain_suffixes"] == ["googleadservices.com"] and t["excluded_domains"] == ["\\.google\\.com"]


def test_microsoft_sign_in_and_hicloud_are_broad():
    doc, _ = render(api(code="com.x.y", net="login\\.microsoftonline\\.com|hicloud\\.com"), None)
    assert doc["trackers"][0]["domain_suffixes"] == [] and len(doc["trackers"][0]["excluded_domains"]) == 2


def test_backtracking_patterns_are_dropped():
    for p in ["((a+))+$", "(a+?)+$", "(a{1,30}){1,30}$"]:
        doc, report = render(api(code="com.x.y", net=p), None)
        assert doc["trackers"][0]["domain_patterns"] == [] and report


def test_empty_category_becomes_uncategorised():
    doc, _ = render(api(code="com.x.y", cats=[]), None)
    assert doc["trackers"][0]["categories"] == ["Uncategorised"]


def test_tracker_with_nothing_left_is_dropped():
    doc, report = render(api(code="com.github.a-b.", net=""), None)
    assert doc["trackers"] == [] and report


def test_upper_case_website_host_is_kept():
    doc, _ = render(api(code="com.x.y", website="http://AppsFlyer.com"), None)
    assert doc["trackers"][0]["website"] == "http://AppsFlyer.com"


@pytest.mark.parametrize("site", ["javascript:alert(1)", "https://firebase.google.com@evil.example",
                                  "ftp://x.com/", "https://", "", None])
def test_unsafe_website_becomes_empty(site):
    doc, _ = render(api(code="com.x.y", website=site), None)
    assert doc["trackers"][0]["website"] == ""


@pytest.mark.parametrize("site", ["https://\u212a.com/", "https://\u017f.com/", "HTTP\u212a://x.com/"])
def test_non_ascii_lookalike_website_becomes_empty(site):
    # re.IGNORECASE would let [a-z] match KELVIN SIGN / LONG S; the check is ASCII-only
    doc, _ = render(api(code="com.x.y", website=site), None)
    assert doc["trackers"][0]["website"] == ""


def test_at_sign_in_website_path_is_kept():
    doc, _ = render(api(code="com.x.y", website="https://x.com/@user"), None)
    assert doc["trackers"][0]["website"] == "https://x.com/@user"


def test_output_sorted_by_id_and_has_licence():
    doc, _ = render(api_many([dict(id=9, code="com.x.y"), dict(id=2, code="com.x.y")]), None)
    assert [t["id"] for t in doc["trackers"]] == [2, 9]
    assert doc["license"] == "ODbL-1.0" and doc["version"] == 1


def _synthetic(n):
    return {"trackers": {str(i): _one(id=i, code=f"com.sdk{i}.core") for i in range(1, n + 1)}}


def test_main_refuses_a_large_shrink(tmp_path):
    src = tmp_path / "in.json"
    src.write_text(json.dumps(_synthetic(300)))
    prev = tmp_path / "prev.yml"
    prev.write_text(yaml.safe_dump({"trackers": [{"id": i} for i in range(400)]}))
    out = tmp_path / "out.yml"
    assert mirror.main(["--out", str(out), "--from-json", str(src), "--previous", str(prev)]) == 1
    assert not out.exists()


def test_main_refuses_fewer_than_300(tmp_path):
    src = tmp_path / "in.json"
    src.write_text(json.dumps(_synthetic(299)))
    out = tmp_path / "out.yml"
    assert mirror.main(["--out", str(out), "--from-json", str(src)]) == 1


def test_main_from_json_writes_file(tmp_path):
    src = tmp_path / "in.json"
    src.write_text(json.dumps(_synthetic(320)))
    out = tmp_path / "out.yml"
    assert mirror.main(["--out", str(out), "--from-json", str(src)]) == 0
    assert len(yaml.safe_load(out.read_text())["trackers"]) == 320 + len(mirror.load_supplement())


def _validator():
    spec = importlib.util.spec_from_file_location("validate_ioc_data", THIS_DIR / "validate-ioc-data.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _count(report, prefix):
    return sum(1 for r in report if r.startswith(prefix))


def test_snapshot_normalisation():
    api_doc = json.loads(FIXTURE.read_text(encoding="utf-8"))
    assert len(api_doc["trackers"]) == 432
    doc, report = render(api_doc, None)
    trackers = doc["trackers"]
    assert len(trackers) == 428
    kept = {t["id"] for t in trackers}
    assert set(int(k) for k in api_doc["trackers"]) - kept == {10, 71, 296, 431}

    assert _count(report, mirror.R_CLASS_NAME) == 16
    assert _count(report, mirror.R_UPPER_SEGMENT) == 3
    assert _count(report, mirror.R_BROAD) == 10

    patterns = sorted(p for t in trackers for p in t["domain_patterns"])
    assert patterns == sorted([r"adservice\.google\..*", r"mst[0-9]*\.is\.autonavi\.com", r"mt[0-9]*\.google\.cn"])
    labels = {l for t in trackers for l in t["domain_labels"]}
    assert labels == {"alimama", "adsmogo", "exacttarget", "fidzup"}
    assert sum(1 for t in trackers if t["categories"] == ["Uncategorised"]) == 113
    prefixes = {p for t in trackers for p in t["code_prefixes"]}
    assert not prefixes & {"com.facebook", "com.baidu", "com.dv", "com.prime31"}

    mod = _validator()
    assert mod.validate_trackers_file(doc, "trackers.yml") == []


# A refresh that cannot read Exodus must fail cleanly and leave no output: the
# /update-rules step reports exit code 2 as a feed failure, never as "no change".

def _fetch_errors():
    import http.client
    import urllib.error
    return [urllib.error.URLError("no route to SECRET-BODY"), TimeoutError("SECRET-BODY"),
            http.client.IncompleteRead(b"SECRET-BODY")]


@pytest.mark.parametrize("error", _fetch_errors(), ids=lambda e: type(e).__name__)
def test_main_exits_2_and_writes_nothing_when_exodus_is_unreachable(tmp_path, monkeypatch, capsys, error):
    def boom():
        raise error
    monkeypatch.setattr(mirror, "_fetch", boom)
    prev = tmp_path / "prev.yml"
    prev.write_text("trackers: []\n", encoding="utf-8")
    out = tmp_path / "out.yml"
    assert mirror.main(["--out", str(out), "--previous", str(prev)]) == 2
    assert not out.exists() and prev.read_text(encoding="utf-8") == "trackers: []\n"
    err = capsys.readouterr().err
    assert err.startswith("ERROR: could not read the Exodus tracker list") and "SECRET-BODY" not in err


def test_main_exits_2_when_the_fetched_answer_is_not_json(tmp_path, monkeypatch):
    def not_json():
        return json.loads("<html>503 Service Unavailable</html>")
    monkeypatch.setattr(mirror, "_fetch", not_json)
    out = tmp_path / "out.yml"
    assert mirror.main(["--out", str(out)]) == 2
    assert not out.exists()


@pytest.mark.parametrize("body", [
    "<html>503 Service Unavailable</html>", "[]", '{"trackers": []}', '{"detail": "throttled"}', "null", "",
    '{"trackers": {"abc": {}}}', '{"trackers": {"1": "not a tracker"}}'])
def test_main_exits_2_when_the_answer_is_not_the_tracker_list(tmp_path, body, capsys):
    src = tmp_path / "in.json"
    src.write_text(body, encoding="utf-8")
    out = tmp_path / "out.yml"
    assert mirror.main(["--out", str(out), "--from-json", str(src)]) == 2
    assert not out.exists()
    assert capsys.readouterr().err.count("ERROR:") == 1


def test_main_exits_2_when_the_json_file_is_missing(tmp_path):
    out = tmp_path / "out.yml"
    assert mirror.main(["--out", str(out), "--from-json", str(tmp_path / "missing.json")]) == 2
    assert not out.exists()


def test_main_writes_nothing_when_the_list_is_too_small(tmp_path):
    src = tmp_path / "in.json"
    src.write_text(json.dumps({"trackers": {}}), encoding="utf-8")
    out = tmp_path / "out.yml"
    assert mirror.main(["--out", str(out), "--from-json", str(src)]) == 1
    assert not out.exists()


# 2026-11 review of the /update-rules tracker step. The mirror applies the limits the
# validator enforces, so one odd upstream entry is set aside with a drop-report line
# instead of failing every refresh; and a fault in the rules repository's own files is
# reported as that, never as "Exodus could not be read".

@pytest.mark.parametrize("name", ["N" * 81, "", None, ["a", "list"], "Evil\nname", "Evil\u202ename"])
def test_tracker_with_an_unusable_name_is_dropped_and_reported(name):
    doc, report = render(api_many([dict(id=1, code="com.x.y"), dict(id=2, code="com.z.w", name=name)]), None)
    assert [t["id"] for t in doc["trackers"]] == [1]
    line = [r for r in report if r.startswith(mirror.R_TRACKER + ": 2: ")]
    assert len(line) == 1 and len(line[0]) < 200 and line[0].isascii() and line[0].isprintable()


def test_tracker_with_an_80_character_name_is_kept():
    doc, report = render(api(code="com.x.y", name="N" * 80), None)
    assert doc["trackers"][0]["name"] == "N" * 80 and report == []


def test_website_over_200_characters_becomes_empty():
    base = "https://example.org/"
    doc, _ = render(api(code="com.x.y", website=base + "a" * (200 - len(base))), None)
    assert len(doc["trackers"][0]["website"]) == 200
    doc, _ = render(api(code="com.x.y", website=base + "a" * (201 - len(base))), None)
    assert doc["trackers"][0]["website"] == ""


def test_signatures_over_253_characters_are_dropped_and_reported():
    doc, report = render(api(code="com.x.y|com." + "a" * 250 + "|." + "s" * 254 + ".",
                             net="ok\\.example\\.com|" + "a" * 250 + "\\.net|\\." + "l" * 254 + "\\."), None)
    t = doc["trackers"][0]
    assert (t["code_prefixes"], t["code_segments"]) == (["com.x.y"], [])
    assert (t["domain_suffixes"], t["domain_labels"]) == (["ok.example.com"], [])
    assert sum(1 for r in report if r.startswith(mirror.R_FIELD)) == 4


@pytest.mark.parametrize("code,kept", [
    ("androidx.core|com.tracker.sdk", ["com.tracker.sdk"]),
    ("com.google.android.gms.|com.google.android.gms.analytics", ["com.google.android.gms.analytics"]),
    ("kotlin.jvm.internal.Intrinsics|com.tracker.sdk", ["com.tracker.sdk"])])
def test_code_prefix_matching_an_ordinary_package_is_set_aside(code, kept):
    doc, report = render(api(code=code), None)
    assert doc["trackers"][0]["code_prefixes"] == kept
    assert sum(1 for r in report if r.startswith(mirror.R_BROAD + ": 1: ")) == 1


def test_code_segment_matching_an_ordinary_package_is_set_aside():
    doc, report = render(api(code=".android.|.sizmek."), None)
    assert doc["trackers"][0]["code_segments"] == ["sizmek"]
    assert sum(1 for r in report if r.startswith(mirror.R_BROAD + ": 1: ")) == 1


def test_whatever_the_mirror_keeps_the_validator_accepts():
    odd = [dict(id=i, code=f"com.sdk{i}.core") for i in range(1, 301)]
    odd += [dict(id=400, code="com.a.b", name="N" * 81), dict(id=401, code="androidx.core|com.c.d"),
            dict(id=402, code="com.e.f", website="https://example.org/" + "a" * 200),
            dict(id=403, code="com.g.h|com." + "a" * 250)]
    doc, _ = render(api_many(odd), None)
    assert _validator().validate_trackers_file(doc, "trackers.yml") == []


def _main_from_fixture(tmp_path, *extra):
    out = tmp_path / "out.yml"
    return mirror.main(["--out", str(out), "--from-json", str(FIXTURE), *extra]), out


@pytest.mark.parametrize("error", [FileNotFoundError("first_party_hosts.txt"),
                                   UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte")],
                         ids=lambda e: type(e).__name__)
@pytest.mark.parametrize("loader", ["first_party", "common"])
def test_main_exits_3_when_a_list_in_the_rules_repository_cannot_be_read(tmp_path, monkeypatch, capsys,
                                                                         loader, error):
    def boom(*_a, **_k):
        raise error
    if loader == "first_party":
        monkeypatch.setattr(mirror.dg, "load_first_party_hosts", boom)
    else:
        monkeypatch.setattr(mirror.tg, "load_common_packages", boom)
    code, out = _main_from_fixture(tmp_path)
    err = capsys.readouterr().err
    assert code == 3 and not out.exists()
    assert err.count("ERROR:") == 1 and "Exodus" not in err


@pytest.mark.parametrize("body", [": not yaml: [\n", "- just\n- a list\n", "trackers: nope\n", "just a string\n"])
def test_main_exits_3_when_the_previous_list_is_not_a_tracker_list(tmp_path, capsys, body):
    prev = tmp_path / "prev.yml"
    prev.write_text(body, encoding="utf-8")
    code, out = _main_from_fixture(tmp_path, "--previous", str(prev))
    err = capsys.readouterr().err
    assert code == 3 and not out.exists()
    assert err.count("ERROR:") == 1 and "Exodus" not in err


def test_main_exits_3_when_the_previous_list_is_missing(tmp_path, capsys):
    # A missing previous list would switch the shrink guard off without a word.
    code, out = _main_from_fixture(tmp_path, "--previous", str(tmp_path / "missing.yml"))
    err = capsys.readouterr().err
    assert code == 3 and not out.exists()
    assert err.count("ERROR:") == 1 and "Exodus" not in err


def test_main_without_a_previous_list_still_writes(tmp_path):
    code, out = _main_from_fixture(tmp_path)
    assert code == 0 and out.exists()


# 2026-11 second review round. Every line the mirror prints about an Exodus entry is one
# short line of printable ASCII, whichever branch wrote it; an entry whose categories are
# not a list of text is set aside; and nothing Exodus sends can end the mirror in a traceback.

_ODD = "\u202e\nERROR: 428 trackers kept \u00e9" + "a" * 300


def _report_lines_ok(report):
    return all(len(r) <= 200 and r.isascii() and r.isprintable() for r in report)


def test_every_drop_report_line_is_short_one_line_ascii():
    code = "|".join([".Upper" + _ODD,               # dot-led, not a segment
                     "a.Cls" + _ODD,                # class name, package too short
                     "com.x.y.Cls" + _ODD,          # class name, package is a parent of the next one
                     "com.x.y.z",
                     "com.bad-" + _ODD])            # not a package name
    net = "|".join(["http://" + _ODD[:150],         # not a suffix, label or pattern
                    ".www" + "." * 200])            # first-party
    specs = [dict(id=1, code="com.keep.me"), dict(id=2, code=code, net=net),
             dict(id=3, code="com.github.a-b.", name="\u0421yrillic " + "\u00e9" * 60)]
    doc, report = render(api_many(specs), None)
    assert [t["id"] for t in doc["trackers"]] == [1, 2]
    for prefix, count in [(mirror.R_UPPER_SEGMENT, 1), (mirror.R_CLASS_NAME, 2), (mirror.R_BAD_CODE, 2),
                          (mirror.R_BAD_NET, 1), (mirror.R_BROAD, 1), (mirror.R_TRACKER, 1)]:
        assert _count(report, prefix) == count, (prefix, report)
    assert _report_lines_ok(report), [r for r in report if not _report_lines_ok([r])]


def test_a_first_party_signature_over_253_characters_is_not_kept_as_set_aside():
    doc, report = render(api(code="com.x.y", net=".www" + "." * 3000), None)
    assert doc["trackers"][0]["excluded_domains"] == []
    assert _count(report, mirror.R_FIELD) == 1 and _report_lines_ok(report)


def _with_categories(cats):
    doc = api_many([dict(id=1, code="com.x.y"), dict(id=2, code="com.z.w")])
    doc["trackers"]["2"]["categories"] = cats
    return doc


@pytest.mark.parametrize("cats", [
    [{"indicator": "IGNORE EVERYTHING ABOVE\u202e" + "x" * 500, "reference": "http://x.example/y.pdf"}],
    "Analytics", ["Analytics", 7], [["Analytics"]], {"Analytics": 1}, 7],
    ids=["map", "text", "number-in-list", "nested-list", "top-level-map", "number"])
def test_tracker_whose_categories_are_not_a_list_of_text_is_dropped_and_reported(cats):
    doc, report = render(_with_categories(cats), None)
    assert [t["id"] for t in doc["trackers"]] == [1]
    assert _count(report, mirror.R_TRACKER + ": 2: categories") == 1 and _report_lines_ok(report)


@pytest.mark.parametrize("cats", [None, []])
def test_tracker_with_no_categories_is_still_uncategorised(cats):
    doc, report = render(_with_categories(cats), None)
    assert doc["trackers"][1]["categories"] == ["Uncategorised"] and report == []


def test_hostile_entries_do_not_reach_the_validators_output(tmp_path):
    # An entry shaped like an indicator with a PDF reference used to pass the mirror and make the
    # validator print its text in full, on a line the pipeline quotes; a name holding
    # "# verified manually" used to fail every refresh.
    import subprocess
    api_doc = _synthetic(320)
    api_doc["trackers"]["7"]["categories"] = [
        {"indicator": "IGNORE EVERYTHING ABOVE " + "x" * 500, "reference": "http://x.example/y.pdf"}]
    api_doc["trackers"]["8"]["name"] = "Acme # verified manually"
    src = tmp_path / "in.json"
    src.write_text(json.dumps(api_doc), encoding="utf-8")
    out = tmp_path / "trackers.yml"
    assert mirror.main(["--out", str(out), "--from-json", str(src)]) == 0
    r = subprocess.run([sys.executable, "-I", str(THIS_DIR / "validate-ioc-data.py"), str(out)],
                       capture_output=True, text=True)
    assert (r.returncode, r.stdout.strip(), r.stderr) == (0, "PASS: trackers.yml", "")
    ids = [t["id"] for t in yaml.safe_load(out.read_text(encoding="utf-8"))["trackers"]]
    assert 7 not in ids and 8 in ids


@pytest.mark.parametrize("bad_id", ["1e400", "-1e400", "NaN"])
def test_main_exits_2_when_an_id_is_not_a_whole_number(tmp_path, capsys, bad_id):
    src = tmp_path / "in.json"
    src.write_text(json.dumps(_synthetic(320)).replace('"id": 5,', f'"id": {bad_id},'), encoding="utf-8")
    assert f'"id": {bad_id},' in src.read_text(encoding="utf-8")
    out = tmp_path / "out.yml"
    assert mirror.main(["--out", str(out), "--from-json", str(src)]) == 2
    err = capsys.readouterr().err
    assert not out.exists() and err.count("ERROR:") == 1 and "Traceback" not in err


# 2026-11 third review round.

def test_repeated_categories_are_kept_once_in_exodus_order():
    # 50,000 repeats of one label used to pass the mirror and the validator and to be invisible in
    # the review summary (it compares categories as sets), while the file outgrew the app's fetch limit.
    cats = ["Analytics", "Advertisement", "Analytics"] + ["Analytics"] * 50000
    doc, report = render(_with_categories(cats), None)
    assert doc["trackers"][1]["categories"] == ["Analytics", "Advertisement"] and report == []


@pytest.mark.parametrize("bad_id", [0, -5, 10 ** 9, 10 ** 400], ids=["zero", "negative", "ten-digits", "401-digits"])
def test_tracker_whose_id_is_out_of_range_is_dropped_and_its_id_is_not_printed_in_full(bad_id):
    doc = api_many([dict(id=1, code="com.x.y"), dict(id=2, code="com.z.w")])
    doc["trackers"]["2"]["id"] = bad_id
    built, report = render(doc, None)
    assert [t["id"] for t in built["trackers"]] == [1]
    assert len(report) == 1 and report[0].startswith(mirror.R_TRACKER + ": 0: its id ") and _report_lines_ok(report)
    # the review summary counts and shows a drop line only when it has this shape
    summary = _load(THIS_DIR / "summarize-tracker-changes.py", "summarize_tracker_changes_for_ids")
    assert summary.DROP_LINE.match(report[0])


def test_every_kept_id_fits_the_summary_scripts_drop_line_pattern():
    # Exodus's range ends just below AndroDR's own (tracker_guards.SUPPLEMENT_ID_MIN).
    top = mirror.tg.SUPPLEMENT_ID_MIN - 1
    doc, report = render(api_many([dict(id=1, code="com.x.y"), dict(id=top, code="com.z.w"),
                                   dict(id=mirror.tg.ID_MAX, code="com.q.r")]), None)
    assert [t["id"] for t in doc["trackers"]] == [1, 900_000]
    summary = _load(THIS_DIR / "summarize-tracker-changes.py", "summarize_tracker_changes_for_kept_ids")
    assert len(report) == 1 and summary.DROP_LINE.match(report[0])


@pytest.mark.parametrize("depth", [20000, 200000])
def test_main_exits_2_when_the_answer_is_nested_too_deep(tmp_path, capsys, depth):
    src = tmp_path / "in.json"
    src.write_text('{"trackers": {"1": {"id": 1, "categories": ' + "[" * depth + "]" * depth + "}}}",
                   encoding="utf-8")
    out = tmp_path / "out.yml"
    assert mirror.main(["--out", str(out), "--from-json", str(src)]) == 2
    err = capsys.readouterr().err
    assert not out.exists() and err.count("ERROR:") == 1 and "Traceback" not in err


def test_main_exits_2_when_an_entry_cannot_be_walked(tmp_path, monkeypatch, capsys):
    def too_deep(*_a, **_k):
        raise RecursionError("maximum recursion depth exceeded")
    monkeypatch.setattr(mirror, "render", too_deep)
    code, out = _main_from_fixture(tmp_path)
    err = capsys.readouterr().err
    assert code == 2 and not out.exists() and err.count("ERROR:") == 1


def test_a_pattern_over_the_file_cap_is_reported_in_one_short_line():
    long_pattern = "z[0-9]*\\." + "\\.".join(["a" * 40] * 3) + "\\.ex\\.com"
    specs = [dict(id=i, code="com.x.y", net=f"a{i}[0-9]*\\.ex\\.com|b{i}[0-9]*\\.ex\\.com") for i in range(1, 33)]
    specs.append(dict(id=33, code="com.x.y", net=long_pattern))
    doc, report = render(api_many(specs), None)
    assert doc["trackers"][-1]["domain_patterns"] == []
    assert len(report) == 1 and report[0].startswith(mirror.R_CAP + ": 33: file cap, ")
    assert report[0].endswith("...") and _report_lines_ok(report)


# AndroDR's own entries (tracker-supplement.yml). Exodus lists no residential-proxy SDK, so
# those are ours; the mirror appends them on every run. A fault in one stops the run (exit 3):
# a quietly dropped supplement entry would be a detection lost without a word.

BRIGHT_PREFIXES = ["brdat.sdk", "com.android.eapx", "io.lum.sdk", "io.topvpn.vpn_api", "org.hola.peer"]


def _sup(**kw):
    entry = dict(id=900001, name="Own SDK", website="https://example.org", categories=["Proxyware"],
                 code_prefixes=["org.own.sdk"])
    entry.update(kw)
    return {k: v for k, v in entry.items() if v is not None}


def _sup_file(tmp_path, *entries, body=None):
    f = tmp_path / "supplement.yml"
    f.write_text(body if body is not None else yaml.safe_dump({"version": 1, "trackers": list(entries)}),
                 encoding="utf-8")
    return f


def test_the_real_supplement_loads_and_holds_bright_sdk():
    entries = mirror.load_supplement()
    bright = next(e for e in entries if e["id"] == 900001)
    assert bright["name"] == "Bright SDK (residential proxy)"
    assert bright["categories"] == ["Proxyware"]
    assert bright["code_prefixes"] == BRIGHT_PREFIXES
    assert {"brdtnet.com", "bright-sdk.com", "luminatinet.com"} <= set(bright["domain_suffixes"])
    assert "references" not in bright  # for the reviewer, not for the list the app reads


def test_supplement_hosts_stay_within_the_threat_list():
    # The entry's hosts are the Bright SDK hosts of ioc-data/c2-domains.yml and nothing wider:
    # brightdata.com, luminati.io and the shared CDN parents are deliberately not listed there.
    c2 = yaml.safe_load((THIS_DIR.parent / "ioc-data" / "c2-domains.yml").read_text(encoding="utf-8"))
    listed = {e["indicator"] for e in c2["entries"] if e.get("category") == "PROXYWARE"}
    bright = next(e for e in mirror.load_supplement() if e["id"] == 900001)
    assert set(bright["domain_suffixes"]) <= listed


def test_supplement_entries_are_appended_after_the_exodus_ones():
    sup = mirror.load_supplement()
    doc, _ = render(api_many([dict(id=9, code="com.x.y"), dict(id=2, code="com.x.y")]), None, supplement=sup)
    ids = [t["id"] for t in doc["trackers"]]
    assert ids == [2, 9] + [e["id"] for e in sup] and ids == sorted(ids)
    assert "900001" in doc["supplement"] and "Exodus" in doc["attribution"]


def test_without_a_supplement_the_document_is_the_exodus_list_alone():
    doc, _ = render(api(code="com.x.y"), None)
    assert "supplement" not in doc and [t["id"] for t in doc["trackers"]] == [1]


def test_a_regeneration_from_an_exodus_dump_keeps_the_supplement(tmp_path):
    code, out = _main_from_fixture(tmp_path)
    assert code == 0
    doc = yaml.safe_load(out.read_text(encoding="utf-8"))
    assert len(doc["trackers"]) == 428 + len(mirror.load_supplement())
    last = doc["trackers"][-1]
    assert last["id"] == 900001 and last["categories"] == ["Proxyware"] and last["code_prefixes"] == BRIGHT_PREFIXES
    assert _validator().validate_trackers_file(doc, "trackers.yml") == []


def test_the_list_in_use_is_the_mirror_of_the_snapshot_plus_the_supplement(tmp_path):
    # ioc-data/trackers.yml is only ever the mirror's whole output; the supplement is in it.
    in_use = yaml.safe_load((THIS_DIR.parent / "ioc-data" / "trackers.yml").read_text(encoding="utf-8"))
    ours = [t for t in in_use["trackers"] if t["id"] >= mirror.tg.SUPPLEMENT_ID_MIN]
    assert ours == mirror.load_supplement()


def test_an_exodus_entry_in_the_supplement_id_range_is_set_aside():
    doc, report = render(api_many([dict(id=5, code="com.x.y"), dict(id=900001, code="com.evil.sdk")]),
                         None, supplement=mirror.load_supplement())
    assert [t["id"] for t in doc["trackers"]].count(900001) == 1
    assert doc["trackers"][-1]["name"] == "Bright SDK (residential proxy)"
    assert _count(report, mirror.R_TRACKER) == 1 and "900001" in report[0] and "reserved" in report[0]


@pytest.mark.parametrize("entry, why", [
    (_sup(id=900000), "whole number"),
    (_sup(id=448), "whole number"),
    (_sup(id="900001"), "whole number"),
    (_sup(id=True), "whole number"),
    (_sup(name=""), "name"),
    (_sup(name="N" * 81), "name"),
    (_sup(website="javascript:alert(1)"), "website"),
    (_sup(categories=[]), "categories"),
    (_sup(categories="Proxyware"), "categories"),
    (_sup(categories=["Proxyware", "Proxyware"]), "categories"),
    (_sup(code_prefixes=["com.google.gson"]), "ordinary package"),
    (_sup(code_prefixes=["java.util"]), "ordinary package"),
    (_sup(code_prefixes=["Not A Package"]), "prefix check"),
    (_sup(code_prefixes="org.own.sdk"), "not a list"),
    (_sup(code_prefixes=["org.own.sdk", "org.own.sdk"]), "repeats"),
    (_sup(code_prefixes=None), "no signature"),
    (_sup(domain_suffixes=["youtube.com"]), "first-party host"),
    (_sup(domain_suffixes=["not a host"]), "suffix check"),
    (_sup(domain_patterns=[r"mt[0-9]*\.google\.cn"]), "unknown key"),
    (_sup(note="x"), "unknown key"),
    (_sup(references=["http://example.org"]), "references"),
    (_sup(references="https://example.org"), "references"),
    ("just text", "not a map"),
])
def test_a_faulty_supplement_entry_stops_the_load(tmp_path, entry, why):
    with pytest.raises(ValueError, match=why):
        mirror.load_supplement(_sup_file(tmp_path, entry))


def test_a_repeated_supplement_id_stops_the_load(tmp_path):
    with pytest.raises(ValueError, match="used twice"):
        mirror.load_supplement(_sup_file(tmp_path, _sup(), _sup(name="Other")))


@pytest.mark.parametrize("body", ["- a\n- list\n", "version: 2\ntrackers: []\n", "version: 1\ntrackers: nope\n",
                                  "just a string\n"])
def test_a_supplement_that_is_not_a_supplement_stops_the_load(tmp_path, body):
    with pytest.raises(ValueError, match="version 1 supplement"):
        mirror.load_supplement(_sup_file(tmp_path, body=body))


def test_supplement_entries_come_back_sorted_by_id(tmp_path):
    f = _sup_file(tmp_path, _sup(id=900005, name="B"), _sup(id=900002, name="A"))
    assert [e["id"] for e in mirror.load_supplement(f)] == [900002, 900005]


@pytest.mark.parametrize("body", [None, ": not yaml: [\n", "version: 1\ntrackers:\n- id: 5\n  name: X\n"],
                         ids=["missing", "not-yaml", "bad-entry"])
def test_main_exits_3_and_writes_nothing_when_the_supplement_is_missing_or_faulty(tmp_path, monkeypatch,
                                                                                    capsys, body):
    f = tmp_path / "supplement.yml"
    if body is not None:
        f.write_text(body, encoding="utf-8")
    monkeypatch.setattr(mirror, "SUPPLEMENT_FILE", f)
    code, out = _main_from_fixture(tmp_path)
    err = capsys.readouterr().err
    assert code == 3 and not out.exists()
    assert err.count("ERROR:") == 1 and "Exodus" not in err


def test_the_size_guards_count_exodus_entries_only(tmp_path):
    # 299 from Exodus plus our own is still a broken Exodus answer, and a previous list is
    # compared without its supplement entries.
    src = tmp_path / "in.json"
    src.write_text(json.dumps(_synthetic(360)))
    prev = tmp_path / "prev.yml"
    prev.write_text(yaml.safe_dump({"trackers": [{"id": i} for i in range(1, 401)] + [{"id": 900001}]}))
    out = tmp_path / "out.yml"
    assert mirror.main(["--out", str(out), "--from-json", str(src), "--previous", str(prev)]) == 0
    prev.write_text(yaml.safe_dump({"trackers": [{"id": i} for i in range(1, 402)] + [{"id": 900001}]}))
    assert mirror.main(["--out", str(tmp_path / "o2.yml"), "--from-json", str(src), "--previous", str(prev)]) == 1


def test_the_kept_line_keeps_the_shape_the_update_rules_step_reads(tmp_path, capsys):
    # scripts/test_update_rules_pipeline.py (AndroDR) pins: ^[0-9]+ trackers kept, [0-9]+ drop-report lines$
    import re
    code, _ = _main_from_fixture(tmp_path)
    lines = capsys.readouterr().err.splitlines()
    assert code == 0
    assert [l for l in lines if re.fullmatch(r"[0-9]+ trackers kept, [0-9]+ drop-report lines", l)] == \
        ["428 trackers kept, 36 drop-report lines"]
    assert lines[-1] == "1 of AndroDR's own entries appended"
