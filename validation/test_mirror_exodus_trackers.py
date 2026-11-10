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
    assert len(yaml.safe_load(out.read_text())["trackers"]) == 320


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
