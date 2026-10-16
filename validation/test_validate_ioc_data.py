"""Unit tests for validate-ioc-data.py hash-format rejection (AndroDR #128).

Covers the extension added in #128: structural rejection of hash IOC formats
that cannot match on-device (MD5, SHA-1 in APK context, TLSH, SHA-512, ssdeep).

Run:
    python3 -m pytest validation/test_validate_ioc_data.py -v
"""
import os
import pathlib
import subprocess
import sys
import textwrap


THIS_DIR = pathlib.Path(__file__).parent
SCRIPT = THIS_DIR / "validate-ioc-data.py"


def run_validator(tmp_path, filename: str, body: str, env=None):
    """Write `body` to tmp_path/filename and run the validator on it."""
    p = tmp_path / filename
    p.write_text(body)
    result = subprocess.run(
        [sys.executable, str(SCRIPT), str(p)],
        capture_output=True, text=True, env=env,
    )
    return result


# ---------- malware-hashes.yml (APK): SHA-256 only ----------

SHA256 = "b2be8ef1895f42981a717359ab2d263dc1351f7893ac8629ea6863dc76601d8e"
MD5    = "b4489cb4fac743246f29abf7f605dd15"
SHA1   = "774cb9a0f6593befe30469dd3b73c4064aa0fb96"
TLSH   = "t1" + "a" * 70  # 72 chars total
SHA512 = "a" * 128
SSDEEP = "3072:abc123xyz:def456uvw"


def _apk_body(indicator: str, source: str = "malwarebazaar") -> str:
    return textwrap.dedent(f"""
        version: "2026-04-16"
        description: "test"
        sources: [{source}]
        entries:
          - indicator: "{indicator}"
            family: DogfoodSpy
            category: MALWARE
            severity: HIGH
            source: {source}
            reference: feed:{source}#DogfoodSpy
    """).strip()


def _cert_body(indicator: str) -> str:
    return textwrap.dedent(f"""
        version: "2026-04-16"
        description: "test"
        sources: [stalkerware-indicators]
        entries:
          - indicator: "{indicator}"
            family: DogfoodSpy
            category: STALKERWARE
            severity: CRITICAL
            source: stalkerware-indicators
            reference: feed:stalkerware-indicators#DogfoodSpy
    """).strip()


def test_apk_sha256_accepted(tmp_path):
    r = run_validator(tmp_path, "malware-hashes.yml", _apk_body(SHA256))
    assert r.returncode == 0, r.stderr


def test_apk_md5_rejected(tmp_path):
    r = run_validator(tmp_path, "malware-hashes.yml", _apk_body(MD5))
    assert r.returncode == 1
    assert "likely MD5" in r.stderr
    assert "SHA-256" in r.stderr


def test_apk_sha1_rejected(tmp_path):
    r = run_validator(tmp_path, "malware-hashes.yml", _apk_body(SHA1))
    assert r.returncode == 1
    assert "SHA-1 is not matched on-device" in r.stderr


def test_apk_tlsh_rejected(tmp_path):
    r = run_validator(tmp_path, "malware-hashes.yml", _apk_body(TLSH.replace("t1", "aa")))
    # TLSH detector expects 72 hex only; force all-hex for detection
    assert r.returncode == 1
    assert "TLSH" in r.stderr or "72 hex" in r.stderr


def test_apk_sha512_rejected(tmp_path):
    r = run_validator(tmp_path, "malware-hashes.yml", _apk_body(SHA512))
    assert r.returncode == 1
    assert "SHA-512" in r.stderr


def test_apk_ssdeep_rejected(tmp_path):
    r = run_validator(tmp_path, "malware-hashes.yml", _apk_body(SSDEEP))
    assert r.returncode == 1
    # Either classified as ssdeep OR falls through to generic format error —
    # both are acceptable rejections.
    assert ("ssdeep" in r.stderr.lower()) or ("invalid APK hash format" in r.stderr)


def test_apk_filename_variant_apk_hashes_yml_also_strict(tmp_path):
    """apk-hashes.yml is reserved per ioc-lookup-definitions.yml — same rule."""
    r = run_validator(tmp_path, "apk-hashes.yml", _apk_body(MD5))
    assert r.returncode == 1
    assert "likely MD5" in r.stderr


# ---------- cert-hashes.yml: SHA-256 OR SHA-1 accepted, MD5 rejected with clear hint ----------


def test_cert_sha256_accepted(tmp_path):
    r = run_validator(tmp_path, "cert-hashes.yml", _cert_body(SHA256))
    assert r.returncode == 0, r.stderr


def test_cert_sha1_accepted(tmp_path):
    r = run_validator(tmp_path, "cert-hashes.yml", _cert_body(SHA1))
    assert r.returncode == 0, r.stderr


def test_cert_md5_rejected_with_named_hint(tmp_path):
    r = run_validator(tmp_path, "cert-hashes.yml", _cert_body(MD5))
    assert r.returncode == 1
    assert "likely MD5" in r.stderr
    assert "cert-hashes.yml accepts SHA-256 or SHA-1 only" in r.stderr


def test_cert_tlsh_rejected(tmp_path):
    r = run_validator(tmp_path, "cert-hashes.yml", _cert_body("a" * 72))
    assert r.returncode == 1
    assert "TLSH" in r.stderr or "72 hex" in r.stderr


# ---------- No regressions on non-hash files ----------


def test_package_names_yml_unaffected(tmp_path):
    """package-names.yml stores PACKAGE_NAME strings, not hashes — the new
    APK-hash format check must NOT fire on this file."""
    body = textwrap.dedent("""
        version: "2026-04-16"
        description: "test"
        sources: [stalkerware-indicators]
        entries:
          - indicator: com.dogfood.monitor
            family: DogfoodSpy
            category: STALKERWARE
            severity: CRITICAL
            source: stalkerware-indicators
            reference: feed:stalkerware-indicators#DogfoodSpy
    """).strip()
    r = run_validator(tmp_path, "package-names.yml", body)
    assert r.returncode == 0, r.stderr


def test_c2_domains_yml_unaffected(tmp_path):
    body = textwrap.dedent("""
        version: "2026-04-16"
        description: "test"
        sources: [threatfox]
        entries:
          - indicator: api.dogfood-telemetry.example
            family: DogfoodSpy
            category: MALWARE
            severity: CRITICAL
            source: threatfox
            reference: feed:stalkerware-indicators#DogfoodSpy
    """).strip()
    r = run_validator(tmp_path, "c2-domains.yml", body)
    assert r.returncode == 0, r.stderr


def _entry(**over):
    # Default family is not a campaign name: A5's family-to-campaign rule would otherwise demand a key.
    e = {"indicator": "evil.example", "family": "DogfoodSpy", "category": "NATION_STATE_SPYWARE",
         "severity": "CRITICAL", "source": "threat_research",
         "reference": "https://citizenlab.ca/2025/03/a-first-look-at-paragons-proliferating-spyware-operations/"}
    e.update(over)
    return e


def _body(entry):
    import yaml
    return yaml.safe_dump({"version": "x", "description": "t", "sources": [entry.get("source", "x")],
                           "entries": [{k: v for k, v in entry.items() if v is not None}]})


# Requires https://citizenlab.ca/ in threat_research's reference_prefixes (true
# once A3 lands: the Graphite entries cite Citizen Lab).
def test_valid_entry_passes(tmp_path):
    assert run_validator(tmp_path, "c2-domains.yml", _body(_entry())).returncode == 0


def test_missing_family_rejected(tmp_path):
    r = run_validator(tmp_path, "c2-domains.yml", _body(_entry(family=None)))
    assert r.returncode == 1 and "family" in r.stderr


def test_missing_reference_rejected(tmp_path):
    r = run_validator(tmp_path, "c2-domains.yml", _body(_entry(reference=None)))
    assert r.returncode == 1 and "reference" in r.stderr


def test_reference_prefix_not_allowed(tmp_path):
    r = run_validator(tmp_path, "c2-domains.yml", _body(_entry(reference="https://random-blog.example/x")))
    assert r.returncode == 1 and "prefix" in r.stderr


def test_other_sources_prefix_not_accepted(tmp_path):
    # A prefix allowed for a different source must not validate this entry.
    r = run_validator(tmp_path, "c2-domains.yml", _body(_entry(source="stalkerware-indicators")))
    assert r.returncode == 1 and "prefix" in r.stderr


def test_feed_reference_must_name_allowed_source(tmp_path):
    # family == fragment, so only the unknown-source check can fire (no section-token error).
    r = run_validator(tmp_path, "c2-domains.yml", _body(_entry(family="X", reference="feed:not-a-source#X")))
    assert r.returncode == 1 and "unknown source 'not-a-source'" in r.stderr


def test_unknown_campaign_rejected(tmp_path):
    r = run_validator(tmp_path, "c2-domains.yml", _body(_entry(campaign="notacampaign")))
    assert r.returncode == 1 and "campaign" in r.stderr


def test_known_campaign_accepted(tmp_path):
    # Family must name the campaign (A5's reverse rule); A4 doesn't enforce that yet, but the fixture
    # is already valid under it so the test stays green after A5 (round 10, R10-3).
    assert run_validator(tmp_path, "c2-domains.yml",
                         _body(_entry(family="Graphite (Paragon)", campaign="graphite"))).returncode == 0


def test_campaign_on_generic_source_rejected(tmp_path):
    r = run_validator(tmp_path, "c2-domains.yml", _body(_entry(source="threatfox", campaign="graphite",
                      reference="feed:threatfox#Graphite (Paragon)")))
    assert r.returncode == 1 and "campaign key on source" in r.stderr


def test_placeholder_shaped_domain_rejected(tmp_path):
    r = run_validator(tmp_path, "c2-domains.yml", _body(_entry(indicator="anubis-c2.net")))
    assert r.returncode == 1 and "placeholder" in r.stderr


def test_unpinned_or_traversing_reference_rejected(tmp_path):
    for ref in ["https://citizenlab.ca/2025/../x/", "https://citizenlab.ca/a%2Fb",
                "https://github.com/mvt-project/mvt-indicators/blob/abc1234/x"]:
        r = run_validator(tmp_path, "c2-domains.yml", _body(_entry(reference=ref)))
        assert r.returncode == 1, ref


def test_unpinned_code_host_prefix_rejected(tmp_path, monkeypatch):
    # load_reference_prefixes exits on a prefix prefix_problem() refuses (shared rule with the checker).
    import importlib.util, json, pytest
    spec = importlib.util.spec_from_file_location("vid", THIS_DIR / "validate-ioc-data.py")
    vid = importlib.util.module_from_spec(spec); spec.loader.exec_module(vid)
    bad = tmp_path / "s.json"
    bad.write_text(json.dumps([{"id": "x", "reference_prefixes": ["https://raw.githubusercontent.com/mvt-project/mvt-indicators/"]}]))
    with pytest.raises(SystemExit):
        vid.load_reference_prefixes(bad)


def test_cold_start_seed_only_in_package_names_with_mirror_feed_reference(tmp_path):
    ok = _entry(indicator="com.cocospy", family="Cocospy", category="STALKERWARE", source="stalkerware-indicators",
                reference="feed:stalkerware-indicators#Cocospy", cold_start_seed=True)
    assert run_validator(tmp_path, "package-names.yml", _body(ok)).returncode == 0
    r = run_validator(tmp_path, "c2-domains.yml", _body(_entry(cold_start_seed=True)))
    assert r.returncode == 1 and "cold_start_seed" in r.stderr
    https_ref = dict(ok, reference="https://citizenlab.ca/x/", source="threat_research")
    r = run_validator(tmp_path, "package-names.yml", _body(https_ref))
    assert r.returncode == 1 and "cold_start_seed" in r.stderr


# Added beside the brief's tests: Interfaces requires block_by_default outside c2-domains.yml to be rejected.
def test_block_by_default_only_in_c2_domains(tmp_path):
    assert run_validator(tmp_path, "c2-domains.yml", _body(_entry(block_by_default=True))).returncode == 0
    r = run_validator(tmp_path, "package-names.yml", _body(_entry(block_by_default=True)))
    assert r.returncode == 1 and "block_by_default" in r.stderr


# ---------- A4 fix round 1: one failing-first test per rule ----------

def test_denylisted_bare_host_prefix_rejected(tmp_path):
    # Rule: a reference_prefixes entry naming a denylisted host alone (no path) is refused at load.
    import importlib.util, json, pytest
    spec = importlib.util.spec_from_file_location("vid", THIS_DIR / "validate-ioc-data.py")
    vid = importlib.util.module_from_spec(spec); spec.loader.exec_module(vid)
    bad = tmp_path / "s.json"
    bad.write_text(json.dumps([{"id": "x", "reference_prefixes": ["https://medium.com/"]}]))
    with pytest.raises(SystemExit) as exc:
        vid.load_reference_prefixes(bad)
    assert "bare multi-tenant host" in str(exc.value.code)


SECTION_REF = "feed:amnesty-investigations#2021-10-07_donot"
SECTION_FAM = "Donot Team"
SECTION_IND = "accounts.dogfood.example"
SECTION_LINE = "c2-domains.yml\t" + SECTION_IND + "\t" + SECTION_REF + "\t" + SECTION_FAM


def _section_body(campaign=None):
    e = _entry(indicator=SECTION_IND, family=SECTION_FAM, category="SPYWARE", severity="HIGH",
               source="amnesty-investigations", reference=SECTION_REF)
    if campaign is not None:
        e["campaign"] = campaign
    return _body(e)


def _tokens_env(tmp_path, line=None):
    # Points the validator at a scratch approval file (SECTION_TOKENS_FILE); the real file is untouched.
    f = tmp_path / "tokens.txt"
    f.write_text("" if line is None else line + "\n")
    return {**os.environ, "SECTION_TOKENS_FILE": str(f)}


def test_section_citation_without_approval_rejected(tmp_path):
    r = run_validator(tmp_path, "c2-domains.yml", _section_body(), env=_tokens_env(tmp_path))
    assert r.returncode == 1
    assert "needs an owner-approved line in validation/feed-section-tokens.txt" in r.stderr


def test_section_citation_with_approval_accepted(tmp_path):
    r = run_validator(tmp_path, "c2-domains.yml", _section_body(), env=_tokens_env(tmp_path, SECTION_LINE))
    assert r.returncode == 0, r.stderr


def test_approved_section_citation_with_campaign_rejected(tmp_path):
    r = run_validator(tmp_path, "c2-domains.yml", _section_body(campaign="pegasus"),
                      env=_tokens_env(tmp_path, SECTION_LINE))
    assert r.returncode == 1
    assert "a section-cited entry may not carry a campaign key" in r.stderr


def test_not_campaign_rules(tmp_path):
    thief = _entry(indicator="thief.example", family="Predator The Thief", source="threatfox",
                   reference="feed:threatfox#Predator The Thief", not_campaign=True)
    r = run_validator(tmp_path, "c2-domains.yml", _body(thief))
    assert r.returncode == 1 and "not-campaign.txt" in r.stderr          # needs owner approval
    exact = dict(thief, family="Pegasus", reference="feed:threatfox#Pegasus")
    r = run_validator(tmp_path, "c2-domains.yml", _body(exact))
    assert r.returncode == 1 and "IS a campaign name" in r.stderr
    dotted = dict(thief, family="Pegasus.", reference="feed:threatfox#Pegasus.")
    assert "IS a campaign name" in run_validator(tmp_path, "c2-domains.yml", _body(dotted)).stderr
    keyed = dict(thief, campaign="predator")
    assert "may not carry a campaign key" in run_validator(tmp_path, "c2-domains.yml", _body(keyed)).stderr


def test_not_campaign_approved_entry_passes(tmp_path):
    # An approved line lets a distinct homonym family through without a key (round 14, R14-7).
    approvals = tmp_path / "not-campaign.txt"   # never the checked-in file (round 15, R15-6)
    approvals.write_text("c2-domains.yml\tthief.example\tfeed:threatfox#Predator The Thief\tPredator The Thief\n")
    ok = _entry(indicator="thief.example", family="Predator The Thief", source="threatfox",
                reference="feed:threatfox#Predator The Thief", not_campaign=True)
    env = dict(os.environ, NOT_CAMPAIGN_FILE=str(approvals))
    assert run_validator(tmp_path, "c2-domains.yml", _body(ok), env=env).returncode == 0


def test_campaign_family_without_key_rejected(tmp_path):
    r = run_validator(tmp_path, "c2-domains.yml", _body(_entry(family="Midnight Mimosa")))
    assert r.returncode == 1 and "midnight-mimosa" in r.stderr
    ok = _entry(family="Midnight Mimosa", campaign="midnight-mimosa")
    assert run_validator(tmp_path, "c2-domains.yml", _body(ok)).returncode == 0
    alias = _entry(family="Intellexa")
    assert "predator" in run_validator(tmp_path, "c2-domains.yml", _body(alias)).stderr
    wrong = _entry(family="2021-10-07_donot", source="amnesty-investigations",
                   reference="feed:amnesty-investigations#2021-10-07_donot", campaign="pegasus")
    r = run_validator(tmp_path, "c2-domains.yml", _body(wrong))
    assert r.returncode == 1 and "requires a family naming that campaign" in r.stderr
    generic = _entry(family="Predator", source="threatfox", reference="feed:threatfox#Predator")
    r = run_validator(tmp_path, "c2-domains.yml", _body(generic))
    assert r.returncode == 1 and "re-source it as threat_research" in r.stderr
