"""campaigns.yml `detected_by`: the rule services that can make each campaign DETECTED (AndroDR #394).

The app renders "fully checked / not checked, and why" per campaign from this list plus what the
scan stored, so the list must be exactly what the shipped rules and ioc-data can detect: derived
here from rules.txt rules, ioc-data campaign values and the MVT map, and compared both ways.
"""
import json
import pathlib
import textwrap

import yaml

ROOT = pathlib.Path(__file__).parent.parent
# ioc-data file -> the ioc_lookup that reads it on the device
LOOKUP_FOR_FILE = {
    "c2-domains.yml": "domain_ioc_db",
    "package-names.yml": "package_ioc_db",
    "cert-hashes.yml": "cert_hash_ioc_db",
    "malware-hashes.yml": "apk_hash_ioc_db",
}


def _load(path):
    return yaml.safe_load(path.read_text()) or {}


def _selections(detection):
    for name, sel in (detection or {}).items():
        if name == "condition":
            continue
        for item in (sel if isinstance(sel, list) else [sel]):
            if isinstance(item, dict):
                yield item


def _ioc_lookups(rule):
    out = set()
    for sel in _selections(rule.get("detection")):
        for field, value in sel.items():
            if str(field).endswith("|ioc_lookup"):
                out.update(value if isinstance(value, list) else [value])
    return out


def derive(root):
    """{campaign key: sorted services} the shipped rules and ioc-data can detect it with."""
    camps = _load(root / "ioc-data" / "campaigns.yml").get("campaigns", [])
    key_by_name = {c["key"]: c["key"] for c in camps}
    for c in camps:
        for alias in c.get("aliases") or []:
            key_by_name.setdefault(str(alias).lower(), c["key"])
    out = {c["key"]: set() for c in camps}
    lookup_services = {}
    for rel in (root / "rules.txt").read_text().split():
        if not rel.endswith(".yml"):
            continue
        rule = _load(root / rel)
        service = (rule.get("logsource") or {}).get("service")
        if rule.get("category") != "device_posture":   # patch level is EXPOSED, never DETECTED
            for tag in rule.get("tags") or []:
                tag = str(tag)
                if tag.startswith("campaign.") and tag[len("campaign."):].lower() in key_by_name:
                    out[key_by_name[tag[len("campaign."):].lower()]].add(service)
        if (rule.get("display") or {}).get("evidence_type") == "ioc_match":   # only these carry a campaign
            for name in _ioc_lookups(rule):
                lookup_services.setdefault(name, set()).add(service)
    for fname, lookup in LOOKUP_FOR_FILE.items():
        path = root / "ioc-data" / fname
        if not path.is_file():
            continue
        for entry in _load(path).get("entries") or []:
            if entry.get("campaign") in out:
                out[entry["campaign"]].update(lookup_services.get(lookup, set()))
    mvt = root / "validation" / "mvt-campaign-map.json"
    if mvt.is_file():   # MVT campaign attribution is domain-only
        for m in json.loads(mvt.read_text()):
            if m.get("key") in out:
                out[m["key"]].update(lookup_services.get("domain_ioc_db", set()))
    return {k: sorted(v) for k, v in out.items()}


def mismatches(root):
    declared = {c["key"]: c.get("detected_by")
                for c in _load(root / "ioc-data" / "campaigns.yml").get("campaigns", [])}
    derived = derive(root)
    return [f"{k}: declared {declared[k]} but the rules and ioc-data give {derived[k]}"
            for k in sorted(derived) if declared[k] != derived[k]]


def test_detected_by_matches_what_the_rules_can_detect():
    assert not mismatches(ROOT), "\n".join(mismatches(ROOT))


def test_detected_by_is_a_sorted_unique_list_of_taxonomy_services():
    services = set(_load(ROOT / "validation" / "logsource-taxonomy.yml")["services"])
    for c in _load(ROOT / "ioc-data" / "campaigns.yml")["campaigns"]:
        value = c.get("detected_by")
        assert isinstance(value, list), f"{c['key']}: detected_by must be a list ([] = patch level only)"
        assert value == sorted(set(value)), f"{c['key']}: detected_by must be sorted and unique: {value}"
        assert set(value) <= services, f"{c['key']}: not taxonomy services: {set(value) - services}"


# -- fixture repos: the gate fails on the mistakes it exists for ----------------------------------

IOC_RULE = """\
    title: t
    id: {id}
    tags: [attack.t1437]
    logsource: {{product: androdr, service: {service}}}
    detection:
        selection:
            {field}|ioc_lookup: {lookup}
        condition: selection
    category: incident
    display: {{evidence_type: {evidence}}}
"""


def mini(tmp_path, detected_by, rules=(), entries=None, mvt=()):
    (tmp_path / "ioc-data").mkdir()
    (tmp_path / "validation").mkdir()
    (tmp_path / "ioc-data" / "campaigns.yml").write_text(yaml.safe_dump({"campaigns": [
        {"key": "pegasus", "label": "Pegasus", "aliases": ["nso"], "detected_by": detected_by}]}))
    names = []
    for i, text in enumerate(rules):
        (tmp_path / f"r{i}.yml").write_text(textwrap.dedent(text))
        names.append(f"r{i}.yml")
    (tmp_path / "rules.txt").write_text("\n".join(names) + "\n")
    for fname, items in (entries or {}).items():
        (tmp_path / "ioc-data" / fname).write_text(yaml.safe_dump({"entries": items}))
    (tmp_path / "validation" / "mvt-campaign-map.json").write_text(json.dumps(list(mvt)))
    return tmp_path


def tagged_rule(service, category="incident", tag="campaign.pegasus"):
    return f"""\
    title: t
    id: androdr-900
    tags: [{tag}]
    logsource: {{product: androdr, service: {service}}}
    detection: {{selection: {{x: y}}, condition: selection}}
    category: {category}
"""


def test_a_new_tagged_rule_on_a_new_service_fails_until_declared(tmp_path):
    root = mini(tmp_path, [], rules=[tagged_rule("file_scanner")])
    assert mismatches(root) == ["pegasus: declared [] but the rules and ioc-data give ['file_scanner']"]


def test_an_overclaimed_service_fails(tmp_path):
    root = mini(tmp_path, ["dns_monitor"])
    assert mismatches(root) == ["pegasus: declared ['dns_monitor'] but the rules and ioc-data give []"]


def test_an_alias_tag_counts_and_a_patch_level_tag_does_not(tmp_path):
    root = mini(tmp_path, ["app_scanner"], rules=[
        tagged_rule("app_scanner", tag="campaign.nso"),
        tagged_rule("device_auditor", category="device_posture"),
    ])
    assert mismatches(root) == []


def test_campaign_iocs_count_only_through_an_ioc_match_rule(tmp_path):
    rules = [
        IOC_RULE.format(id="androdr-003", service="dns_monitor", field="domain",
                        lookup="domain_ioc_db", evidence="ioc_match"),
        IOC_RULE.format(id="androdr-004", service="app_scanner", field="apk_hash",
                        lookup="apk_hash_ioc_db", evidence="none"),
    ]
    entries = {"c2-domains.yml": [{"indicator": "a.example", "campaign": "pegasus"}],
               "malware-hashes.yml": [{"indicator": "a" * 64, "campaign": "pegasus"}]}
    assert derive(mini(tmp_path, ["dns_monitor"], rules=rules, entries=entries)) == {"pegasus": ["dns_monitor"]}


def test_mvt_campaigns_count_through_the_domain_lookup_rule(tmp_path):
    rules = [IOC_RULE.format(id="androdr-003", service="dns_monitor", field="domain",
                             lookup="domain_ioc_db", evidence="ioc_match")]
    root = mini(tmp_path, ["dns_monitor"], rules=rules, mvt=[{"name": "n", "url": "u", "key": "pegasus"}])
    assert mismatches(root) == []
