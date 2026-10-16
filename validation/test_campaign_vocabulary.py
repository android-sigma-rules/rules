"""Rule campaign tags and IOC campaign values must come from campaigns.yml."""
import pathlib, yaml
ROOT = pathlib.Path(__file__).parent.parent


def keys():
    return {c["key"] for c in yaml.safe_load((ROOT / "ioc-data" / "campaigns.yml").read_text())["campaigns"]}


def test_keys_unique_and_well_formed():
    ks = [c["key"] for c in yaml.safe_load((ROOT / "ioc-data" / "campaigns.yml").read_text())["campaigns"]]
    assert len(ks) == len(set(ks))
    import re
    assert all(re.fullmatch(r"[a-z0-9_-]{1,32}", k) for k in ks)


def names():
    out = set()
    for c in yaml.safe_load((ROOT / "ioc-data" / "campaigns.yml").read_text())["campaigns"]:
        out.add(c["key"]); out.update(c.get("aliases", []))
    return out


def test_names_do_not_collide_after_normalisation():
    # keys, labels and aliases as campaign_names() sees them (round 12, S12-4)
    import importlib.util
    spec = importlib.util.spec_from_file_location("cr", ROOT / "validation" / "check-reference.py")
    cr = importlib.util.module_from_spec(spec); spec.loader.exec_module(cr)
    cs = yaml.safe_load((ROOT / "ioc-data" / "campaigns.yml").read_text())["campaigns"]
    seen = {}
    for c in cs:
        for n in {cr.norm_name(x) for x in [c["key"], c.get("label", "")] + list(c.get("aliases", [])) if x}:
            assert seen.setdefault(n, c["key"]) == c["key"], f"'{n}' names both {seen[n]} and {c['key']}"


def test_rule_campaign_tags_are_in_vocabulary():
    missing = []
    for rel in (ROOT / "rules.txt").read_text().split():
        if rel.endswith(".yml"):
            for t in (yaml.safe_load((ROOT / rel).read_text()) or {}).get("tags", []) or []:
                if str(t).startswith("campaign.") and str(t)[9:] not in names():
                    missing.append((rel, t))
    assert not missing, missing


def test_every_campaign_has_label_and_https_references():
    # The report row label and its provenance come from here (AndroDR Plan B, Task B7).
    for c in yaml.safe_load((ROOT / "ioc-data" / "campaigns.yml").read_text())["campaigns"]:
        assert isinstance(c.get("label"), str) and c["label"].strip(), f"{c['key']}: missing label"
        refs = c.get("references")
        assert isinstance(refs, list) and refs, f"{c['key']}: needs at least one reference"
        assert all(isinstance(r, str) and r.startswith("https://") for r in refs), f"{c['key']}: {refs}"
