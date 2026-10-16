#!/usr/bin/env python3
"""ioc-data domains listed by a compiled MVT collection must carry that collection's campaign key.

Usage: check-mvt-campaign-keys.py [--stix-dir DIR] [ioc-data/c2-domains.yml]
Without --stix-dir the two STIX files are fetched from the exact URLs in mvt-campaign-map.json.
"""
import argparse, json, pathlib, re, sys, urllib.request
import yaml

HERE = pathlib.Path(__file__).parent
DOMAIN = re.compile(r"domain-name:value\s*=\s*'([^']+)'")


def load_map():
    return json.loads((HERE / "mvt-campaign-map.json").read_text())


def _stix(entry, stix_dir):
    if stix_dir:
        return (pathlib.Path(stix_dir) / (entry["key"] + ".stix2")).read_text()
    with urllib.request.urlopen(entry["url"], timeout=60) as r:   # fixed URLs from the reviewed map
        return r.read(20_000_000).decode("utf-8", errors="ignore")


def problems(c2_file, mapping, stix_dir=None):
    entries = (yaml.safe_load(pathlib.Path(c2_file).read_text()) or {}).get("entries", [])
    out = []
    for m in mapping:
        listed = {d.lower() for o in json.loads(_stix(m, stix_dir)).get("objects", [])
                  if o.get("type") == "indicator" for d in DOMAIN.findall(o.get("pattern", ""))}
        for e in entries:
            ind = str(e.get("indicator", "")).lower()
            if ind in listed and e.get("campaign") != m["key"]:
                out.append(f"{ind} is in MVT collection '{m['name']}' but has no `campaign: {m['key']}`")
    return out


INDEX_URL = "https://raw.githubusercontent.com/mvt-project/mvt-indicators/main/indicators.yaml"


def map_drift(mapping, index_yaml):
    """Map tuples MVT's indicators.yaml no longer lists (renamed or moved collection)."""
    listed = set()
    for i in (yaml.safe_load(index_yaml) or {}).get("indicators", []) or []:
        g = i.get("github") or {}
        if i.get("type") == "github" and all(g.get(k) for k in ("owner", "repo", "branch", "path")):
            listed.add((i.get("name"), f"https://raw.githubusercontent.com/{g['owner']}/{g['repo']}/{g['branch']}/{g['path']}"))
    return [f"MVT no longer lists '{m['name']}' at {m['url']}" for m in mapping if (m["name"], m["url"]) not in listed]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file", nargs="?", default=str(HERE.parent / "ioc-data" / "c2-domains.yml"))
    ap.add_argument("--stix-dir")
    ap.add_argument("--check-map", action="store_true", help="only check the map against MVT's live index")
    a = ap.parse_args()
    if a.check_map:
        with urllib.request.urlopen(INDEX_URL, timeout=60) as r:
            ps = map_drift(load_map(), r.read(5_000_000).decode("utf-8", errors="ignore"))
        for p in ps:
            print(f"::error::{p} — re-review and update validation/mvt-campaign-map.json and AndroDR MvtCampaigns")
        sys.exit(1 if ps else 0)
    ps = problems(a.file, load_map(), a.stix_dir)
    for p in ps:
        print(f"::error::{p}")
    sys.exit(1 if ps else 0)


if __name__ == "__main__":
    main()
