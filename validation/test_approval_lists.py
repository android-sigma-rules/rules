"""Owner-approved lines must match a live ioc-data entry exactly (Task A4, round 14).

A stale approval line must not silently re-approve an entry that was later re-added with other content.
"""
import pathlib
import re

import yaml

THIS_DIR = pathlib.Path(__file__).parent
IOC_DIR = THIS_DIR.parent / "ioc-data"
FEED_REF = re.compile(r"^feed:([a-z0-9_-]+)#(.+)$")


def _lines(name):
    out = []
    for l in (THIS_DIR / name).read_text().split("\n"):
        if l.strip() and not l.startswith("#"):
            fn, ind, ref, fam = (l.split("\t") + ["", "", "", ""])[:4]
            out.append((fn, ind.strip(), ref.strip(), fam.strip()))
    return out


def _entries(fn):
    return (yaml.safe_load((IOC_DIR / fn).read_text()) or {}).get("entries", []) or []


def test_section_tokens_match_entries_exactly():
    problems = []
    for fn, ind, ref, fam in _lines("feed-section-tokens.txt"):
        match = [e for e in _entries(fn) if str(e.get("indicator", "")).lower() == ind.lower()
                 and e.get("reference") == ref and e.get("family") == fam]
        if not match:
            problems.append(f"{fn}\t{ind}\t{ref}\t{fam}: no entry with that indicator, reference and family")
            continue
        m = FEED_REF.match(ref)
        if not m or m.group(2) == fam or match[0].get("campaign") is not None:
            problems.append(f"{fn}\t{ind}: entry is not a campaign-free section citation")
    assert problems == []


def test_not_campaign_lines_match_entries_exactly():
    problems = []
    for fn, ind, ref, fam in _lines("not-campaign.txt"):
        match = [e for e in _entries(fn) if str(e.get("indicator", "")).lower() == ind.lower()
                 and e.get("reference") == ref and e.get("family") == fam and e.get("not_campaign") is True]
        if not match:
            problems.append(f"{fn}\t{ind}\t{ref}\t{fam}: no entry with not_campaign: true for it")
    assert problems == []
