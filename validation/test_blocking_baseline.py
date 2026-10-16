"""The domains blocked by default are exactly the reviewed baseline (Task A4).

Any intended change to the blocking set edits validation/blocked-baseline.txt and
ioc-data/c2-domains.yml in the same reviewed PR; an accidental change fails here.
"""
import pathlib

import yaml

THIS_DIR = pathlib.Path(__file__).parent


def test_block_by_default_set_equals_baseline():
    data = yaml.safe_load((THIS_DIR.parent / "ioc-data" / "c2-domains.yml").read_text()) or {}
    blocked = {str(e["indicator"]).lower() for e in data.get("entries", []) or [] if e.get("block_by_default") is True}
    baseline = {l.strip().lower() for l in (THIS_DIR / "blocked-baseline.txt").read_text().split("\n")
                if l.strip() and not l.startswith("#")}
    assert blocked == baseline, {"extra": sorted(blocked - baseline)[:20], "missing": sorted(baseline - blocked)[:20]}
