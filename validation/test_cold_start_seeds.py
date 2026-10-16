import pathlib, yaml
ROOT = pathlib.Path(__file__).parent.parent


def test_cold_start_seeds_are_exactly_the_frozen_list():
    entries = yaml.safe_load((ROOT / "ioc-data" / "package-names.yml").read_text())["entries"]
    marked = sorted(str(e["indicator"]).lower() for e in entries if e.get("cold_start_seed") is True)
    frozen = sorted(l.strip() for l in (ROOT / "validation" / "cold-start-seeds.txt").read_text().split("\n")
                    if l.strip() and not l.startswith("#"))
    assert marked == frozen
