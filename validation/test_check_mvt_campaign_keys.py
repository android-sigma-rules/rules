import importlib.util, json, pathlib
THIS_DIR = pathlib.Path(__file__).parent
spec = importlib.util.spec_from_file_location("mck", THIS_DIR / "check-mvt-campaign-keys.py")
mck = importlib.util.module_from_spec(spec); spec.loader.exec_module(mck)

STIX = json.dumps({"objects": [{"type": "indicator", "pattern_type": "stix",
                                "pattern": "[domain-name:value = 'c2.pegasus.example']"}]})


def write(tmp_path, entries):
    (tmp_path / "stix").mkdir(exist_ok=True)
    (tmp_path / "stix" / "pegasus.stix2").write_text(STIX)
    (tmp_path / "stix" / "predator.stix2").write_text(json.dumps({"objects": []}))
    f = tmp_path / "c2-domains.yml"
    f.write_text("entries:\n" + "".join(
        f"- indicator: {i}\n  source: threat_research\n" + (f"  campaign: {c}\n" if c else "") for i, c in entries))
    return f


def test_mvt_listed_domain_without_key_fails(tmp_path):
    f = write(tmp_path, [("c2.pegasus.example", None)])
    assert mck.problems(f, mck.load_map(), stix_dir=tmp_path / "stix") == [
        "c2.pegasus.example is in MVT collection 'NSO Group Pegasus Indicators of Compromise' "
        "but has no `campaign: pegasus`"]


def test_mvt_listed_domain_with_wrong_key_fails(tmp_path):
    f = write(tmp_path, [("c2.pegasus.example", "predator")])
    assert len(mck.problems(f, mck.load_map(), stix_dir=tmp_path / "stix")) == 1


def test_matching_key_and_unlisted_domain_pass(tmp_path):
    f = write(tmp_path, [("c2.pegasus.example", "pegasus"), ("other.example", None)])
    assert mck.problems(f, mck.load_map(), stix_dir=tmp_path / "stix") == []


INDEX = """indicators:
  - type: github
    name: NSO Group Pegasus Indicators of Compromise
    github:
      owner: AmnestyTech
      repo: investigations
      branch: master
      path: 2021-07-18_nso/pegasus.stix2
  - type: github
    name: Predator Spyware Indicators of Compromise
    github:
      owner: mvt-project
      repo: mvt-indicators
      branch: main
      path: intellexa_predator/predator.stix2
"""


def test_map_drift_detected():
    assert mck.map_drift(mck.load_map(), INDEX) == []
    moved = INDEX.replace("branch: master", "branch: main")
    assert mck.map_drift(mck.load_map(), moved) == [
        "MVT no longer lists 'NSO Group Pegasus Indicators of Compromise' at "
        "https://raw.githubusercontent.com/AmnestyTech/investigations/master/2021-07-18_nso/pegasus.stix2"]
