import importlib.util, pathlib, textwrap
THIS_DIR = pathlib.Path(__file__).parent
spec = importlib.util.spec_from_file_location("bf", THIS_DIR / "backfill-references.py")
bf = importlib.util.module_from_spec(spec); spec.loader.exec_module(bf)


def test_sets_reference_only_when_feed_confirms(tmp_path):
    feeds = tmp_path / "feeds"; feeds.mkdir()
    (feeds / "stalkerware-indicators.txt").write_text(
        "## stalkerware-indicators/ioc.yaml\n| - name: TheTruthSpy\n|   packages:\n|   - com.ttsapp\n")
    yml = tmp_path / "package-names.yml"
    yml.write_text(textwrap.dedent("""
        entries:
        - indicator: com.ttsapp
          family: TheTruthSpy
          category: STALKERWARE
          severity: CRITICAL
          source: stalkerware-indicators
        - indicator: com.thetruthspy
          family: TheTruthSpy
          category: STALKERWARE
          severity: CRITICAL
          source: stalkerware-indicators
    """).lstrip())
    review = bf.backfill_file(yml, feeds, write=True)
    text = yml.read_text()
    assert "reference: feed:stalkerware-indicators#TheTruthSpy" in text
    assert text.count("reference:") == 1
    assert [r["indicator"] for r in review] == ["com.thetruthspy"]


def test_threat_research_entries_go_to_review(tmp_path):
    yml = tmp_path / "c2-domains.yml"
    yml.write_text("entries:\n- indicator: evil.com\n  family: X\n  category: MALWARE\n"
                   "  severity: HIGH\n  source: threat_research\n")
    review = bf.backfill_file(yml, tmp_path, write=True)
    assert review[0]["status"] == "NEEDS_REPORT_URL"
    assert "reference:" not in yml.read_text()
