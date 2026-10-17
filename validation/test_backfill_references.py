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


def test_backfill_passes_entry_family_to_check(tmp_path, monkeypatch):
    seen = {}

    def fake_check(indicator, reference, feed_dir, *args, **kwargs):
        seen.update(kwargs)
        return "FOUND", ""

    monkeypatch.setattr(bf.cr, "check", fake_check)
    yml = tmp_path / "package-names.yml"
    yml.write_text("entries:\n- indicator: com.pegasus.example\n  family: Pegasus\n"
                   "  category: SPYWARE\n  severity: CRITICAL\n  source: stalkerware-indicators\n")
    bf.backfill_file(yml, tmp_path, write=False)
    assert seen.get("family") == "Pegasus"


SNIPPET_SCRIPT = pathlib.Path(THIS_DIR.parent / "scripts" / "fetch-feed-dumps.sh")


def _malwarebazaar_snippet():
    lines = SNIPPET_SCRIPT.read_text().split("\n")
    start = next(i for i, line in enumerate(lines) if line.rstrip().endswith("<<'PY'"))
    end = next(i for i in range(start + 1, len(lines)) if lines[i] == "PY")
    return "\n".join(lines[start + 1:end]) + "\n"


def test_malwarebazaar_snippet_warns_and_writes_header_only_without_key(tmp_path):
    import os, subprocess, sys
    repo = tmp_path / "repo"
    (repo / "ioc-data").mkdir(parents=True)
    (repo / "ioc-data" / "malware-hashes.yml").write_text(
        "entries:\n- indicator: 0123456789abcdef0123456789abcdef\n  family: Pegasus\n"
        "  category: SPYWARE\n  severity: CRITICAL\n  source: malwarebazaar\n")
    out = tmp_path / "malwarebazaar.txt"
    env = {k: v for k, v in os.environ.items() if k != "MALWAREBAZAAR_API_KEY"}
    sys.path.insert(0, str(THIS_DIR))
    import mb_hashes
    hashes = tmp_path / "mb-hashes.txt"
    hashes.write_text("\n".join(mb_hashes.collect_mb_hashes(repo)))
    proc = subprocess.run([sys.executable, "-I", "-", str(out), str(hashes)], input=_malwarebazaar_snippet(),
                          capture_output=True, text=True, env=env, timeout=60)
    assert proc.returncode == 0, proc.stderr
    assert "MALWAREBAZAAR_API_KEY not set" in proc.stderr
    assert out.read_text() == "## malwarebazaar/get_info.jsonl\n"
