"""Unit tests for validate-ioc-complementarity.py.

Run: python3 -m pytest validation/test_validate_ioc_complementarity.py -v
"""
import pathlib
import subprocess
import sys
import textwrap

THIS_DIR = pathlib.Path(__file__).parent
SCRIPT = THIS_DIR / "validate-ioc-complementarity.py"


def run_script(args, env=None):
    return subprocess.run(
        [sys.executable, str(SCRIPT)] + args,
        capture_output=True, text=True, env=env,
    )


def test_script_exists():
    assert SCRIPT.exists(), f"expected script at {SCRIPT}"


def test_exits_nonzero_when_entry_is_in_upstream_snapshot(tmp_path):
    # Offline mode: provide an explicit upstream snapshot rather than
    # fetching from the network. A real fetch is tested separately.
    upstream_snapshot = tmp_path / "upstream.txt"
    upstream_snapshot.write_text("PACKAGE_NAME\tcom.bad.example\n")

    ioc_file = tmp_path / "package-names.yml"
    ioc_file.write_text(textwrap.dedent("""
        version: "2026-04-16"
        description: "test"
        entries:
          - indicator: com.bad.example
            category: STALKERWARE
            severity: CRITICAL
            source: stalkerware-indicators
    """).strip())

    result = run_script([
        "--offline-snapshot", str(upstream_snapshot),
        "--file", str(ioc_file),
        "--mode", "strict",
    ])
    assert result.returncode != 0, result.stdout + result.stderr
    assert "com.bad.example" in (result.stdout + result.stderr)


def test_exits_zero_when_entry_not_in_upstream(tmp_path):
    upstream_snapshot = tmp_path / "upstream.txt"
    upstream_snapshot.write_text("PACKAGE_NAME\tcom.other.app\n")

    ioc_file = tmp_path / "package-names.yml"
    ioc_file.write_text(textwrap.dedent("""
        version: "2026-04-16"
        description: "test"
        entries:
          - indicator: com.unique.entry
            category: STALKERWARE
            severity: CRITICAL
            source: amnesty-investigations
    """).strip())

    result = run_script([
        "--offline-snapshot", str(upstream_snapshot),
        "--file", str(ioc_file),
        "--mode", "strict",
    ])
    assert result.returncode == 0, result.stdout + result.stderr


def test_parser_limited_feed_is_skipped_with_warning(tmp_path):
    """A feed tagged `parser_limited: true` must be skipped entirely (no fetch)
    and produce a loud WARNING on stderr so silent rot of the complementarity
    invariant against that feed is impossible to miss."""

    # All feeds in this mirror-feeds.yml are parser-limited, so no network
    # fetch is attempted by the validator (test must work offline).
    mirror_feeds = tmp_path / "mirror-feeds.yml"
    mirror_feeds.write_text(textwrap.dedent("""
        version: 1
        feeds:
          - id: bogus-feed
            url: https://example.invalid/nope
            parser: threatfox-json
            types: [C2_DOMAIN]
            parser_limited: true
            parser_limited_reason: "test fixture — never reached"
    """).strip())

    # An ioc-data entry that would NOT trip on its own (no real upstream
    # snapshot to dedup against). We're only checking the skip behavior.
    ioc_file = tmp_path / "c2-domains.yml"
    ioc_file.write_text(textwrap.dedent("""
        version: "2026-04-16"
        description: "test"
        entries:
          - indicator: example.com
            family: TEST_FAMILY
            category: C2
            severity: CRITICAL
            source: threat_research
    """).strip())

    result = run_script([
        "--mirror-feeds", str(mirror_feeds),
        "--file", str(ioc_file),
        "--mode", "strict",
    ])

    # The entry isn't in any (empty, since skipped) upstream snapshot, so
    # strict mode exits 0.
    assert result.returncode == 0, result.stdout + result.stderr

    # But the validator MUST have logged the SKIP warning for the
    # parser-limited feed.
    combined = result.stdout + result.stderr
    assert "SKIP parser-limited feed 'bogus-feed'" in combined, combined
    assert "complementarity against this feed is NOT enforced" in combined, combined


def test_parser_limited_non_bool_value_is_rejected(tmp_path):
    """A typo like `parser_limited: "true"` (string) or `parser_limited: 1`
    must be rejected with sys.exit(2). Silently falling through to a fetch
    would re-introduce the exact silent-skip rot the flag exists to prevent."""

    mirror_feeds = tmp_path / "mirror-feeds.yml"
    mirror_feeds.write_text(textwrap.dedent("""
        version: 1
        feeds:
          - id: typo-feed
            url: https://example.invalid/nope
            parser: threatfox-json
            types: [C2_DOMAIN]
            parser_limited: "true"
            parser_limited_reason: "string typo, not a YAML bool"
    """).strip())

    ioc_file = tmp_path / "c2-domains.yml"
    ioc_file.write_text(textwrap.dedent("""
        version: "2026-04-16"
        description: "test"
        entries: []
    """).strip())

    result = run_script([
        "--mirror-feeds", str(mirror_feeds),
        "--file", str(ioc_file),
        "--mode", "strict",
    ])

    assert result.returncode == 2, result.stdout + result.stderr
    combined = result.stdout + result.stderr
    assert "must be a YAML boolean" in combined, combined


def test_intermixed_working_and_skipped_feeds(tmp_path):
    """Loop must `continue` past a skipped feed and still fetch+parse the
    next working feed. Locks in the real config's mixed-feed pattern
    (stalkerware works, mvt+threatfox are parser_limited)."""

    # Two feeds: a parser_limited one (skipped) and a stalkerware-yaml one
    # backed by a local file:// URL that the real parser can consume.
    stalkerware_file = tmp_path / "stalkerware.yaml"
    stalkerware_file.write_text(textwrap.dedent("""
        - name: TestSpy
          type: stalkerware
          packages:
            - com.upstream.bypass
    """).strip())

    mirror_feeds = tmp_path / "mirror-feeds.yml"
    mirror_feeds.write_text(textwrap.dedent(f"""
        version: 1
        feeds:
          - id: skipped-feed
            url: https://example.invalid/nope
            parser: threatfox-json
            types: [C2_DOMAIN]
            parser_limited: true
            parser_limited_reason: "intermixed test fixture"
          - id: working-feed
            url: file://{stalkerware_file}
            parser: stalkerware-yaml
            types: [PACKAGE_NAME]
    """).strip())

    # ioc-data entry that DUPLICATES the working feed's entry — must fail
    # strict mode, proving the loop continued to the working feed.
    ioc_file = tmp_path / "package-names.yml"
    ioc_file.write_text(textwrap.dedent("""
        version: "2026-04-16"
        description: "test"
        entries:
          - indicator: com.upstream.bypass
            category: STALKERWARE
            severity: CRITICAL
            source: stalkerware-indicators
    """).strip())

    result = run_script([
        "--mirror-feeds", str(mirror_feeds),
        "--file", str(ioc_file),
        "--mode", "strict",
    ])

    combined = result.stdout + result.stderr
    # The working feed must have been fetched (entry detected as duplicate)
    assert result.returncode != 0, combined
    assert "com.upstream.bypass" in combined, combined
    # And the skipped one must have produced its SKIP warning
    assert "SKIP parser-limited feed 'skipped-feed'" in combined, combined


def test_parser_limited_feed_does_not_attempt_fetch(tmp_path):
    """Regression guard: even if the URL is unreachable, a parser_limited
    feed must NOT fail the validator. The skip happens before the fetch."""

    mirror_feeds = tmp_path / "mirror-feeds.yml"
    mirror_feeds.write_text(textwrap.dedent("""
        version: 1
        feeds:
          - id: unreachable-feed
            url: http://127.0.0.1:1/definitely-not-listening
            parser: threatfox-json
            types: [C2_DOMAIN]
            parser_limited: true
            parser_limited_reason: "should never be fetched"
    """).strip())

    ioc_file = tmp_path / "c2-domains.yml"
    ioc_file.write_text(textwrap.dedent("""
        version: "2026-04-16"
        description: "test"
        entries: []
    """).strip())

    # No --allow-upstream-unreachable: a real fetch attempt would exit 2.
    result = run_script([
        "--mirror-feeds", str(mirror_feeds),
        "--file", str(ioc_file),
        "--mode", "strict",
    ])
    assert result.returncode == 0, result.stdout + result.stderr


def test_advisory_mode_reports_but_does_not_fail(tmp_path):
    upstream_snapshot = tmp_path / "upstream.txt"
    upstream_snapshot.write_text("PACKAGE_NAME\tcom.bad.example\n")

    ioc_file = tmp_path / "package-names.yml"
    ioc_file.write_text(textwrap.dedent("""
        version: "2026-04-16"
        description: "test"
        entries:
          - indicator: com.bad.example
            category: STALKERWARE
            severity: CRITICAL
            source: stalkerware-indicators
    """).strip())

    result = run_script([
        "--offline-snapshot", str(upstream_snapshot),
        "--file", str(ioc_file),
        "--mode", "advisory",
    ])
    assert result.returncode == 0, result.stdout + result.stderr
    assert "WARN" in (result.stdout + result.stderr) or "advisory" in (result.stdout + result.stderr).lower()
