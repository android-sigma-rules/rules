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
