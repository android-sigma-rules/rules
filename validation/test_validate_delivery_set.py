"""Tests for validate-delivery-set.py — the cross-file gate on rules.txt.

Run:
    python3 -m pytest validation/test_validate_delivery_set.py -v
"""
import pathlib
import shutil
import subprocess
import sys

THIS_DIR = pathlib.Path(__file__).parent
REPO = THIS_DIR.parent
SCRIPT = THIS_DIR / "validate-delivery-set.py"


def run_on(repo_root):
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--repo-root", str(repo_root)],
        capture_output=True, text=True,
    )


def make_repo(tmp_path, entries, files=None):
    """Build a minimal repo: rules.txt + rule files with given ids."""
    (tmp_path / "rules.txt").write_text("\n".join(entries) + "\n")
    for relpath, rule_id in (files or {}).items():
        p = tmp_path / relpath
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(f"title: t\nid: {rule_id}\nstatus: production\n")
    return tmp_path


def test_real_repo_delivery_set_passes():
    result = run_on(REPO)
    assert result.returncode == 0, result.stderr


def test_staging_path_rejected(tmp_path):
    repo = make_repo(
        tmp_path,
        ["staging/process_monitor/androdr_030_spyware_process.yml"],
        {"staging/process_monitor/androdr_030_spyware_process.yml": "androdr-030"},
    )
    result = run_on(repo)
    assert result.returncode == 1
    assert "never deliverable" in result.stderr


def test_correlation_path_rejected(tmp_path):
    repo = make_repo(
        tmp_path,
        ["correlation/androdr_corr_001_install_then_admin.yml"],
        {"correlation/androdr_corr_001_install_then_admin.yml": "androdr-corr-001"},
    )
    result = run_on(repo)
    assert result.returncode == 1
    assert "never deliverable" in result.stderr


def test_missing_file_rejected(tmp_path):
    repo = make_repo(tmp_path, ["app_scanner/androdr_001_package_ioc.yml"])
    result = run_on(repo)
    assert result.returncode == 1
    assert "does not exist" in result.stderr


def test_id_filename_mismatch_rejected(tmp_path):
    # The shadowing vector: a "new" file whose declared id hijacks an
    # existing rule (on-device merge is last-wins by id).
    repo = make_repo(
        tmp_path,
        ["app_scanner/androdr_099_innocent_name.yml"],
        {"app_scanner/androdr_099_innocent_name.yml": "androdr-016"},
    )
    result = run_on(repo)
    assert result.returncode == 1
    assert "filename promises androdr-099" in result.stderr


def test_duplicate_id_rejected(tmp_path):
    repo = make_repo(
        tmp_path,
        ["app_scanner/androdr_001_package_ioc.yml", "dns_monitor/androdr_001_domain_thing.yml"],
        {
            "app_scanner/androdr_001_package_ioc.yml": "androdr-001",
            "dns_monitor/androdr_001_domain_thing.yml": "androdr-001",
        },
    )
    result = run_on(repo)
    assert result.returncode == 1
    assert "duplicates" in result.stderr


def test_duplicate_basename_rejected(tmp_path):
    repo = make_repo(
        tmp_path,
        ["app_scanner/androdr_001_package_ioc.yml", "dns_monitor/androdr_001_package_ioc.yml"],
        {
            "app_scanner/androdr_001_package_ioc.yml": "androdr-001",
            "dns_monitor/androdr_001_package_ioc.yml": "androdr-003",
        },
    )
    result = run_on(repo)
    assert result.returncode == 1
    assert "collides" in result.stderr


def test_atom_naming_consistency_enforced(tmp_path):
    repo = make_repo(
        tmp_path,
        ["timeline/androdr_atom_app_launch.yml"],
        {"timeline/androdr_atom_app_launch.yml": "androdr-atom-dns-lookup"},
    )
    result = run_on(repo)
    assert result.returncode == 1
    assert "filename promises androdr-atom-app-launch" in result.stderr
