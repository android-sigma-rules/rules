"""Tests for the candidate-accuracy lints in validate-rule.py (AndroDR pipeline
candidate-accuracy spec, 2026-06-10): retired-ID registry, device-posture
severity cap, lone-exploited-CVE rejection, plus a regression sweep over all
existing rules.

Run:
    python3 -m pytest validation/test_validate_rule_lints.py -v
"""
import copy
import pathlib
import subprocess
import sys

import yaml

THIS_DIR = pathlib.Path(__file__).parent
REPO = THIS_DIR.parent
SCRIPT = THIS_DIR / "validate-rule.py"

# A known-good production posture rule is the mutation baseline — guarantees
# the unmodified parts always satisfy the schema.
BASE = yaml.safe_load(
    (REPO / "device_auditor" / "androdr_044_stale_patch.yml").read_text()
)


def run_validator_on(tmp_path, rule: dict):
    p = tmp_path / "rule.yml"
    p.write_text(yaml.safe_dump(rule, sort_keys=False))
    return subprocess.run(
        [sys.executable, str(SCRIPT), str(p)],
        capture_output=True, text=True,
    )


def make_rule(**overrides) -> dict:
    rule = copy.deepcopy(BASE)
    rule.update(overrides)
    return rule


# ---------- retired-ID registry ----------

def test_retired_id_rejected(tmp_path):
    result = run_validator_on(tmp_path, make_rule(id="androdr-084"))
    assert result.returncode == 1
    assert "retired" in result.stderr


def test_fresh_id_accepted(tmp_path):
    result = run_validator_on(tmp_path, make_rule(id="androdr-200"))
    assert result.returncode == 0, result.stderr


def test_registry_file_exists_and_seeded():
    registry = THIS_DIR / "retired-rule-ids.txt"
    assert registry.exists()
    ids = {
        line.strip()
        for line in registry.read_text().splitlines()
        if line.strip() and not line.startswith("#")
    }
    # entries may carry trailing comments; strip them like the loader does
    ids = {entry.split("#")[0].strip() for entry in ids}
    assert "androdr-084" in ids
