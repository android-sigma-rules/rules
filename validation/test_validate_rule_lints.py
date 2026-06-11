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


# ---------- device-posture severity cap ----------

def test_posture_rule_at_high_rejected(tmp_path):
    result = run_validator_on(tmp_path, make_rule(level="high"))
    assert result.returncode == 1
    assert "SeverityCapPolicy" in result.stderr


def test_posture_rule_at_critical_rejected(tmp_path):
    result = run_validator_on(tmp_path, make_rule(level="critical"))
    assert result.returncode == 1


def test_posture_rule_at_medium_accepted(tmp_path):
    result = run_validator_on(tmp_path, make_rule(level="medium"))
    assert result.returncode == 0, result.stderr


def test_posture_cap_keys_on_top_level_category(tmp_path):
    # display.category app_risk but top-level category device_posture -> capped
    # (SeverityCapPolicy.applyCap takes rule.category, the top-level field)
    rule = make_rule(level="high")
    rule["display"] = copy.deepcopy(rule["display"])
    rule["display"]["category"] = "app_risk"
    rule["category"] = "device_posture"
    result = run_validator_on(tmp_path, rule)
    assert result.returncode == 1


def test_incident_rule_displayed_as_posture_uncapped(tmp_path):
    # The androdr-020/030 shape: top-level incident (uncapped at runtime),
    # display.category device_posture (UI grouping only) -> must be ACCEPTED.
    rule = make_rule(level="critical", category="incident")
    rule.pop("report_safe_state", None)
    result = run_validator_on(tmp_path, rule)
    assert result.returncode == 0, result.stderr


def test_non_posture_rule_at_high_accepted(tmp_path):
    # category: incident is the uncapped class (schema enum: incident | device_posture)
    rule = make_rule(level="high", category="incident")
    rule.pop("report_safe_state", None)
    rule["display"] = copy.deepcopy(rule["display"])
    rule["display"]["category"] = "app_risk"
    rule["display"].pop("safe_title", None)
    result = run_validator_on(tmp_path, rule)
    assert result.returncode == 0, result.stderr


# ---------- lone-exploited-CVE rejection ----------

def _cve_rule(cves):
    rule = make_rule()
    rule["detection"] = {
        "selection": {"unpatched_cve_id|contains": cves},
        "condition": "selection",
    }
    return rule


def test_single_cve_list_rejected(tmp_path):
    result = run_validator_on(tmp_path, _cve_rule(["CVE-2026-12345"]))
    assert result.returncode == 1
    assert "androdr-047" in result.stderr


def test_single_cve_string_rejected(tmp_path):
    result = run_validator_on(tmp_path, _cve_rule("CVE-2026-12345"))
    assert result.returncode == 1


def test_cve_set_accepted(tmp_path):
    result = run_validator_on(
        tmp_path, _cve_rule(["CVE-2026-1", "CVE-2026-2", "CVE-2026-3"])
    )
    assert result.returncode == 0, result.stderr


def test_non_cve_posture_rule_unaffected(tmp_path):
    result = run_validator_on(tmp_path, make_rule())
    assert result.returncode == 0, result.stderr


def test_single_cve_plain_equality_rejected(tmp_path):
    # no-modifier form must be caught too
    rule = make_rule()
    rule["detection"] = {
        "selection": {"unpatched_cve_id": "CVE-2026-12345"},
        "condition": "selection",
    }
    result = run_validator_on(tmp_path, rule)
    assert result.returncode == 1
    assert "androdr-047" in result.stderr


# ---------- regression: all shipped rules still pass ----------

def test_all_existing_rules_pass_validator():
    rule_files = sorted(REPO.glob("*/androdr_*.yml")) + sorted(
        REPO.glob("staging/*/androdr_*.yml")
    )
    assert len(rule_files) > 30, "rule discovery glob looks broken"
    failures = []
    for p in rule_files:
        result = subprocess.run(
            [sys.executable, str(SCRIPT), str(p)],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            failures.append(f"{p.relative_to(REPO)}:\n{result.stderr}")
    assert not failures, "\n".join(failures)


# ---------- reviewer-found hardening (category enum, empty CVE list, display type) ----------

def test_invalid_category_value_rejected(tmp_path):
    # Case-sensitive bypass: Kotlin lowercases category, so 'Device_Posture'
    # would be capped on-device while sailing past a naive == check.
    result = run_validator_on(tmp_path, make_rule(level="high", category="Device_Posture"))
    assert result.returncode == 1
    assert "Invalid category" in result.stderr


def test_bogus_category_value_rejected(tmp_path):
    result = run_validator_on(tmp_path, make_rule(category="posture"))
    assert result.returncode == 1
    assert "Invalid category" in result.stderr


def test_empty_cve_list_rejected(tmp_path):
    result = run_validator_on(tmp_path, _cve_rule([]))
    assert result.returncode == 1
    assert "vacuous" in result.stderr


def test_non_dict_display_clean_error(tmp_path):
    rule = make_rule()
    rule["display"] = "not-a-mapping"
    result = run_validator_on(tmp_path, rule)
    assert result.returncode == 1
    assert "display must be a mapping" in result.stderr
    assert "Traceback" not in result.stderr
