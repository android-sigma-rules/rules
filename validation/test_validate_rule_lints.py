"""Tests for the candidate-accuracy lints in validate-rule.py (AndroDR pipeline
candidate-accuracy spec, 2026-06-10): retired-ID registry, device-posture
severity cap, lone-exploited-CVE rejection, plus a regression sweep over all
existing rules. Since AndroDR #268, also the dead-rule gates: the
field-vs-taxonomy lint, selection-shape and value-list checks, the device
condition grammar, and the fail-closed taxonomy load.

Run:
    python3 -m pytest validation/test_validate_rule_lints.py -v
"""
import copy
import pathlib
import shutil
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


# A known-good production app_scanner incident rule (delivered, allowlisted
# for from_trusted_store + is_known_oem_app) — mutation baseline for the
# #275 ioc_lookup-registration and B5 judgment-field-deprecation lints.
APP_BASE = yaml.safe_load(
    (REPO / "app_scanner" / "androdr_010_sideloaded_app.yml").read_text()
)


def make_app_rule(**overrides) -> dict:
    rule = copy.deepcopy(APP_BASE)
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


# ---------- correlation-rule shape (#175 mirror reconcile) ----------

CORR_BASE = yaml.safe_load(
    (REPO / "correlation" / "androdr_corr_001_install_then_admin.yml").read_text()
)


def make_corr_rule(**overrides) -> dict:
    rule = copy.deepcopy(CORR_BASE)
    rule.update(overrides)
    return rule


def test_valid_correlation_rule_accepted(tmp_path):
    result = run_validator_on(tmp_path, make_corr_rule())
    assert result.returncode == 0, result.stderr


def test_all_repo_correlation_rules_pass():
    for f in sorted((REPO / "correlation").glob("*.yml")):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), str(f)],
            capture_output=True, text=True,
        )
        assert result.returncode == 0, f"{f.name}: {result.stderr}"


def test_correlation_hybrid_with_detection_rejected(tmp_path):
    rule = make_corr_rule()
    rule["detection"] = {"selection": {"x": 1}, "condition": "selection"}
    result = run_validator_on(tmp_path, rule)
    assert result.returncode == 1
    assert "must not declare 'detection'" in result.stderr


def test_correlation_unknown_type_rejected(tmp_path):
    rule = make_corr_rule()
    rule["correlation"]["type"] = "sliding_window"
    result = run_validator_on(tmp_path, rule)
    assert result.returncode == 1
    assert "Invalid correlation.type" in result.stderr


def test_correlation_empty_rules_list_rejected(tmp_path):
    rule = make_corr_rule()
    rule["correlation"]["rules"] = []
    result = run_validator_on(tmp_path, rule)
    assert result.returncode == 1
    assert "non-empty list" in result.stderr


def test_correlation_dangling_reference_rejected(tmp_path):
    rule = make_corr_rule()
    rule["correlation"]["rules"] = ["androdr-atom-package-install", "androdr-atom-nonexistent"]
    result = run_validator_on(tmp_path, rule)
    assert result.returncode == 1
    assert "unknown rule ID" in result.stderr


def test_correlation_bad_timespan_rejected(tmp_path):
    rule = make_corr_rule()
    rule["correlation"]["timespan"] = "90 minutes"
    result = run_validator_on(tmp_path, rule)
    assert result.returncode == 1
    assert "Invalid correlation.timespan" in result.stderr


def test_correlation_timespan_over_cap_rejected(tmp_path):
    rule = make_corr_rule()
    rule["correlation"]["timespan"] = "91d"
    result = run_validator_on(tmp_path, rule)
    assert result.returncode == 1
    assert "90-day cap" in result.stderr


def test_event_count_requires_condition_gte(tmp_path):
    rule = make_corr_rule()
    rule["correlation"]["type"] = "event_count"
    rule["correlation"].pop("condition", None)
    result = run_validator_on(tmp_path, rule)
    assert result.returncode == 1
    assert "condition.gte" in result.stderr


def test_correlation_retired_id_rejected(tmp_path):
    result = run_validator_on(tmp_path, make_corr_rule(id="androdr-084"))
    assert result.returncode == 1
    assert "retired" in result.stderr


# ---------- ceremony hardening: reference scope + explicit-null false-passes ----------

def test_correlation_reference_to_staging_id_rejected(tmp_path):
    # androdr-030 exists in staging/ only. On-device, correlation.rules
    # resolve against loaded DETECTION rules; staging is never delivered, and
    # one unresolved reference drops ALL correlation rules at bundle load.
    rule = make_corr_rule()
    rule["correlation"]["rules"] = ["androdr-atom-package-install", "androdr-030"]
    result = run_validator_on(tmp_path, rule)
    assert result.returncode == 1
    assert "unknown rule ID" in result.stderr


def test_correlation_reference_to_corr_id_rejected(tmp_path):
    # Corr ids are never detection rules; corr-of-corr cannot resolve on-device.
    rule = make_corr_rule()
    rule["correlation"]["rules"] = ["androdr-corr-002"]
    result = run_validator_on(tmp_path, rule)
    assert result.returncode == 1
    assert "unknown rule ID" in result.stderr


def test_correlation_null_group_by_rejected(tmp_path):
    # A dangling 'group-by:' line parses as None; Kotlin containsKey→throw
    # drops the rule on-device, so treating it as absent is a false-pass.
    rule = make_corr_rule()
    rule["correlation"]["group-by"] = None
    result = run_validator_on(tmp_path, rule)
    assert result.returncode == 1
    assert "group-by" in result.stderr


def test_correlation_null_display_rejected(tmp_path):
    rule = make_corr_rule()
    rule["display"] = None
    result = run_validator_on(tmp_path, rule)
    assert result.returncode == 1
    assert "display must be a mapping" in result.stderr
    assert "Traceback" not in result.stderr


def test_correlation_non_dict_correlation_clean_error(tmp_path):
    rule = make_corr_rule()
    rule["correlation"] = "not-a-mapping"
    result = run_validator_on(tmp_path, rule)
    assert result.returncode == 1
    assert "correlation must be a mapping" in result.stderr
    assert "Traceback" not in result.stderr


def test_correlation_unicode_digit_timespan_rejected(tmp_path):
    # Python \d matches Unicode digits, Kotlin's does not — [0-9] keeps the
    # validator no laxer than the on-device parser.
    rule = make_corr_rule()
    rule["correlation"]["timespan"] = "٥d"  # ARABIC-INDIC DIGIT FIVE
    result = run_validator_on(tmp_path, rule)
    assert result.returncode == 1
    assert "Invalid correlation.timespan" in result.stderr


# ---------- dead-rule gates (#268): field-vs-taxonomy ----------

def test_unknown_detection_field_rejected(tmp_path):
    rule = make_rule()
    rule["detection"] = {"selection": {"adb_enbaled": True}, "condition": "selection"}
    result = run_validator_on(tmp_path, rule)
    assert result.returncode == 1
    assert "Unknown detection field 'adb_enbaled'" in result.stderr
    assert "Valid fields" in result.stderr


def test_unknown_field_with_modifier_rejected(tmp_path):
    rule = make_rule()
    rule["detection"] = {"selection": {"patch_age_dayz|gte": 180}, "condition": "selection"}
    result = run_validator_on(tmp_path, rule)
    assert result.returncode == 1
    assert "Unknown detection field 'patch_age_dayz'" in result.stderr


def test_typo_in_negated_filter_rejected(tmp_path):
    # The over-fire direction: a typo'd field inside a not-referenced filter
    # makes the filter never subtract on-device — the rule fires on
    # everything. Pinned as its own case so a future "skip filter
    # selections" optimization of the lint fails loudly.
    rule = make_rule()
    rule["detection"] = {
        "selection": {"adb_enabled": True},
        "filter_known_good": {"is_system_ap": True},
        "condition": "selection and not filter_known_good",
    }
    result = run_validator_on(tmp_path, rule)
    assert result.returncode == 1
    assert "Unknown detection field 'is_system_ap'" in result.stderr


def _incident_app_rule(detection):
    # app_scanner-shaped incident rule (BASE is a device_auditor posture
    # rule; same conversion as test_non_posture_rule_at_high_accepted).
    rule = make_rule(category="incident")
    rule.pop("report_safe_state", None)
    rule["display"] = copy.deepcopy(rule["display"])
    rule["display"]["category"] = "app_risk"
    rule["display"].pop("safe_title", None)
    rule["logsource"] = {"product": "androdr", "service": "app_scanner"}
    rule["detection"] = detection
    return rule


def test_valid_fields_with_modifiers_pass(tmp_path):
    # package_ioc_db is a real registered lookup (#275); is_system_app is a
    # raw_fact field — neither collides with the judgment-field (B5) or
    # ioc_lookup-registration lints, keeping this a pure fields/modifiers check.
    rule = _incident_app_rule({
        "selection": {
            "package_name|ioc_lookup": "package_ioc_db",
            "is_system_app": False,
        },
        "filter_known_good": {"package_name|contains": ["com.google."]},
        "condition": "selection and not filter_known_good",
    })
    result = run_validator_on(tmp_path, rule)
    assert result.returncode == 0, result.stderr


def test_unknown_service_rejected(tmp_path):
    rule = make_rule()
    rule["logsource"] = {"product": "androdr", "service": "nonexistent_service"}
    result = run_validator_on(tmp_path, rule)
    assert result.returncode == 1
    assert "Invalid logsource.service" in result.stderr
    assert "taxonomy" in result.stderr


def test_timeline_atom_rules_pass():
    # timeline/ atoms (no sigma_ prefix in this repo) must pass with the
    # taxonomy's timeline entry — they'd have been the only day-one failures.
    atoms = sorted((REPO / "timeline").glob("androdr_atom_*.yml"))
    assert len(atoms) >= 5, "timeline atom discovery glob looks broken"
    for f in atoms:
        result = subprocess.run(
            [sys.executable, str(SCRIPT), str(f)],
            capture_output=True, text=True,
        )
        assert result.returncode == 0, f"{f.name}: {result.stderr}"


def _network_monitor_rule():
    # network_monitor is the sole non-active (unwired) taxonomy service;
    # destination_port is one of its valid fields.
    rule = make_rule()
    rule["logsource"] = {"product": "androdr", "service": "network_monitor"}
    rule["detection"] = {
        "selection": {"destination_port|gte": 1},
        "condition": "selection",
    }
    return rule


def test_non_active_service_rejected_outside_staging(tmp_path):
    result = run_validator_on(tmp_path, _network_monitor_rule())
    assert result.returncode == 1
    assert "unwired" in result.stderr
    assert "staging" in result.stderr


def run_validator_rel(cwd, rel_path, rule):
    # Invoke with a RELATIVE path from cwd — how CI's find|xargs sweep does.
    p = cwd / rel_path
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(yaml.safe_dump(rule, sort_keys=False))
    return subprocess.run(
        [sys.executable, str(SCRIPT), rel_path],
        capture_output=True, text=True, cwd=cwd,
    )


def test_non_active_service_allowed_under_staging(tmp_path):
    result = run_validator_rel(tmp_path, "staging/rule.yml", _network_monitor_rule())
    assert result.returncode == 0, result.stderr


def test_staging_exemption_is_first_path_component_only(tmp_path):
    # app_scanner/staging_foo.yml IS deliverable — a substring match must
    # not grant the exemption (validate-delivery-set.py convention).
    result = run_validator_rel(
        tmp_path, "app_scanner/staging_rule.yml", _network_monitor_rule()
    )
    assert result.returncode == 1
    assert "unwired" in result.stderr


# ---------- dead-rule gates (#268): selection shape + value lists ----------

def test_non_mapping_selection_rejected(tmp_path):
    # Standard SIGMA list-of-maps syntax: silently dropped by the device
    # parser; under `not`, the rule then fires on everything.
    rule = make_rule()
    rule["detection"] = {
        "selection": [{"adb_enabled": True}],
        "condition": "selection",
    }
    result = run_validator_on(tmp_path, rule)
    assert result.returncode == 1
    assert "must be a mapping" in result.stderr
    assert "Traceback" not in result.stderr


def test_empty_mapping_selection_rejected(tmp_path):
    rule = make_rule()
    rule["detection"] = {"selection": {}, "condition": "selection"}
    result = run_validator_on(tmp_path, rule)
    assert result.returncode == 1
    assert "empty mapping" in result.stderr


def test_empty_value_list_any_field_rejected(tmp_path):
    # The CVE-only vacuous-value error, generalized to every field.
    rule = make_rule()
    rule["detection"] = {"selection": {"adb_enabled": []}, "condition": "selection"}
    result = run_validator_on(tmp_path, rule)
    assert result.returncode == 1
    assert "vacuous" in result.stderr


def test_null_value_rejected(tmp_path):
    rule = make_rule()
    rule["detection"] = {"selection": {"adb_enabled": None}, "condition": "selection"}
    result = run_validator_on(tmp_path, rule)
    assert result.returncode == 1
    assert "vacuous" in result.stderr


def test_uncompilable_regex_rejected(tmp_path):
    rule = make_rule()
    rule["detection"] = {
        "selection": {"patch_level|re": ["[unclosed"]},
        "condition": "selection",
    }
    result = run_validator_on(tmp_path, rule)
    assert result.returncode == 1
    assert "uncompilable regex" in result.stderr


# ---------- dead-rule gates (#268): condition grammar ----------
# Device grammar: ["not"] name (("and"|"or") ["not"] name)* — whitespace
# split (ASCII class only), case-insensitive keywords, NO parentheses.

def _cond_rule(condition, extra_selections=None):
    rule = make_rule()
    detection = {"selection": {"adb_enabled": True}}
    if extra_selections:
        detection.update(extra_selections)
    if condition is not ...:
        detection["condition"] = condition
    rule["detection"] = detection
    return rule


def test_paren_condition_rejected(tmp_path):
    # The evaluator has no paren handling; the validator's old
    # paren-STRIPPING was a false-pass divergence.
    rule = _cond_rule(
        "(selection or filter_x) and not filter_x",
        {"filter_x": {"dev_options_enabled": False}},
    )
    result = run_validator_on(tmp_path, rule)
    assert result.returncode == 1
    assert "condition" in result.stderr.lower()


def test_keyword_as_operand_rejected(tmp_path):
    # "not and": the evaluator consumes 'and' as an operand (?: false),
    # not false -> true -> fires on every record.
    result = run_validator_on(tmp_path, _cond_rule("not and"))
    assert result.returncode == 1
    assert "keyword" in result.stderr


def test_dangling_not_rejected(tmp_path):
    result = run_validator_on(tmp_path, _cond_rule("selection and not"))
    assert result.returncode == 1
    assert "dangling 'not'" in result.stderr


def test_trailing_operator_rejected(tmp_path):
    result = run_validator_on(tmp_path, _cond_rule("selection and"))
    assert result.returncode == 1
    assert "dangling operator" in result.stderr


def test_empty_condition_rejected(tmp_path):
    result = run_validator_on(tmp_path, _cond_rule(""))
    assert result.returncode == 1
    assert "empty detection.condition" in result.stderr


def test_missing_condition_defaults_to_selection(tmp_path):
    # Device parser null-coalesces an absent condition to "selection".
    # With a selection of that name: pass. Without: undefined reference.
    result = run_validator_on(tmp_path, _cond_rule(...))
    assert result.returncode == 0, result.stderr

    rule = make_rule()
    rule["detection"] = {"sel_a": {"adb_enabled": True}}
    result = run_validator_on(tmp_path, rule)
    assert result.returncode == 1
    assert "undefined selection: selection" in result.stderr


def test_explicit_null_condition_defaults_to_selection(tmp_path):
    result = run_validator_on(tmp_path, _cond_rule(None))
    assert result.returncode == 0, result.stderr


def test_nbsp_condition_rejected(tmp_path):
    # Java \s is ASCII-only; Python's default split is Unicode-aware. An
    # NBSP-joined condition is grammar-valid under a Unicode split but a
    # single unresolvable token on-device -> dead rule.
    rule = _cond_rule(
        "selection\u00a0and\u00a0not\u00a0filter_x",
        {"filter_x": {"dev_options_enabled": False}},
    )
    result = run_validator_on(tmp_path, rule)
    assert result.returncode == 1
    assert "undefined selection" in result.stderr


def test_case_insensitive_keywords_accepted(tmp_path):
    # The evaluator lowercases keywords; AND/Not must parse as keywords.
    rule = _cond_rule(
        "selection AND Not filter_x",
        {"filter_x": {"dev_options_enabled": False}},
    )
    result = run_validator_on(tmp_path, rule)
    assert result.returncode == 0, result.stderr


# ---------- dead-rule gates (#268): taxonomy fail-closed ----------

def _run_from_copied_script(tmp_path, taxonomy_content=None):
    shutil.copy(SCRIPT, tmp_path / "validate-rule.py")
    shutil.copy(THIS_DIR / "rule-schema.json", tmp_path / "rule-schema.json")
    if taxonomy_content is not None:
        (tmp_path / "logsource-taxonomy.yml").write_text(taxonomy_content)
    p = tmp_path / "rule.yml"
    p.write_text(yaml.safe_dump(make_rule(), sort_keys=False))
    return subprocess.run(
        [sys.executable, str(tmp_path / "validate-rule.py"), str(p)],
        capture_output=True, text=True,
    )


def test_missing_taxonomy_fatal(tmp_path):
    result = _run_from_copied_script(tmp_path)
    assert result.returncode != 0
    assert "taxonomy" in result.stderr
    assert "Traceback" not in result.stderr


def test_corrupt_taxonomy_fatal(tmp_path):
    result = _run_from_copied_script(tmp_path, "services: []\n")
    assert result.returncode != 0
    assert "taxonomy" in result.stderr
    assert "Traceback" not in result.stderr


def test_fieldless_taxonomy_service_fatal(tmp_path):
    result = _run_from_copied_script(
        tmp_path,
        "services:\n  device_auditor:\n    status: active\n    fields: {}\n",
    )
    assert result.returncode != 0
    assert "fields" in result.stderr
    assert "Traceback" not in result.stderr


# ---------- #275: ioc_lookup registration ----------

def test_unregistered_ioc_lookup_rejected(tmp_path):
    rule = make_app_rule(id="androdr-300")
    rule["detection"] = {"selection": {"package_name|ioc_lookup": "no_such_db"}, "condition": "selection"}
    result = run_validator_on(tmp_path, rule)
    assert result.returncode == 1
    assert "no_such_db" in result.stderr and "ioc-lookup-definitions" in result.stderr


def test_registered_ioc_lookup_accepted(tmp_path):
    rule = make_app_rule(id="androdr-301")
    rule["detection"] = {"selection": {"package_name|ioc_lookup": "known_good_app_db"}, "condition": "selection"}
    assert run_validator_on(tmp_path, rule).returncode == 0


def test_nameless_ioc_lookup_rejected(tmp_path):
    rule = make_app_rule(id="androdr-304")
    rule["detection"] = {"selection": {"installer|ioc_lookup": None}, "condition": "selection"}
    assert run_validator_on(tmp_path, rule).returncode == 1


# ---------- B5: judgment-field deprecation (delivered vs staging) ----------

def test_new_rule_using_judgment_field_rejected(tmp_path):
    rule = make_app_rule(id="androdr-302")
    rule["detection"] = {"selection": {"from_trusted_store": False}, "condition": "selection"}
    result = run_validator_on(tmp_path, rule)
    assert result.returncode == 1
    assert "judgment" in result.stderr and "from_trusted_store" in result.stderr


def test_allowlisted_delivered_rule_accepted(tmp_path):
    assert run_validator_on(tmp_path, copy.deepcopy(APP_BASE)).returncode == 0


def test_modifier_spelled_judgment_field_rejected(tmp_path):
    rule = make_app_rule(id="androdr-305")
    rule["detection"] = {"selection": {"is_sideloaded|equals": True}, "condition": "selection"}
    assert run_validator_on(tmp_path, rule).returncode == 1


# ---------- B4: complete kinds + data-driven freeze ----------

def test_every_taxonomy_field_declares_kind():
    tax = yaml.safe_load((THIS_DIR / "logsource-taxonomy.yml").read_text())
    missing = [f"{svc}/{fname}"
               for svc, sdef in tax["services"].items()
               for fname, fdef in sdef["fields"].items()
               if not isinstance(fdef, dict) or fdef.get("kind") not in ("raw_fact", "judgment")]
    assert missing == []


def test_judgment_set_equals_allowlist_keys():
    tax = yaml.safe_load((THIS_DIR / "logsource-taxonomy.yml").read_text())
    marked = {fname for sdef in tax["services"].values()
              for fname, fdef in sdef["fields"].items()
              if isinstance(fdef, dict) and fdef.get("kind") == "judgment"}
    allowed = set(yaml.safe_load((THIS_DIR / "judgment-field-allowlist.yml").read_text())["allowed"])
    assert marked == allowed  # the allowlist keys ARE the frozen set (data, not code)


# ---------- B3: caps single-source with rank comparison ----------

def test_severity_cap_sourced_from_yaml(tmp_path):
    caps = yaml.safe_load((THIS_DIR / "severity-caps.yml").read_text())["caps"]
    assert caps == {"device_posture": "medium"}
    assert run_validator_on(tmp_path, make_rule(id="androdr-303", level="critical")).returncode == 1
    assert run_validator_on(tmp_path, make_rule(id="androdr-306", level="medium")).returncode == 0
