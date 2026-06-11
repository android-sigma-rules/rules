#!/usr/bin/env python3
"""Validate an AndroDR SIGMA rule YAML file against the rule schema.

Usage: python validate-rule.py <rule.yml> [--schema rule-schema.json]

Exit codes:
  0 = valid
  1 = validation errors (printed to stderr)
  2 = file not found / parse error
"""

import json
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("pyyaml required: pip install pyyaml")

SCRIPT_DIR = Path(__file__).parent
# "all" is a combiner (trailing), not a base modifier. Grammar allowed:
#   field|base | field|base|all | field|all (standalone, maps to ALL semantics).
VALID_MODIFIERS = {
    "contains", "startswith", "endswith", "re",
    "gte", "lte", "gt", "lt", "ioc_lookup", "all",
}
MAX_REGEX_LENGTH = 500


def load_schema(schema_path: Path) -> dict:
    with open(schema_path) as f:
        return json.load(f)


def load_permissions(perms_path: Path) -> set[str]:
    with open(perms_path) as f:
        return {line.strip() for line in f if line.strip() and not line.startswith("#")}


def load_retired_ids(path: Path) -> set[str]:
    """IDs listed in retired-rule-ids.txt may never be reused."""
    if not path.exists():
        return set()
    with open(path) as f:
        return {
            line.split("#")[0].strip()
            for line in f
            if line.split("#")[0].strip()
        }


def validate_rule(rule: dict, schema: dict, permissions: set[str],
                  retired_ids: frozenset[str] | set[str] = frozenset()) -> list[str]:
    """Return list of error strings. Empty list means valid."""
    errors = []

    # Required fields
    for field in schema.get("required", []):
        if field not in rule:
            errors.append(f"Missing required field: {field}")

    if "id" in rule:
        rule_id = rule["id"]
        if not isinstance(rule_id, str) or not rule_id.startswith("androdr-"):
            errors.append(f"Rule ID must match 'androdr-NNN', got: {rule_id}")
        elif rule_id in retired_ids:
            errors.append(
                f"Rule ID {rule_id} was retired and must not be reused "
                f"(see validation/retired-rule-ids.txt); allocate the next free ID"
            )

    if "status" in rule and rule["status"] not in ("experimental", "test", "production"):
        errors.append(f"Invalid status: {rule['status']}")

    if "level" in rule and rule["level"] not in ("critical", "high", "medium", "low", "informational"):
        errors.append(f"Invalid level: {rule['level']}")

    # Severity-cap policy: device_posture findings are clamped to 'medium' at
    # runtime (AndroDR SeverityCapPolicy; the evaluator derives the cap
    # category from display.category, see SigmaRuleEvaluator). Declaring above
    # medium is dead text — reject so the pipeline never proposes it.
    display_block = rule.get("display") if isinstance(rule.get("display"), dict) else {}
    posture = (
        rule.get("category") == "device_posture"
        or display_block.get("category") == "device_posture"
    )
    if posture and rule.get("level") in ("high", "critical"):
        errors.append(
            "device_posture rules are clamped to 'medium' at runtime by "
            "SeverityCapPolicy; declare level: medium or below (or reclassify "
            "as category: incident if a genuine HIGH/CRITICAL signal is intended)"
        )

    # Logsource
    logsource = rule.get("logsource", {})
    if logsource.get("product") != "androdr":
        errors.append(f"logsource.product must be 'androdr', got: {logsource.get('product')}")
    valid_services = {
        "app_scanner", "device_auditor", "dns_monitor",
        "process_monitor", "file_scanner",
        "receiver_audit", "accessibility_audit", "appops_audit",
        "network_monitor", "tombstone_parser", "wakelock_parser",
        "battery_daily", "package_install_history",
        "platform_compat", "db_info",
    }
    if logsource.get("service") not in valid_services:
        errors.append(f"Invalid logsource.service: {logsource.get('service')}")

    # Detection — check condition references and modifiers
    detection = rule.get("detection", {})
    condition = detection.get("condition", "")
    selection_names = {k for k in detection if k != "condition"}

    for token in condition.replace("(", " ").replace(")", " ").split():
        if token.lower() not in ("and", "or", "not") and token not in selection_names:
            errors.append(f"Condition references undefined selection: {token}")

    for sel_name, sel_value in detection.items():
        if sel_name == "condition" or not isinstance(sel_value, dict):
            continue
        for field_key in sel_value:
            # Lone actively-exploited-CVE rule = duplicate of androdr-047
            # (CISA KEV catalog) once the severity cap lands. Only
            # named-campaign CVE *sets* (cf. androdr-048..052) justify a
            # dedicated rule. Checked before the modifier guard so the
            # plain-equality form (no modifier) is covered too.
            if field_key.split("|")[0] == "unpatched_cve_id" and posture:
                cve_values = sel_value[field_key]
                cve_count = len(cve_values) if isinstance(cve_values, list) else 1
                if cve_count == 1:
                    errors.append(
                        "single actively-exploited-CVE rules duplicate "
                        "androdr-047 (CISA KEV catalog); only named-campaign "
                        "CVE sets (cf. androdr-048..052) justify a dedicated rule"
                    )
            if "|" not in field_key:
                continue
            tokens = field_key.split("|")
            modifiers = tokens[1:]
            # Grammar: chain must be [base] or [base, "all"]. Mirrors Kotlin
            # SigmaRuleParser's single-base-modifier-plus-optional-|all rule.
            if "all" in modifiers[:-1]:
                errors.append(
                    f"'all' must be the trailing combiner in '{field_key}'"
                )
            if len(modifiers) > 2 or (len(modifiers) == 2 and modifiers[-1] != "all"):
                errors.append(
                    f"Chain too long in '{field_key}': expected at most one modifier "
                    f"(optionally followed by |all). Got: {'|'.join(modifiers)}"
                )
            # tokens[0] is the field name; tokens[1:] are modifiers (chain).
            for modifier in tokens[1:]:
                if modifier not in VALID_MODIFIERS:
                    errors.append(
                        f"Invalid modifier '{modifier}' in field '{field_key}'. "
                        f"Supported: {', '.join(sorted(VALID_MODIFIERS))}"
                    )
            # Regex length check fires whenever 're' appears anywhere in the modifier
            # chain (e.g. 'url|re|all' must still enforce the max pattern length).
            if "re" in tokens[1:]:
                values = sel_value[field_key]
                if isinstance(values, list):
                    for v in values:
                        if isinstance(v, str) and len(v) > MAX_REGEX_LENGTH:
                            errors.append(f"Regex pattern exceeds {MAX_REGEX_LENGTH} chars in '{field_key}'")
                elif isinstance(values, str) and len(values) > MAX_REGEX_LENGTH:
                    errors.append(f"Regex pattern exceeds {MAX_REGEX_LENGTH} chars in '{field_key}'")

    # Display block
    display = rule.get("display", {})
    if display:
        valid_categories = {"app_risk", "device_posture", "network"}
        if "category" in display and display["category"] not in valid_categories:
            errors.append(f"Invalid display.category: {display['category']}")
        valid_evidence = {"none", "cve_list", "ioc_match", "permission_cluster"}
        if "evidence_type" in display and display["evidence_type"] not in valid_evidence:
            errors.append(f"Invalid display.evidence_type: {display['evidence_type']}")

    # Tags — check ATT&CK format
    for tag in rule.get("tags", []):
        if tag.startswith("attack.t") or tag.startswith("attack.T"):
            tid = tag.replace("attack.", "").upper()
            parts = tid.split(".")
            if not (len(parts) in (1, 2) and parts[0][0] == "T" and parts[0][1:].isdigit()):
                errors.append(f"Invalid ATT&CK tag format: {tag}")

    # implies_flags — orthogonal facts about the detection subject the
    # rule's selection structurally guarantees. Source of truth for the
    # allowed values is the schema's enum, so adding a new value there
    # is the single edit point.
    if "implies_flags" in rule:
        flags = rule["implies_flags"]
        if not isinstance(flags, list):
            errors.append("implies_flags must be an array")
        else:
            valid_implies = set(
                schema.get("properties", {})
                    .get("implies_flags", {})
                    .get("items", {})
                    .get("enum", [])
            )
            for flag in flags:
                if flag not in valid_implies:
                    errors.append(
                        f"Invalid implies_flag value: {flag!r}. "
                        f"Valid: {sorted(valid_implies)}"
                    )

    return errors


def main():
    if len(sys.argv) < 2:
        print("Usage: python validate-rule.py <rule.yml>", file=sys.stderr)
        sys.exit(2)

    rule_path = Path(sys.argv[1])
    if not rule_path.exists():
        print(f"File not found: {rule_path}", file=sys.stderr)
        sys.exit(2)

    schema_path = SCRIPT_DIR / "rule-schema.json"
    perms_path = SCRIPT_DIR / "android-permissions.txt"

    schema = load_schema(schema_path)
    permissions = load_permissions(perms_path) if perms_path.exists() else set()
    retired_ids = load_retired_ids(SCRIPT_DIR / "retired-rule-ids.txt")

    with open(rule_path) as f:
        try:
            rule = yaml.safe_load(f)
        except yaml.YAMLError as e:
            print(f"YAML parse error: {e}", file=sys.stderr)
            sys.exit(2)

    errors = validate_rule(rule, schema, permissions, retired_ids)

    if errors:
        print(f"FAIL: {rule_path.name} — {len(errors)} error(s):", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        sys.exit(1)
    else:
        print(f"PASS: {rule_path.name}")
        sys.exit(0)


if __name__ == "__main__":
    main()
