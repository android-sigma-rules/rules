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
VALID_MODIFIERS = {
    "contains", "startswith", "endswith", "re",
    "gte", "lte", "gt", "lt", "ioc_lookup",
}
MAX_REGEX_LENGTH = 500


def load_schema(schema_path: Path) -> dict:
    with open(schema_path) as f:
        return json.load(f)


def load_permissions(perms_path: Path) -> set[str]:
    with open(perms_path) as f:
        return {line.strip() for line in f if line.strip() and not line.startswith("#")}


def validate_rule(rule: dict, schema: dict, permissions: set[str]) -> list[str]:
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

    if "status" in rule and rule["status"] not in ("experimental", "test", "production"):
        errors.append(f"Invalid status: {rule['status']}")

    if "level" in rule and rule["level"] not in ("critical", "high", "medium", "low"):
        errors.append(f"Invalid level: {rule['level']}")

    # Logsource
    logsource = rule.get("logsource", {})
    if logsource.get("product") != "androdr":
        errors.append(f"logsource.product must be 'androdr', got: {logsource.get('product')}")
    valid_services = {"app_scanner", "device_auditor", "dns_monitor", "process_monitor", "file_scanner"}
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
            if "|" in field_key:
                _, modifier = field_key.rsplit("|", 1)
                if modifier not in VALID_MODIFIERS:
                    errors.append(f"Invalid modifier '{modifier}' in field '{field_key}'")
                if modifier == "re":
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

    with open(rule_path) as f:
        try:
            rule = yaml.safe_load(f)
        except yaml.YAMLError as e:
            print(f"YAML parse error: {e}", file=sys.stderr)
            sys.exit(2)

    errors = validate_rule(rule, schema, permissions)

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
