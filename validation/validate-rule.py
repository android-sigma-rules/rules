#!/usr/bin/env python3
"""Validate an AndroDR SIGMA rule YAML file against the rule schema.

Usage: python validate-rule.py <rule.yml> [--schema rule-schema.json]

Exit codes:
  0 = valid
  1 = validation errors (printed to stderr)
  2 = file not found / parse error
"""

import json
import re
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

# Correlation-rule grammar — mirrors SigmaRuleParser.parseCorrelationRule in
# AndroDR (types, timespan units, and the 90-day cap must stay in sync with
# CORRELATION_TIMESPAN_CAP_DAYS there).
VALID_CORRELATION_TYPES = {"temporal", "temporal_ordered", "event_count"}
TIMESPAN_RE = re.compile(r"^(\d+)([smhd])$")
TIMESPAN_UNIT_MS = {"s": 1_000, "m": 60_000, "h": 3_600_000, "d": 86_400_000}
MAX_TIMESPAN_MS = 90 * 86_400_000


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


def check_id_and_status(rule: dict, retired_ids) -> list[str]:
    """Shared id/status checks for both rule shapes."""
    errors = []
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
    return errors


def check_attack_tags(rule: dict) -> list[str]:
    errors = []
    for tag in rule.get("tags", []):
        if tag.startswith("attack.t") or tag.startswith("attack.T"):
            tid = tag.replace("attack.", "").upper()
            parts = tid.split(".")
            if not (len(parts) in (1, 2) and parts[0][0] == "T" and parts[0][1:].isdigit()):
                errors.append(f"Invalid ATT&CK tag format: {tag}")
    return errors


def validate_correlation_rule(rule: dict,
                              retired_ids: frozenset[str] | set[str] = frozenset(),
                              known_rule_ids: set[str] | None = None) -> list[str]:
    """Validate the correlation-rule shape (no logsource/detection/level/category;
    a `correlation:` block instead). Mirrors the Kotlin CorrelationParseException
    grammar so a rule that passes here cannot fail to parse on-device."""
    errors = []

    for field in ("title", "id", "status", "correlation"):
        if field not in rule:
            errors.append(f"Missing required field: {field}")

    errors += check_id_and_status(rule, retired_ids)
    errors += check_attack_tags(rule)

    # The Kotlin parser routes on the presence of the `correlation` key; a
    # hybrid carrying standard-rule structure would silently lose it on-device.
    for forbidden in ("logsource", "detection", "level", "category"):
        if forbidden in rule:
            errors.append(
                f"correlation rules must not declare '{forbidden}' "
                "(the on-device parser routes on the 'correlation' key and "
                "ignores standard-rule fields)"
            )

    corr = rule.get("correlation")
    if not isinstance(corr, dict):
        if corr is not None:
            errors.append(f"correlation must be a mapping, got: {type(corr).__name__}")
        return errors

    ctype = corr.get("type")
    if ctype not in VALID_CORRELATION_TYPES:
        errors.append(
            f"Invalid correlation.type: {ctype} "
            f"(must be one of {', '.join(sorted(VALID_CORRELATION_TYPES))})"
        )

    refs = corr.get("rules")
    if not isinstance(refs, list) or not refs:
        errors.append("correlation.rules must be a non-empty list of rule IDs")
    else:
        for ref in refs:
            if not isinstance(ref, str) or not ref.startswith("androdr-"):
                errors.append(f"correlation.rules entry is not an androdr- rule ID: {ref!r}")
            elif known_rule_ids is not None and ref not in known_rule_ids:
                errors.append(
                    f"correlation.rules references unknown rule ID: {ref} "
                    "(no rule file in this repo declares it)"
                )

    timespan = corr.get("timespan")
    if not isinstance(timespan, str) or not TIMESPAN_RE.match(timespan.strip()):
        errors.append(
            f"Invalid correlation.timespan: {timespan!r} (expected <int><s|m|h|d>, e.g. 30m)"
        )
    else:
        m = TIMESPAN_RE.match(timespan.strip())
        if int(m.group(1)) * TIMESPAN_UNIT_MS[m.group(2)] > MAX_TIMESPAN_MS:
            errors.append(
                f"correlation.timespan {timespan} exceeds the on-device 90-day cap"
            )

    if ctype == "event_count":
        cond = corr.get("condition")
        gte = cond.get("gte") if isinstance(cond, dict) else None
        if not isinstance(gte, int) or isinstance(gte, bool):
            errors.append("event_count correlation requires condition.gte (Int)")

    group_by = corr.get("group-by")
    if group_by is not None and (
        not isinstance(group_by, list)
        or not all(isinstance(g, str) for g in group_by)
    ):
        errors.append("correlation.group-by must be a list of field names")

    display = rule.get("display")
    if display is not None and not isinstance(display, dict):
        errors.append(f"display must be a mapping, got: {type(display).__name__}")
    elif isinstance(display, dict) and display.get("category") not in (None, "correlation"):
        errors.append(
            f"Invalid display.category for a correlation rule: {display['category']} "
            "(must be 'correlation')"
        )

    return errors


def validate_rule(rule: dict, schema: dict, permissions: set[str],
                  retired_ids: frozenset[str] | set[str] = frozenset(),
                  known_rule_ids: set[str] | None = None) -> list[str]:
    """Return list of error strings. Empty list means valid."""
    # Correlation rules are a distinct shape (no logsource/detection); the
    # standard schema does not apply to them.
    if "correlation" in rule:
        return validate_correlation_rule(rule, retired_ids, known_rule_ids)

    errors = []

    # Required fields
    for field in schema.get("required", []):
        if field not in rule:
            errors.append(f"Missing required field: {field}")

    errors += check_id_and_status(rule, retired_ids)

    if "level" in rule and rule["level"] not in ("critical", "high", "medium", "low", "informational"):
        errors.append(f"Invalid level: {rule['level']}")

    # Category enum check — exact, case-sensitive. The Kotlin parser
    # lowercases category before mapping to RuleCategory, so a value like
    # 'Device_Posture' would be silently capped on-device while bypassing a
    # naive == comparison here. Rejecting non-canonical spellings closes
    # that bypass for every category-keyed lint below.
    if "category" in rule and rule["category"] not in ("incident", "device_posture"):
        errors.append(
            f"Invalid category: {rule['category']} (must be 'incident' or 'device_posture')"
        )

    # Severity-cap policy: device_posture findings are clamped to 'medium' at
    # runtime via SeverityCapPolicy.applyCap(rule.category, rule.level) — the
    # TOP-LEVEL category field, NOT display.category (which only selects the
    # UI grouping bucket; cf. androdr-020/030: category incident, displayed
    # under device_posture, uncapped). Declaring above medium on a capped
    # category is dead text — reject so the pipeline never proposes it.
    posture = rule.get("category") == "device_posture"
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
        "platform_compat", "db_info", "timeline",
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
                if cve_count == 0:
                    errors.append(
                        f"empty value list for '{field_key}' is a vacuous "
                        "selection that can never match"
                    )
                elif cve_count == 1:
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
    if display is not None and not isinstance(display, dict):
        errors.append(f"display must be a mapping, got: {type(display).__name__}")
        display = {}
    if display:
        valid_categories = {"app_risk", "device_posture", "network"}
        if "category" in display and display["category"] not in valid_categories:
            errors.append(f"Invalid display.category: {display['category']}")
        valid_evidence = {"none", "cve_list", "ioc_match", "permission_cluster"}
        if "evidence_type" in display and display["evidence_type"] not in valid_evidence:
            errors.append(f"Invalid display.evidence_type: {display['evidence_type']}")

    # Tags — check ATT&CK format
    errors += check_attack_tags(rule)

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

    # Correlation rules reference other rules by ID; resolve against every
    # rule file in the repo (service dirs + staging) so a dangling reference
    # fails validation instead of silently never firing on-device.
    known_rule_ids = None
    if isinstance(rule, dict) and "correlation" in rule:
        repo_root = SCRIPT_DIR.parent
        id_re = re.compile(r"^id:\s*(androdr-\S+)", re.M)
        known_rule_ids = set()
        for pattern in ("*/*.yml", "staging/*/*.yml"):
            for f in repo_root.glob(pattern):
                m = id_re.search(f.read_text())
                if m:
                    known_rule_ids.add(m.group(1))

    errors = validate_rule(rule, schema, permissions, retired_ids, known_rule_ids)

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
