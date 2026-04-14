#!/usr/bin/env python3
"""Validate a Rule Author decision manifest against decisions-schema.json.

Usage: python validate-decisions.py <path/to/decisions.json-or-.yml>

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
    yaml = None

ALLOWED_TYPES = {"ioc_confidence", "telemetry_gap"}
RULE_ID_RE = re.compile(r"^androdr-(NNN|\d{3}|corr-\d{3}|atom-[a-z0-9-]+)$")
GAP_ONLY_KEYS = {"missing_field", "suggested_service"}
REQUIRED_KEYS = {"field", "chosen", "alternative", "reasoning"}
OPTIONAL_KEYS = {"rule_id", "type"} | GAP_ONLY_KEYS
ALLOWED_KEYS = REQUIRED_KEYS | OPTIONAL_KEYS


def validate_decision(decision: dict, index: int) -> list[str]:
    errors: list[str] = []
    if not isinstance(decision, dict):
        return [f"decisions[{index}]: not an object"]

    for key in REQUIRED_KEYS:
        if key not in decision:
            errors.append(f"decisions[{index}]: missing required field {key!r}")

    for key in decision:
        if key not in ALLOWED_KEYS:
            errors.append(f"decisions[{index}]: unexpected key {key!r}")

    rule_id = decision.get("rule_id")
    if rule_id is not None and (not isinstance(rule_id, str) or not RULE_ID_RE.match(rule_id)):
        errors.append(f"decisions[{index}].rule_id: must match androdr-NNN or null, got {rule_id!r}")

    dtype = decision.get("type")
    if dtype is not None and dtype not in ALLOWED_TYPES:
        errors.append(f"decisions[{index}].type: must be one of {sorted(ALLOWED_TYPES)}, got {dtype!r}")

    is_gap = dtype == "telemetry_gap"
    for key in GAP_ONLY_KEYS:
        present = key in decision
        if is_gap and not present:
            errors.append(f"decisions[{index}]: telemetry_gap requires {key!r}")
        if not is_gap and present:
            errors.append(f"decisions[{index}]: {key!r} is only valid when type=telemetry_gap")

    return errors


def validate(manifest: dict) -> list[str]:
    if not isinstance(manifest, dict):
        return ["manifest: top-level must be an object"]
    if "decisions" not in manifest:
        return ["manifest: missing 'decisions' array"]
    decisions = manifest["decisions"]
    if not isinstance(decisions, list):
        return ["manifest.decisions: expected array"]

    errors: list[str] = []
    for i, d in enumerate(decisions):
        errors.extend(validate_decision(d, i))
    return errors


def load(path: Path) -> dict:
    text = path.read_text()
    if path.suffix in {".yml", ".yaml"}:
        if yaml is None:
            sys.exit("pyyaml required to validate YAML manifests: pip install pyyaml")
        return yaml.safe_load(text)
    return json.loads(text)


def main():
    if len(sys.argv) < 2:
        print("Usage: python validate-decisions.py <manifest.json|.yml>", file=sys.stderr)
        sys.exit(2)

    path = Path(sys.argv[1])
    if not path.exists():
        print(f"File not found: {path}", file=sys.stderr)
        sys.exit(2)

    try:
        manifest = load(path)
    except (json.JSONDecodeError, Exception) as e:
        print(f"Parse error: {e}", file=sys.stderr)
        sys.exit(2)

    errors = validate(manifest)
    if errors:
        print(f"FAIL: {path.name} — {len(errors)} error(s):", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        sys.exit(1)
    print(f"PASS: {path.name}")
    sys.exit(0)


if __name__ == "__main__":
    main()
