#!/usr/bin/env python3
"""Validate an AndroDR IOC data YAML file.

Usage: python3 validate-ioc-data.py <ioc-data-file.yml>

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

try:
    from jsonschema import Draft202012Validator
except ImportError:
    sys.exit("jsonschema required: pip install jsonschema")

SCRIPT_DIR = Path(__file__).parent
BLOCKED_CATEGORIES = {"TEST", "FIXTURE", "SIMULATION", "DEBUG"}
BLOCKED_FAMILY_PATTERNS = re.compile(
    r"(test|fixture|simulation|sample|example)", re.IGNORECASE
)
HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")
HEX_SHA1 = re.compile(r"^[0-9a-f]{40}$")


def load_allowed_sources(path: Path) -> set[str]:
    with open(path) as f:
        entries = json.load(f)
    return {entry["id"] for entry in entries}


def validate_ioc_file(data: dict, allowed_sources: set[str], filename: str) -> list[str]:
    """Return list of error strings. Empty = valid."""
    errors = []
    entries = data.get("entries", [])
    if not entries:
        errors.append("No 'entries' list found in file")
        return errors

    # Schema validation (runs first; legacy checks below still run for defense-in-depth)
    schema_path = SCRIPT_DIR / "ioc-entry-schema.json"
    if schema_path.exists():
        with open(schema_path) as f:
            entry_schema = json.load(f)
        validator = Draft202012Validator(entry_schema)
        for idx, entry in enumerate(entries):
            for err in validator.iter_errors(entry):
                errors.append(f"entries[{idx}]: schema violation: {err.message}")

    seen_indicators = set()
    is_cert_file = "cert" in filename.lower()

    for idx, entry in enumerate(entries):
        prefix = f"entries[{idx}]"

        # Known-good allowlist entries (popular-apps.yml shape) don't carry
        # threat-IOC provenance fields. Skip threat-IOC-specific legacy checks
        # for them; the schema above already validated their required fields.
        is_known_good_entry = "packageName" in entry and "indicator" not in entry
        if is_known_good_entry:
            continue

        # Source field
        source = entry.get("source")
        if not source:
            errors.append(f"{prefix}: missing 'source' field")
        elif source not in allowed_sources:
            errors.append(f"{prefix}: unknown source '{source}' (not in allowed-sources.json)")

        # Blocked categories
        category = entry.get("category", "")
        if category.upper() in BLOCKED_CATEGORIES:
            errors.append(f"{prefix}: blocked category '{category}'")

        # Blocked family patterns
        family = entry.get("family", "") or entry.get("familyName", "")
        if family and BLOCKED_FAMILY_PATTERNS.search(family):
            errors.append(f"{prefix}: blocked family name '{family}' (matches test/fixture pattern)")

        # Cert hash format — accept SHA-256 (64 hex chars) or SHA-1 (40 hex chars)
        indicator = entry.get("indicator", "")
        if is_cert_file and indicator:
            if not (HEX_SHA256.match(indicator) or HEX_SHA1.match(indicator)):
                errors.append(
                    f"{prefix}: invalid cert hash format "
                    f"(expected 64-char SHA-256 or 40-char SHA-1 lowercase hex): "
                    f"'{indicator[:20]}...'"
                )

        # Duplicate check
        if indicator:
            if indicator in seen_indicators:
                errors.append(f"{prefix}: duplicate indicator '{indicator}'")
            seen_indicators.add(indicator)

    return errors


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 validate-ioc-data.py <ioc-data-file.yml>", file=sys.stderr)
        sys.exit(2)

    ioc_path = Path(sys.argv[1])
    if not ioc_path.exists():
        print(f"File not found: {ioc_path}", file=sys.stderr)
        sys.exit(2)

    sources_path = SCRIPT_DIR / "allowed-sources.json"
    if not sources_path.exists():
        print(f"allowed-sources.json not found at: {sources_path}", file=sys.stderr)
        sys.exit(2)

    allowed_sources = load_allowed_sources(sources_path)

    with open(ioc_path) as f:
        try:
            data = yaml.safe_load(f)
        except yaml.YAMLError as e:
            print(f"YAML parse error: {e}", file=sys.stderr)
            sys.exit(2)

    if not data:
        print(f"PASS: {ioc_path.name} (empty file)")
        sys.exit(0)

    entries = data.get("entries")
    # Treat "entries missing entirely" the same as "entries: []". This covers
    # structural files like known-oem-prefixes.yml, which use prefix-group keys
    # (aosp_prefixes, samsung_prefixes, ...) instead of an entries list. Those
    # files have no per-entry provenance to validate, so there is nothing for
    # this validator to do. Chose this over a per-filename allowlist so future
    # prefix-group-style files are handled without code changes.
    if entries is None or len(entries) == 0:
        print(f"PASS: {ioc_path.name} (no entries)")
        sys.exit(0)

    errors = validate_ioc_file(data, allowed_sources, ioc_path.name)

    if errors:
        print(f"FAIL: {ioc_path.name} — {len(errors)} error(s):", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        sys.exit(1)
    else:
        print(f"PASS: {ioc_path.name}")
        sys.exit(0)


if __name__ == "__main__":
    main()
