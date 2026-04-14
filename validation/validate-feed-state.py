#!/usr/bin/env python3
"""Validate feed-state.json against feed-state-schema.json.

Usage: python validate-feed-state.py [path/to/feed-state.json]
       Defaults to ../feed-state.json (repo root).

Exit codes:
  0 = valid
  1 = validation errors (printed to stderr)
  2 = file not found / parse error
"""

import json
import re
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent
DEFAULT_STATE_PATH = SCRIPT_DIR.parent / "feed-state.json"
SCHEMA_PATH = SCRIPT_DIR / "feed-state-schema.json"

ISO_TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$")
ISO_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
SHA_RE = re.compile(r"^[0-9a-f]{7,40}$")
VERSION_RE = re.compile(r"^\d+\.\d+$")


def _check_iso_timestamp(value, path, errors):
    if not isinstance(value, str) or not ISO_TS_RE.match(value):
        errors.append(f"{path}: expected ISO 8601 UTC timestamp, got {value!r}")


def _check_iso_date(value, path, errors):
    if not isinstance(value, str) or not ISO_DATE_RE.match(value):
        errors.append(f"{path}: expected YYYY-MM-DD, got {value!r}")


def _check_feed_cursor(cursor, feed_name, required_extra, extra_check, errors):
    """extra_check is a list of (key, validator_fn) pairs for feed-specific keys."""
    if not isinstance(cursor, dict):
        errors.append(f"feeds.{feed_name}: expected object, got {type(cursor).__name__}")
        return
    allowed = {"last_seen_timestamp"} | set(required_extra)
    if "last_seen_timestamp" not in cursor:
        errors.append(f"feeds.{feed_name}: missing last_seen_timestamp")
    else:
        _check_iso_timestamp(cursor["last_seen_timestamp"], f"feeds.{feed_name}.last_seen_timestamp", errors)
    for extra in required_extra:
        if extra not in cursor:
            errors.append(f"feeds.{feed_name}: missing {extra}")
    for key, check_fn in extra_check:
        if key in cursor:
            check_fn(cursor[key], f"feeds.{feed_name}.{key}", errors)
    for key in cursor:
        if key not in allowed:
            errors.append(f"feeds.{feed_name}: unexpected key {key!r}")


FEED_SPEC = {
    "threatfox":              ([], []),
    "malwarebazaar":          ([], []),
    "asb":                    (["last_bulletin"], [("last_bulletin", _check_iso_date)]),
    "nvd":                    (["last_modified"], [("last_modified", _check_iso_timestamp)]),
    "stalkerware_indicators": (
        ["last_commit_sha"],
        [("last_commit_sha",
          lambda v, p, e: e.append(f"{p}: expected git SHA, got {v!r}") if not (isinstance(v, str) and SHA_RE.match(v)) else None)]
    ),
    "attack_mobile":          (
        ["last_version"],
        [("last_version",
          lambda v, p, e: e.append(f"{p}: expected N.N version, got {v!r}") if not (isinstance(v, str) and VERSION_RE.match(v)) else None)]
    ),
    "amnesty":                ([], []),
}


def validate(state: dict) -> list[str]:
    errors: list[str] = []
    if state.get("version") != 2:
        errors.append(f"version must be 2 (got {state.get('version')!r}); run migration")
    if "last_full_sweep" not in state:
        errors.append("missing last_full_sweep")
    else:
        _check_iso_date(state["last_full_sweep"], "last_full_sweep", errors)

    feeds = state.get("feeds", {})
    if not isinstance(feeds, dict):
        errors.append("feeds: expected object")
        return errors

    for feed_name, (required_extra, extra_check) in FEED_SPEC.items():
        if feed_name not in feeds:
            errors.append(f"feeds.{feed_name}: missing")
            continue
        _check_feed_cursor(feeds[feed_name], feed_name, required_extra, extra_check, errors)

    for feed_name in feeds:
        if feed_name not in FEED_SPEC:
            errors.append(f"feeds.{feed_name}: unknown feed (allowed: {sorted(FEED_SPEC)})")

    return errors


def main():
    state_path = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_STATE_PATH
    if not state_path.exists():
        print(f"File not found: {state_path}", file=sys.stderr)
        sys.exit(2)
    try:
        state = json.loads(state_path.read_text())
    except json.JSONDecodeError as e:
        print(f"JSON parse error: {e}", file=sys.stderr)
        sys.exit(2)

    errors = validate(state)
    if errors:
        print(f"FAIL: {state_path.name} — {len(errors)} error(s):", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        sys.exit(1)
    print(f"PASS: {state_path.name}")
    sys.exit(0)


if __name__ == "__main__":
    main()
