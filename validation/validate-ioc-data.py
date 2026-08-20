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
HEX_MD5 = re.compile(r"^[0-9a-f]{32}$")
HEX_TLSH = re.compile(r"^[0-9a-f]{72}$")
HEX_SHA512 = re.compile(r"^[0-9a-f]{128}$")


def classify_hash(indicator: str) -> str:
    """Return a human-readable hint for why a hash indicator is not a usable APK/cert hash.

    Recognizes common wrong formats that have slipped into threat-intel reports
    (MD5 from Kaspersky, TLSH from MalwareBazaar metadata, etc.) and returns a
    short diagnostic message. Returns the empty string if the indicator does
    not match any known format — the caller should still report a generic
    format-mismatch error.
    """
    s = indicator.lower()
    if HEX_MD5.match(s):
        return (
            "32 hex chars — likely MD5 (or PE imphash). AndroDR uses SHA-256 "
            "only for APK lookup. Re-fetch the sample from MalwareBazaar/"
            "VirusTotal to obtain SHA-256."
        )
    if HEX_SHA1.match(s):
        return (
            "40 hex chars — SHA-1 is not matched on-device for APK hashes. "
            "SHA-1 is accepted only in cert-hashes.yml."
        )
    if HEX_TLSH.match(s):
        return (
            "72 hex chars — looks like TLSH (fuzzy similarity hash). "
            "Not supported as APK_HASH."
        )
    if HEX_SHA512.match(s):
        return (
            "128 hex chars — SHA-512 is not supported as APK_HASH; AndroDR "
            "uses SHA-256."
        )
    if re.fullmatch(r"[0-9]+:[A-Za-z0-9+/]+:[A-Za-z0-9+/]+", indicator):
        return "ssdeep fuzzy hash format — not supported as APK_HASH or CERT_HASH."
    return ""


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
    if not schema_path.exists():
        sys.exit(f"ioc-entry-schema.json not found at: {schema_path}")
    with open(schema_path) as f:
        entry_schema = json.load(f)
    validator = Draft202012Validator(entry_schema)
    for idx, entry in enumerate(entries):
        for err in validator.iter_errors(entry):
            errors.append(f"entries[{idx}]: schema violation: {err.message}")

    seen_indicators = set()
    is_cert_file = "cert" in filename.lower()
    # APK-hash files (malware-hashes.yml is the active one; apk-hashes.yml is
    # reserved per ioc-lookup-definitions.yml). Both must carry SHA-256 only,
    # because IndicatorResolver.isKnownBadApkHash does not look up MD5 or SHA-1.
    is_apk_hash_file = (
        "malware-hashes" in filename.lower() or "apk-hashes" in filename.lower()
    )

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
                hint = classify_hash(indicator)
                if hint:
                    errors.append(
                        f"{prefix}: invalid cert hash format for "
                        f"'{indicator[:40]}...' — {hint} "
                        f"(cert-hashes.yml accepts SHA-256 or SHA-1 only)"
                    )
                else:
                    errors.append(
                        f"{prefix}: invalid cert hash format "
                        f"(expected 64-char SHA-256 or 40-char SHA-1 lowercase hex): "
                        f"'{indicator[:20]}...'"
                    )

        # APK hash format — malware-hashes.yml / apk-hashes.yml accept SHA-256
        # only. MD5 (32 hex, common from Kaspersky/Dr.Web) and SHA-1 (40 hex,
        # legacy reports) never match on-device; AndroDR's
        # IndicatorResolver.isKnownBadApkHash uses SHA-256 exclusively.
        if is_apk_hash_file and indicator:
            if not HEX_SHA256.match(indicator):
                hint = classify_hash(indicator)
                if hint:
                    errors.append(
                        f"{prefix}: invalid APK hash format for "
                        f"'{indicator[:40]}...' — {hint}"
                    )
                else:
                    errors.append(
                        f"{prefix}: invalid APK hash format "
                        f"(expected 64-char SHA-256 lowercase hex): "
                        f"'{indicator[:40]}...'"
                    )

        # Duplicate check
        if indicator:
            if indicator in seen_indicators:
                errors.append(f"{prefix}: duplicate indicator '{indicator}'")
            seen_indicators.add(indicator)

    return errors


# Bare public suffixes that must never appear as a brand domain: via the
# on-device label-boundary suffix walk, any one of them would exempt an
# unbounded set of scopes from androdr-092. Not a full PSL — the suffixes our
# own eTLD+1 entries end in, plus the obvious global TLDs. Kept in lockstep
# with BrandImpersonationResolver.PUBLIC_SUFFIX_DENYLIST.
BRAND_PUBLIC_SUFFIX_DENYLIST = {
    "com", "org", "net", "io", "app", "co", "info", "biz",
    "uk", "pl", "pt", "es", "mx", "nl", "br", "de", "be", "fr", "it",
    "co.uk", "com.br", "com.mx", "com.au", "co.jp", "co.in", "com.pl",
}

MIN_BRAND_NAME_VARIANT_LEN = 2
MAX_BRAND_NAME_VARIANTS = 500
MAX_BRAND_DOMAINS = 500


def validate_brand_file(data, filename):
    """Structural validator for brand-names.yml / brand-domains.yml (#299).

    Enforces the same bounds AndroDR's BrandImpersonationResolver enforces
    on-device, so a suppression-capable entry (a bare TLD, an over-broad or
    junk domain, a 1-char name variant) is rejected at the CI gate rather than
    silently shipped on the un-hashed ioc-data channel.
    """
    errors = []
    is_domains = filename == "brand-domains.yml"
    list_key = "domains" if is_domains else "display_names"

    brands = data.get("brands")
    if not isinstance(brands, dict) or not brands:
        errors.append("missing or empty top-level `brands:` map")
        return errors

    total = 0
    for brand_key, brand in brands.items():
        if not isinstance(brand, dict):
            errors.append(f"brand '{brand_key}': value must be a map")
            continue
        values = brand.get(list_key)
        if not isinstance(values, list) or not values:
            errors.append(f"brand '{brand_key}': `{list_key}` must be a non-empty list")
            continue
        for v in values:
            total += 1
            if not isinstance(v, str) or not v.strip():
                errors.append(f"brand '{brand_key}': `{list_key}` entry must be a non-empty string")
                continue
            val = v.strip()
            if is_domains:
                d = val.lower()
                if d != val:
                    errors.append(f"brand '{brand_key}': domain '{val}' must be lowercase")
                if "/" in d or ":" in d or " " in d:
                    errors.append(f"brand '{brand_key}': domain '{val}' must be a bare host (no scheme/path/port)")
                if "." not in d:
                    errors.append(f"brand '{brand_key}': domain '{val}' has no dot — a bare TLD would over-match")
                if d in BRAND_PUBLIC_SUFFIX_DENYLIST:
                    errors.append(f"brand '{brand_key}': domain '{val}' is a public suffix — would exempt everything under it")
            else:
                if len(val) < MIN_BRAND_NAME_VARIANT_LEN:
                    errors.append(f"brand '{brand_key}': name variant '{val}' shorter than {MIN_BRAND_NAME_VARIANT_LEN} chars — over-matches")

    cap = MAX_BRAND_DOMAINS if is_domains else MAX_BRAND_NAME_VARIANTS
    if total > cap:
        errors.append(f"{total} {list_key} exceeds cap {cap}")
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

    # Brand impersonation registry files (#299) use a structural `brands:` map,
    # not `entries:`. They are the fleet's only detection-SUPPRESSING remote
    # input (androdr-092's `not scope_legit`) and are NOT covered by
    # rules.sha256, so they get a dedicated structural validator here rather
    # than the entries-less pass-through below. Mirrors the on-device guards in
    # AndroDR's BrandImpersonationResolver.buildMatcher.
    if ioc_path.name in ("brand-names.yml", "brand-domains.yml"):
        errors = validate_brand_file(data, ioc_path.name)
        if errors:
            print(f"FAIL: {ioc_path.name} — {len(errors)} error(s):", file=sys.stderr)
            for err in errors:
                print(f"  - {err}", file=sys.stderr)
            sys.exit(1)
        print(f"PASS: {ioc_path.name}")
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
