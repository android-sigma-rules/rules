#!/usr/bin/env python3
"""Validate ioc-data/*.yml entries against kotlin-mirror-feeds.yml upstreams.

Modes:
  strict   -- any (type, value) duplicate causes non-zero exit.
  advisory -- duplicates are reported on stdout as WARNings, exit 0.

Offline mode:
  --offline-snapshot FILE  -- use a TSV (type \\t normalized_value per line)
                              instead of fetching from upstreams. For unit
                              tests and CI-without-network scenarios.

Usage:
  validate-ioc-complementarity.py --file ioc-data/package-names.yml --mode strict
  validate-ioc-complementarity.py --all --mode strict            # walk every ioc-data/*.yml
  validate-ioc-complementarity.py --file ... --offline-snapshot ...

Exit codes:
  0 -- no strict-mode violations (advisory warnings may have been emitted)
  1 -- one or more strict-mode violations
  2 -- setup / fetch / parse error

Parser parity:
  The three parsers (stalkerware-yaml, threatfox-json, mvt-stix) match
  the format assumptions in AndroDR's Kotlin bypass feed clients — they
  are deliberately bug-for-bug consistent with the Kotlin side, because
  the invariant being enforced is "no ioc-data entry duplicates what the
  Kotlin client would deliver." If the Kotlin feed's upstream format
  differs from reality (e.g., mvt-indicators.yaml is actually a two-level
  index of STIX2 bundles, which the current Kotlin MvtIndicatorsFeed.kt
  traverses in two phases but this Python parser does not), the Python
  side should be brought in line in a coordinated PR with the Kotlin
  side. See follow-up issue TBD for parser-fidelity audit.

  Feeds whose Python parser is known to be out of sync with the live
  upstream schema can be tagged `parser_limited: true` in
  kotlin-mirror-feeds.yml. The validator skips those feeds with a loud
  WARNING (and a GitHub Actions `::warning::` annotation when running
  under GITHUB_ACTIONS) instead of silently treating their snapshot as
  empty (which would let any ioc-data duplicate slip through unchecked).
  AndroDR #127 uses this for threatfox + mvt-indicators; both Python
  parsers expect schemas that diverge from current upstream reality.
  The flag is a manual override — semantically "do not invoke the
  parser at all" — not a feature-flag for partial parsing.

  MalwareBazaar APK hashes were descoped from this contract (AndroDR
  issue #146): the only useful upstream query is Auth-Key-gated, so the
  device cannot bypass directly. APK hashes are ingested into
  ioc-data/malware-hashes.yml by the update-rules pipeline instead.
"""

import argparse
import json
import os
import pathlib
import sys
import urllib.request
import urllib.error

try:
    import yaml
except ImportError:
    sys.exit("pyyaml required: pip install pyyaml")

SCRIPT_DIR = pathlib.Path(__file__).parent
DEFAULT_IOC_DATA = SCRIPT_DIR.parent / "ioc-data"
DEFAULT_MIRROR_FEEDS = SCRIPT_DIR / "kotlin-mirror-feeds.yml"

USER_AGENT = "androdr-complementarity-validator/1.0"
FETCH_TIMEOUT = 30  # seconds


def load_mirror_feeds(path: pathlib.Path) -> list[dict]:
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return data.get("feeds", [])


def fetch_url(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT) as resp:
        return resp.read()


def normalize_value(raw: str, ioc_type: str) -> str:
    """Normalize an IOC value for dedup comparison."""
    v = raw.strip()
    if ioc_type in ("C2_DOMAIN",):
        v = v.lower().rstrip(".")
    elif ioc_type in ("APK_HASH", "CERT_HASH"):
        v = v.lower()
    return v


# Per-parser: fetch upstream, yield (type, normalized_value) tuples.
# Errors during fetch/parse raise; caller decides whether to fail or degrade.

def parse_stalkerware_yaml(body: bytes) -> set[tuple[str, str]]:
    """AssoEchap/stalkerware-indicators ioc.yaml: list of {name, type, packages: [...]}."""
    data = yaml.safe_load(body) or []
    out: set[tuple[str, str]] = set()
    for entry in data:
        for pkg in entry.get("packages", []) or []:
            out.add(("PACKAGE_NAME", normalize_value(str(pkg), "PACKAGE_NAME")))
    return out


def parse_threatfox_json(body: bytes) -> set[tuple[str, str]]:
    """ThreatFox recent export: {query_status, data: {date: [ {ioc_type, ioc, ...}, ... ]}}."""
    data = json.loads(body)
    out: set[tuple[str, str]] = set()
    for _date, entries in (data.get("data") or {}).items():
        for e in entries or []:
            if e.get("ioc_type") != "domain":
                continue
            raw = e.get("ioc", "")
            # Strip protocol and port/path (same as ThreatFoxDomainFeed.kt)
            for prefix in ("http://", "https://"):
                if raw.startswith(prefix):
                    raw = raw[len(prefix):]
            raw = raw.split("/", 1)[0].split(":", 1)[0]
            if raw:
                out.add(("C2_DOMAIN", normalize_value(raw, "C2_DOMAIN")))
    return out


def parse_mvt_stix(body: bytes) -> set[tuple[str, str]]:
    """MVT indicators.yaml: mixed indicator types. Best-effort extraction."""
    data = yaml.safe_load(body) or {}
    out: set[tuple[str, str]] = set()
    # MVT indicators.yaml has an 'indicators' list with type-keyed entries
    for ind in data.get("indicators", []) or []:
        itype = (ind.get("type") or "").lower()
        value = ind.get("value") or ind.get("pattern") or ""
        if not value:
            continue
        if itype in ("domain-name", "domain"):
            out.add(("C2_DOMAIN", normalize_value(value, "C2_DOMAIN")))
        elif itype in ("app-id", "package", "package-name"):
            out.add(("PACKAGE_NAME", normalize_value(value, "PACKAGE_NAME")))
    return out


PARSERS = {
    "stalkerware-yaml": parse_stalkerware_yaml,
    "threatfox-json": parse_threatfox_json,
    "mvt-stix": parse_mvt_stix,
}


def build_union_snapshot(feeds: list[dict], allow_unreachable: bool) -> tuple[set[tuple[str, str]], list[str]]:
    union: set[tuple[str, str]] = set()
    warnings: list[str] = []
    for feed in feeds:
        fid = feed.get("id")
        url = feed.get("url")
        parser_name = feed.get("parser")
        if not (fid and url and parser_name):
            print(
                f"[complementarity] malformed feed entry in mirror-feeds.yml: {feed}",
                file=sys.stderr,
            )
            sys.exit(2)
        # AndroDR #127: feeds whose parser is known to be out of sync with the
        # live upstream schema are tagged `parser_limited: true` so this
        # validator skips them with a loud warning instead of silently
        # contributing an empty snapshot (which would make the strict-mode
        # invariant trivially pass against those feeds and let duplicates rot).
        #
        # Strict on the value type: a typo like `parser_limited: "true"` or
        # `parser_limited: 1` is rejected loudly rather than silently falling
        # through to a fetch — that fallback would re-introduce the exact
        # silent-skip rot this PR exists to prevent.
        if "parser_limited" in feed:
            flag = feed["parser_limited"]
            if not isinstance(flag, bool):
                print(
                    f"[complementarity] feed '{fid}' has parser_limited="
                    f"{flag!r} ({type(flag).__name__}); must be a YAML "
                    f"boolean (true|false). Refusing to guess.",
                    file=sys.stderr,
                )
                sys.exit(2)
            if flag:
                reason = (feed.get("parser_limited_reason") or "").strip().replace("\n", " ")
                msg = (
                    f"[complementarity] SKIP parser-limited feed '{fid}': {reason} "
                    f"-- complementarity against this feed is NOT enforced; ioc-data "
                    f"entries may shadow on-device Kotlin bypass coverage."
                )
                warnings.append(msg)
                print(msg, file=sys.stderr)
                # GitHub Actions: also emit an inline annotation so the SKIP
                # surfaces on the PR Files tab, not just buried in step logs.
                if os.environ.get("GITHUB_ACTIONS") == "true":
                    print(
                        f"::warning title=parser-limited feed::"
                        f"{fid} skipped — {reason}",
                        file=sys.stderr,
                    )
                continue
        parser = PARSERS.get(parser_name)
        if parser is None:
            print(f"[complementarity] Unknown parser '{parser_name}' for feed '{fid}'", file=sys.stderr)
            sys.exit(2)
        try:
            body = fetch_url(url)
            snapshot = parser(body)
            print(f"[complementarity] fetched {fid}: {len(snapshot)} entries", file=sys.stderr)
            union |= snapshot
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            msg = f"[complementarity] WARN: upstream '{fid}' unreachable: {e}"
            warnings.append(msg)
            if allow_unreachable:
                print(msg, file=sys.stderr)
            else:
                print(f"[complementarity] fetch failed for '{fid}': {e}", file=sys.stderr)
                sys.exit(2)
    return union, warnings


def load_offline_snapshot(path: pathlib.Path) -> set[tuple[str, str]]:
    out: set[tuple[str, str]] = set()
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line or line.startswith("#"):
                continue
            ioc_type, raw_value = line.split("\t", 1)
            out.add((ioc_type, normalize_value(raw_value, ioc_type)))
    return out


IOC_TYPE_BY_FILENAME = {
    "package-names.yml":    "PACKAGE_NAME",
    "c2-domains.yml":       "C2_DOMAIN",
    "cert-hashes.yml":      "CERT_HASH",
    "malware-hashes.yml":   "APK_HASH",
    "apk-hashes.yml":       "APK_HASH",
    "popular-apps.yml":     "PACKAGE_NAME",
    "known-oem-prefixes.yml": "PACKAGE_NAME",
}


def check_file(ioc_file: pathlib.Path, upstream_union: set[tuple[str, str]]) -> list[str]:
    ioc_type = IOC_TYPE_BY_FILENAME.get(ioc_file.name)
    if ioc_type is None:
        print(
            f"[complementarity] Unknown filename '{ioc_file.name}' — add to "
            f"IOC_TYPE_BY_FILENAME. This is a setup error, not a violation.",
            file=sys.stderr,
        )
        sys.exit(2)

    with open(ioc_file, encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    violations: list[str] = []
    for idx, entry in enumerate(data.get("entries") or []):
        indicator = entry.get("indicator")
        if not indicator:
            continue
        normalized = normalize_value(str(indicator), ioc_type)
        if (ioc_type, normalized) in upstream_union:
            source = entry.get("source", "?")
            violations.append(
                f"  entries[{idx}] '{indicator}' (source={source}) present in an upstream feed"
            )
    return violations


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", type=pathlib.Path, help="Single ioc-data/*.yml file to check.")
    ap.add_argument("--all", action="store_true", help="Check every ioc-data/*.yml file.")
    ap.add_argument("--mode", choices=["strict", "advisory"], default="strict")
    ap.add_argument("--mirror-feeds", type=pathlib.Path, default=DEFAULT_MIRROR_FEEDS)
    ap.add_argument("--offline-snapshot", type=pathlib.Path,
                    help="Use a TSV (type<TAB>value) snapshot instead of fetching. For tests.")
    ap.add_argument("--allow-upstream-unreachable", action="store_true",
                    help="Don't fail if an upstream feed is unreachable (pipeline-local use).")
    args = ap.parse_args()

    if not args.file and not args.all:
        ap.error("either --file or --all must be given")

    if args.offline_snapshot:
        upstream_union = load_offline_snapshot(args.offline_snapshot)
    else:
        feeds = load_mirror_feeds(args.mirror_feeds)
        upstream_union, _ = build_union_snapshot(feeds, args.allow_upstream_unreachable)

    files = [args.file] if args.file else sorted(DEFAULT_IOC_DATA.glob("*.yml"))
    any_violation = False
    for f in files:
        violations = check_file(f, upstream_union)
        if violations:
            any_violation = True
            header = f"{f.name}: {len(violations)} complementarity violation(s)"
            if args.mode == "advisory":
                print(f"WARN (advisory): {header}", file=sys.stderr)
                for v in violations:
                    print(v, file=sys.stderr)
            else:
                print(f"FAIL: {header}", file=sys.stderr)
                for v in violations:
                    print(v, file=sys.stderr)

    if any_violation and args.mode == "strict":
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
