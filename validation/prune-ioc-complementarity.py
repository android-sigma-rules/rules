#!/usr/bin/env python3
"""One-shot prune helper for Phase 3 of AndroDR issue #117.

Removes entries from ioc-data/*.yml whose (type, normalized_value) is present
in any upstream listed in kotlin-mirror-feeds.yml AND whose `source` field
matches a kotlin-mirror-feeds.yml feed id.

Safety filter: entries sourced from upstreams NOT in kotlin-mirror-feeds.yml
(amnesty-investigations, citizenlab-indicators, android-security-bulletin,
virustotal, zimperium-ioc) are NEVER pruned, even if their (type, value)
happens to collide with a Kotlin-mirrored upstream (which would indicate a
normalization or ingest bug to investigate separately).

Preserves file headers (version, description, sources). In-place edits each
ioc-data/*.yml; run from a clean working tree and commit the diff.

Usage:
  python3 validation/prune-ioc-complementarity.py --dry-run
  python3 validation/prune-ioc-complementarity.py
"""

import argparse
import pathlib
import sys

# Import the validate module to reuse snapshot logic
import importlib.util

SCRIPT_DIR = pathlib.Path(__file__).parent
VALIDATOR_PATH = SCRIPT_DIR / "validate-ioc-complementarity.py"

# Load as module despite hyphenated filename
spec = importlib.util.spec_from_file_location("validate_ioc_complementarity", VALIDATOR_PATH)
validator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validator)

try:
    import yaml
except ImportError:
    sys.exit("pyyaml required: pip install pyyaml")


def kotlin_mirror_feed_ids() -> set[str]:
    feeds = validator.load_mirror_feeds(SCRIPT_DIR / "kotlin-mirror-feeds.yml")
    return {f["id"] for f in feeds}


def prune_file(ioc_file: pathlib.Path, upstream_union: set[tuple[str, str]],
               mirror_ids: set[str], dry_run: bool) -> tuple[int, list[str]]:
    ioc_type = validator.IOC_TYPE_BY_FILENAME.get(ioc_file.name)
    if ioc_type is None:
        return 0, [f"skip {ioc_file.name}: unknown type"]

    with open(ioc_file, encoding="utf-8") as f:
        raw = f.read()
    data = yaml.safe_load(raw) or {}
    entries = data.get("entries") or []

    kept: list[dict] = []
    dropped: list[tuple[int, dict]] = []
    for idx, entry in enumerate(entries):
        indicator = entry.get("indicator")
        source = entry.get("source", "")
        if not indicator:
            kept.append(entry)
            continue
        normalized = validator.normalize_value(str(indicator), ioc_type)
        is_dup = (ioc_type, normalized) in upstream_union
        is_safe_to_prune = source in mirror_ids
        if is_dup and is_safe_to_prune:
            dropped.append((idx, entry))
        else:
            kept.append(entry)

    if not dropped:
        return 0, [f"{ioc_file.name}: 0 pruned"]

    data["entries"] = kept
    log = [f"{ioc_file.name}: pruning {len(dropped)} entries:"]
    for idx, e in dropped:
        log.append(f"  - entries[{idx}] '{e.get('indicator')}' (source={e.get('source','?')})")

    if not dry_run:
        # Preserve the file header/comments by rebuilding with yaml.safe_dump,
        # then re-inserting the header block (everything above `entries:`) verbatim.
        header_lines = []
        for line in raw.splitlines():
            if line.startswith("entries:"):
                break
            header_lines.append(line)
        # Dump only the entries list
        body = yaml.safe_dump(
            {"entries": kept}, sort_keys=False, allow_unicode=True, default_flow_style=False
        )
        new_content = "\n".join(header_lines).rstrip() + "\n" + body
        ioc_file.write_text(new_content, encoding="utf-8")

    return len(dropped), log


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    mirror_feeds = validator.load_mirror_feeds(SCRIPT_DIR / "kotlin-mirror-feeds.yml")
    print(f"Fetching {len(mirror_feeds)} upstream mirror feeds...", file=sys.stderr)
    upstream_union, warnings = validator.build_union_snapshot(mirror_feeds, allow_unreachable=False)
    print(f"Union size: {len(upstream_union)} unique (type, value) tuples", file=sys.stderr)

    mirror_ids = kotlin_mirror_feed_ids()
    ioc_data_dir = SCRIPT_DIR.parent / "ioc-data"

    total = 0
    for f in sorted(ioc_data_dir.glob("*.yml")):
        pruned, log = prune_file(f, upstream_union, mirror_ids, args.dry_run)
        total += pruned
        for line in log:
            print(line)

    mode = "DRY-RUN: would prune" if args.dry_run else "Pruned"
    print(f"\n{mode} {total} entries total.", file=sys.stderr)


if __name__ == "__main__":
    main()
