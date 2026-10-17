#!/usr/bin/env python3
"""Collect the `source: malwarebazaar` hashes that fetch-feed-dumps.sh must query.

Usage: mb_hashes.py REPO_ROOT [CANDIDATES_DIR]   (prints one hash per line)

Candidate files come from scraped, LLM-authored data: they are read with
yaml.safe_load only, and a file that does not parse or has no `entries:` list is ignored.
"""
import pathlib
import sys

import yaml


def _entries(path):
    try:
        data = yaml.safe_load(pathlib.Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError):
        return []
    entries = data.get("entries") if isinstance(data, dict) else None
    return entries if isinstance(entries, list) else []


def _mb_indicators(path):
    for e in _entries(path):
        if isinstance(e, dict) and e.get("source") == "malwarebazaar" and isinstance(e.get("indicator"), str):
            yield e["indicator"]


def collect_mb_hashes(repo_root, candidates_dir=None):
    """Hashes in ioc-data/malware-hashes.yml, then in candidates_dir/*.yml; deduplicated, order kept."""
    files = [pathlib.Path(repo_root) / "ioc-data" / "malware-hashes.yml"]
    if candidates_dir:
        files += sorted(pathlib.Path(candidates_dir).glob("*.yml"))
    seen = {}
    for f in files:
        for h in _mb_indicators(f):
            seen.setdefault(h, None)
    return list(seen)


if __name__ == "__main__":
    if len(sys.argv) not in (2, 3):
        sys.exit("usage: mb_hashes.py REPO_ROOT [CANDIDATES_DIR]")
    print("\n".join(collect_mb_hashes(*sys.argv[1:])))
