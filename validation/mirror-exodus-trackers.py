#!/usr/bin/env python3
"""Mirror the Exodus Privacy tracker database into ioc-data/trackers.yml.

Exodus data is licensed under the Open Database License 1.0 (ODbL-1.0); the
generated file stays ODbL. Signatures are normalised into a few strict,
validator-checked shapes (see domain_grammar.py) so the app never evaluates an
arbitrary Exodus regular expression.

Usage:
    python3 validation/mirror-exodus-trackers.py --out ioc-data/trackers.yml \
        [--from-json FILE] [--previous FILE]
"""
import argparse
import json
import pathlib
import re
import sys
import urllib.request

import yaml

sys.path.insert(0, str(pathlib.Path(__file__).parent))
import domain_grammar as dg  # noqa: E402

SOURCE_URL = "https://reports.exodus-privacy.eu.org/api/trackers"
ATTRIBUTION = "Exodus Privacy — https://exodus-privacy.eu.org — Open Database License 1.0"
MIN_TRACKERS = 300
MAX_SHRINK = 0.10

# Drop-report line prefixes (tests count by these).
R_CLASS_NAME = "class-name signature dropped"
R_UPPER_SEGMENT = "dot-led signature dropped"
R_BAD_CODE = "code signature dropped"
R_BAD_NET = "network signature dropped"
R_FIELD = "failed field check"
R_BROAD = "broad signature excluded"
R_CAP = "pattern cap exceeded"
R_TRACKER = "tracker dropped"

_PLAIN_CODE = re.compile(r"[a-z0-9_]+(\.[A-Za-z0-9_]+)+")
_SUFFIX = re.compile(r"[a-z0-9-]+(\.[a-z0-9-]+)+")
_LABEL = re.compile(r"[a-z0-9-]+")
_WEBSITE = re.compile(r"https?://[a-z0-9.-]+(:\d+)?(/\S*)?", re.IGNORECASE)


def _split(sig):
    return [s.strip() for s in (sig or "").split("|") if s.strip()]


def _unescape(s):
    return s.replace("\\.", ".").replace("\\-", "-")


def _website(site):
    if isinstance(site, str) and _WEBSITE.fullmatch(site):
        return site
    return ""


def _derive_code(tid, sigs, report):
    prefixes, segments = set(), set()
    plain = [s.rstrip(".") for s in sigs if not s.startswith(".")]
    non_class = [s for s in plain if not s.rsplit(".", 1)[-1][:1].isupper()]
    for raw in sigs:
        s = raw.rstrip(".")
        if not s:
            continue
        if s.startswith("."):
            inner = s[1:]
            if dg.FIELD_CHECKS["segment"](inner):
                segments.add(inner)
            else:
                report.append(f"{R_UPPER_SEGMENT}: {tid}: {raw!r}")
            continue
        last = s.rsplit(".", 1)[-1]
        if last[:1].isupper():
            package = s.rsplit(".", 1)[0] if "." in s else ""
            parts = package.split(".") if package else []
            if len(parts) < 3:
                report.append(f"{R_CLASS_NAME}: {tid}: {raw!r} (package has {len(parts)} segments)")
                continue
            if any(o.startswith(package + ".") for o in non_class):
                report.append(f"{R_CLASS_NAME}: {tid}: {raw!r} (package is a parent of another signature)")
                continue
            candidate = package
        elif _PLAIN_CODE.fullmatch(s):
            candidate = s
        else:
            report.append(f"{R_BAD_CODE}: {tid}: {raw!r}")
            continue
        if dg.FIELD_CHECKS["prefix"](candidate):
            prefixes.add(candidate)
        else:
            report.append(f"{R_FIELD}: {tid}: prefix {candidate!r}")
    return sorted(prefixes), sorted(segments)


def _classify_net(sig):
    """Return (kind, value) or (None, reason)."""
    s = sig
    if s.startswith(".*\\."):
        s = s[4:]
    elif s.startswith("\\."):
        s = s[2:]
    elif s.startswith("."):
        s = s[1:]
    plain = _unescape(s)
    if _SUFFIX.fullmatch(plain):
        return "suffix", plain
    bounded = (sig.startswith("\\.") or sig.startswith(".")) and (sig.endswith("\\.") or sig.endswith("."))
    if bounded:
        return "label", plain.rstrip(".")
    if _LABEL.fullmatch(plain):
        return "label", plain
    if dg.is_restricted_pattern(sig):
        return "pattern", sig
    return None, "not a suffix, label or restricted pattern"


def _derive_net(tid, sigs, first_party, report):
    suffixes, labels, patterns, excluded = set(), set(), [], []
    for sig in sigs:
        kind, value = _classify_net(sig)
        if kind is None:
            report.append(f"{R_BAD_NET}: {tid}: {sig!r} ({value})")
            continue
        if not dg.FIELD_CHECKS[kind](value):
            report.append(f"{R_FIELD}: {tid}: {kind} {value!r}")
            continue
        if any(dg.matches_host(kind, value, h) for h in first_party):
            report.append(f"{R_BROAD}: {tid}: {sig!r}")
            if sig not in excluded:
                excluded.append(sig)
            continue
        if kind == "suffix":
            suffixes.add(value)
        elif kind == "label":
            labels.add(value)
        elif value not in patterns:
            patterns.append(value)
    return sorted(suffixes), sorted(labels), patterns, excluded


def render(api, previous):
    """Normalise an Exodus API dict into (document, drop_report).

    `previous` is the prior document, if any; the shrink guard lives in main().
    """
    first_party = dg.load_first_party_hosts()
    report = []
    built = []
    for key in sorted(api.get("trackers", {}), key=lambda k: int(k)):
        t = api["trackers"][key]
        tid = int(t.get("id", key))
        prefixes, segments = _derive_code(tid, _split(t.get("code_signature")), report)
        suffixes, labels, patterns, excluded = _derive_net(
            tid, _split(t.get("network_signature")), first_party, report)
        if len(patterns) > dg.MAX_PATTERNS_PER_TRACKER:
            for p in patterns[dg.MAX_PATTERNS_PER_TRACKER:]:
                report.append(f"{R_CAP}: {tid}: per-tracker cap, {p!r}")
            patterns = patterns[:dg.MAX_PATTERNS_PER_TRACKER]
        built.append(dict(
            id=tid, name=t.get("name") or "", website=_website(t.get("website")),
            categories=list(t.get("categories") or []) or ["Uncategorised"],
            code_prefixes=prefixes, code_segments=segments, domain_suffixes=suffixes,
            domain_labels=labels, domain_patterns=patterns, excluded_domains=excluded))
    built.sort(key=lambda t: t["id"])

    total = 0
    trackers = []
    for t in built:
        keep = max(0, dg.MAX_PATTERNS_TOTAL - total)
        for p in t["domain_patterns"][keep:]:
            report.append(f"{R_CAP}: {t['id']}: file cap, {p!r}")
        t["domain_patterns"] = t["domain_patterns"][:keep]
        total += len(t["domain_patterns"])
        if not (t["code_prefixes"] or t["code_segments"] or t["domain_suffixes"]
                or t["domain_labels"] or t["domain_patterns"]):
            report.append(f"{R_TRACKER}: {t['id']}: {t['name']!r} has no usable signature left")
            continue
        trackers.append(t)

    doc = dict(version=1, source="exodus-privacy", source_url=SOURCE_URL, license="ODbL-1.0",
               attribution=ATTRIBUTION, trackers=trackers)
    return doc, report


def _fetch():
    req = urllib.request.Request(SOURCE_URL, headers={"User-Agent": "androdr-rules-mirror"})
    with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310 - fixed https URL
        return json.loads(resp.read().decode("utf-8"))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", required=True)
    ap.add_argument("--from-json")
    ap.add_argument("--previous")
    args = ap.parse_args(argv)

    if args.from_json:
        api = json.loads(pathlib.Path(args.from_json).read_text(encoding="utf-8"))
    else:
        api = _fetch()
    previous = None
    if args.previous and pathlib.Path(args.previous).exists():
        previous = yaml.safe_load(pathlib.Path(args.previous).read_text(encoding="utf-8"))

    doc, report = render(api, previous)
    for line in report:
        print(line, file=sys.stderr)
    n = len(doc["trackers"])
    print(f"{n} trackers kept, {len(report)} drop-report lines", file=sys.stderr)
    if n < MIN_TRACKERS:
        print(f"ERROR: only {n} trackers (< {MIN_TRACKERS})", file=sys.stderr)
        return 1
    if previous and previous.get("trackers"):
        old = len(previous["trackers"])
        if n < old * (1 - MAX_SHRINK):
            print(f"ERROR: tracker count shrank from {old} to {n} (> {MAX_SHRINK:.0%})", file=sys.stderr)
            return 1
    pathlib.Path(args.out).write_text(
        yaml.safe_dump(doc, sort_keys=False, allow_unicode=True, width=120), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
