#!/usr/bin/env python3
"""Mirror the Exodus Privacy tracker database into ioc-data/trackers.yml.

Exodus data is licensed under the Open Database License 1.0 (ODbL-1.0); the
generated file stays ODbL. Signatures are normalised into a few strict,
validator-checked shapes (see domain_grammar.py) so the app never evaluates an
arbitrary Exodus regular expression.

Usage (the candidate is written away from the list in use, then reviewed):
    python3 validation/mirror-exodus-trackers.py --out CANDIDATE \
        [--from-json FILE] [--previous ioc-data/trackers.yml]

AndroDR's own entries (validation/tracker-supplement.yml: SDKs Exodus does not
list, such as residential-proxy SDKs) are appended to the mirrored list on every
run. Their ids start at 900001. They pass the same checks as a mirrored entry,
but a fault in one stops the run: a supplement entry is never dropped quietly.

Exit codes: 0 the file was written; 1 a size guard tripped (too few trackers,
or the list shrank by more than a tenth); 2 the source could not be read or
did not answer with a tracker list; 3 a file the mirror reads from the rules
repository (first_party_hosts.txt, common_packages.txt, tracker-supplement.yml,
the list --previous names) is missing or broken. Each failure ends with one
"ERROR:" line on stderr, and nothing is written.

Every other stderr line is about one Exodus entry and repeats its text only
through tracker_guards.shown: one line of printable ASCII, cut short. The id
that leads such a line is a number from 1 to 999999999 (0 stands for an id
outside that range, whose entry is dropped).
"""
import argparse
import http.client
import json
import pathlib
import re
import sys
import urllib.request

import yaml

sys.path.insert(0, str(pathlib.Path(__file__).parent))
import domain_grammar as dg  # noqa: E402
import tracker_guards as tg  # noqa: E402

SOURCE_URL = "https://reports.exodus-privacy.eu.org/api/trackers"
ATTRIBUTION = "Exodus Privacy — https://exodus-privacy.eu.org — Open Database License 1.0"
SUPPLEMENT_FILE = pathlib.Path(__file__).parent / "tracker-supplement.yml"
SUPPLEMENT_NOTE = (f"Entries with id {tg.SUPPLEMENT_ID_MIN} and above are AndroDR's own "
                   "(validation/tracker-supplement.yml), not Exodus Privacy's")
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


def _split(sig):
    return [s.strip() for s in (sig or "").split("|") if s.strip()]


def _unescape(s):
    return s.replace("\\.", ".").replace("\\-", "-")


def _categories(raw):
    """The entry's categories as a list of text, each once, or None when they are anything else."""
    if raw is None:
        raw = []
    if not isinstance(raw, list) or not all(isinstance(c, str) for c in raw):
        return None
    return list(dict.fromkeys(raw)) or ["Uncategorised"]


def _website(site):
    if isinstance(site, str) and site and len(site) <= tg.WEBSITE_MAX and dg.FIELD_CHECKS["website"](site):
        return site
    return ""


def _keep_code(kind, value, raw, tid, common, report):
    """True when a derived prefix or segment may enter the list; otherwise it is reported."""
    if not dg.FIELD_CHECKS[kind](value) or len(value) > tg.SIGNATURE_MAX:
        report.append(f"{R_FIELD}: {tid}: {kind} {tg.shown(value)}")
        return False
    if any(tg.matches_package(kind, value, p) for p in common):
        report.append(f"{R_BROAD}: {tid}: {tg.shown(raw)} (matches an ordinary package)")
        return False
    return True


def _derive_code(tid, sigs, common, report):
    prefixes, segments = set(), set()
    plain = [s.rstrip(".") for s in sigs if not s.startswith(".")]
    non_class = [s for s in plain if not s.rsplit(".", 1)[-1][:1].isupper()]
    for raw in sigs:
        s = raw.rstrip(".")
        if not s:
            continue
        if s.startswith("."):
            inner = s[1:]
            if not dg.FIELD_CHECKS["segment"](inner):
                report.append(f"{R_UPPER_SEGMENT}: {tid}: {tg.shown(raw)}")
            elif _keep_code("segment", inner, raw, tid, common, report):
                segments.add(inner)
            continue
        last = s.rsplit(".", 1)[-1]
        if last[:1].isupper():
            package = s.rsplit(".", 1)[0] if "." in s else ""
            parts = package.split(".") if package else []
            if len(parts) < 3:
                report.append(f"{R_CLASS_NAME}: {tid}: {tg.shown(raw)} (package has {len(parts)} segments)")
                continue
            if any(o.startswith(package + ".") for o in non_class):
                report.append(f"{R_CLASS_NAME}: {tid}: {tg.shown(raw)} (package is a parent of another signature)")
                continue
            candidate = package
        elif _PLAIN_CODE.fullmatch(s):
            candidate = s
        else:
            report.append(f"{R_BAD_CODE}: {tid}: {tg.shown(raw)}")
            continue
        if _keep_code("prefix", candidate, raw, tid, common, report):
            prefixes.add(candidate)
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
        if len(sig) > tg.SIGNATURE_MAX:  # also bounds what excluded_domains can hold
            report.append(f"{R_FIELD}: {tid}: signature {tg.shown(sig)}")
            continue
        kind, value = _classify_net(sig)
        if kind is None:
            report.append(f"{R_BAD_NET}: {tid}: {tg.shown(sig)} ({value})")
            continue
        if not dg.FIELD_CHECKS[kind](value) or len(value) > tg.SIGNATURE_MAX:
            report.append(f"{R_FIELD}: {tid}: {kind} {tg.shown(value)}")
            continue
        if any(dg.matches_host(kind, value, h) for h in first_party):
            report.append(f"{R_BROAD}: {tid}: {tg.shown(sig)}")
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


# (field, domain_grammar.FIELD_CHECKS key, matches_host kind or None): the signature lists a
# supplement entry may carry. Patterns are left out on purpose: none is needed yet, and they
# share a file-wide cap with Exodus's.
_SUPPLEMENT_LISTS = (
    ("code_prefixes", "prefix", None),
    ("code_segments", "segment", None),
    ("domain_suffixes", "suffix", "suffix"),
    ("domain_labels", "label", "label"),
)
_SUPPLEMENT_KEYS = {"id", "name", "website", "categories", "references"} | {f for f, _, _ in _SUPPLEMENT_LISTS}


def _supplement_signatures(t, tid, first_party, common):
    """The entry's signature lists, each sorted; raises ValueError on the first fault."""
    lists = {}
    for field, check, host_kind in _SUPPLEMENT_LISTS:
        values = t.get(field, [])
        if not isinstance(values, list) or not all(isinstance(v, str) for v in values):
            raise ValueError(f"entry {tid}: `{field}` is not a list of text")
        if len(set(values)) != len(values):
            raise ValueError(f"entry {tid}: `{field}` repeats a value")
        for v in values:
            if not dg.FIELD_CHECKS[check](v) or len(v) > tg.SIGNATURE_MAX:
                raise ValueError(f"entry {tid}: `{field}` value {tg.shown(v)} fails the {check} check")
            if host_kind and any(dg.matches_host(host_kind, v, h) for h in first_party):
                raise ValueError(f"entry {tid}: `{field}` value {tg.shown(v)} matches a first-party host")
            if not host_kind and any(tg.matches_package(check, v, p) for p in common):
                raise ValueError(f"entry {tid}: `{field}` value {tg.shown(v)} matches an ordinary package")
        lists[field] = sorted(values)
    if not any(lists.values()):
        raise ValueError(f"entry {tid}: has no signature")
    return lists


def _supplement_entry(t, seen, first_party, common):
    if not isinstance(t, dict):
        raise ValueError("an entry is not a map")
    tid = t.get("id")
    if not isinstance(tid, int) or isinstance(tid, bool) or not tg.SUPPLEMENT_ID_MIN <= tid <= tg.ID_MAX:
        raise ValueError(f"entry id {tg.shown(tid)} is not a whole number from {tg.SUPPLEMENT_ID_MIN} "
                         f"to {tg.ID_MAX}")
    if tid in seen:
        raise ValueError(f"entry {tid}: its id is used twice")
    unknown = sorted(str(k) for k in set(t) - _SUPPLEMENT_KEYS)
    if unknown:
        raise ValueError(f"entry {tid}: unknown key {tg.shown(unknown[0])}")
    problem = tg.name_problem(t.get("name"))
    if problem:
        raise ValueError(f"entry {tid}: name {tg.shown(t.get('name'))} {problem}")
    website = t.get("website", "")
    if not isinstance(website, str) or len(website) > tg.WEBSITE_MAX or not dg.FIELD_CHECKS["website"](website):
        raise ValueError(f"entry {tid}: website {tg.shown(website)} is not empty or http(s)://host[/...]")
    cats = t.get("categories")
    if (not isinstance(cats, list) or not cats or not all(isinstance(c, str) and c.strip() for c in cats)
            or len(set(cats)) != len(cats)):
        raise ValueError(f"entry {tid}: categories are not a non-empty list of distinct text")
    refs = t.get("references", [])
    if not isinstance(refs, list) or not all(isinstance(r, str) and r.startswith("https://") for r in refs):
        raise ValueError(f"entry {tid}: references are not a list of https:// addresses")
    lists = _supplement_signatures(t, tid, first_party, common)
    return dict(id=tid, name=t["name"], website=website, categories=list(cats),
                code_prefixes=lists["code_prefixes"], code_segments=lists["code_segments"],
                domain_suffixes=lists["domain_suffixes"], domain_labels=lists["domain_labels"],
                domain_patterns=[], excluded_domains=[])


def load_supplement(path=SUPPLEMENT_FILE, first_party=None, common=None):
    """AndroDR's own entries, in the list's final shape and sorted by id.

    Raises (OSError, yaml.YAMLError, ValueError) when the file is missing or any entry is
    faulty. Nothing here is set aside the way a faulty Exodus entry is: the file is written by
    us, so a fault is a mistake to fix, and a quietly dropped entry would be a lost detection.
    """
    if first_party is None:
        first_party = dg.load_first_party_hosts()
    if common is None:
        common = tg.load_common_packages()
    doc = yaml.safe_load(pathlib.Path(path).read_text(encoding="utf-8"))
    if not isinstance(doc, dict) or doc.get("version") != 1 or not isinstance(doc.get("trackers"), list):
        raise ValueError("not a version 1 supplement with a `trackers` list")
    entries, seen = [], set()
    for t in doc["trackers"]:
        entry = _supplement_entry(t, seen, first_party, common)
        seen.add(entry["id"])
        entries.append(entry)
    return sorted(entries, key=lambda e: e["id"])


def render(api, previous, first_party=None, common=None, supplement=None):
    """Normalise an Exodus API dict into (document, drop_report).

    `previous` is the prior document, if any; the shrink guard lives in main().
    `first_party` and `common` are the two breadth lists; main() loads them itself so
    that a fault in either is not mistaken for a fault in an Exodus entry.
    `supplement` is the output of load_supplement(), appended after the Exodus entries;
    None renders the Exodus list alone.
    """
    if first_party is None:
        first_party = dg.load_first_party_hosts()
    if common is None:
        common = tg.load_common_packages()
    report = []
    built = []
    for key in sorted(api.get("trackers", {}), key=lambda k: int(k)):
        t = api["trackers"][key]
        tid = int(t.get("id", key))
        if not 1 <= tid <= tg.ID_MAX:
            report.append(f"{R_TRACKER}: 0: its id {tg.shown(tid)} is not between 1 and {tg.ID_MAX}")
            continue
        if tid >= tg.SUPPLEMENT_ID_MIN:
            report.append(f"{R_TRACKER}: {tid}: its id is in the range reserved for AndroDR's own entries")
            continue
        name = t.get("name")
        problem = tg.name_problem(name)
        if problem:
            report.append(f"{R_TRACKER}: {tid}: name {tg.shown(name)} {problem}")
            continue
        categories = _categories(t.get("categories"))
        if categories is None:
            report.append(f"{R_TRACKER}: {tid}: categories {tg.shown(t.get('categories'))} "
                          "are not a list of text")
            continue
        prefixes, segments = _derive_code(tid, _split(t.get("code_signature")), common, report)
        suffixes, labels, patterns, excluded = _derive_net(
            tid, _split(t.get("network_signature")), first_party, report)
        if len(patterns) > dg.MAX_PATTERNS_PER_TRACKER:
            for p in patterns[dg.MAX_PATTERNS_PER_TRACKER:]:
                report.append(f"{R_CAP}: {tid}: per-tracker cap, {tg.shown(p)}")
            patterns = patterns[:dg.MAX_PATTERNS_PER_TRACKER]
        built.append(dict(
            id=tid, name=name, website=_website(t.get("website")),
            categories=categories,
            code_prefixes=prefixes, code_segments=segments, domain_suffixes=suffixes,
            domain_labels=labels, domain_patterns=patterns, excluded_domains=excluded))
    built.sort(key=lambda t: t["id"])

    total = 0
    trackers = []
    for t in built:
        keep = max(0, dg.MAX_PATTERNS_TOTAL - total)
        for p in t["domain_patterns"][keep:]:
            report.append(f"{R_CAP}: {t['id']}: file cap, {tg.shown(p)}")
        t["domain_patterns"] = t["domain_patterns"][:keep]
        total += len(t["domain_patterns"])
        if not (t["code_prefixes"] or t["code_segments"] or t["domain_suffixes"]
                or t["domain_labels"] or t["domain_patterns"]):
            report.append(f"{R_TRACKER}: {t['id']}: {tg.shown(t['name'])} has no usable signature left")
            continue
        trackers.append(t)

    doc = dict(version=1, source="exodus-privacy", source_url=SOURCE_URL, license="ODbL-1.0",
               attribution=ATTRIBUTION)
    if supplement:
        doc["supplement"] = SUPPLEMENT_NOTE
        trackers = trackers + supplement  # every Exodus id is below every supplement id
    doc["trackers"] = trackers
    return doc, report


def _fetch():
    req = urllib.request.Request(SOURCE_URL, headers={"User-Agent": "androdr-rules-mirror"})
    with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310 - fixed https URL
        return json.loads(resp.read().decode("utf-8"))


def _unreadable(why):
    print(f"ERROR: could not read the Exodus tracker list: {why}", file=sys.stderr)
    return 2


def _previous(path):
    """The list `--previous` names, or None when the option was not given. A missing file raises
    (it would switch the shrink guard off without a word), and so does one that is not a tracker list."""
    if not path:
        return None
    doc = yaml.safe_load(pathlib.Path(path).read_text(encoding="utf-8"))
    if not isinstance(doc, dict) or not isinstance(doc.get("trackers"), list):
        raise ValueError("not a tracker list")
    return doc


def _exodus_count(trackers):
    """How many of `trackers` are Exodus's: all but those with an id in the supplement's range."""
    def ours(t):
        tid = t.get("id") if isinstance(t, dict) else None
        return isinstance(tid, int) and not isinstance(tid, bool) and tid >= tg.SUPPLEMENT_ID_MIN
    return sum(1 for t in trackers if not ours(t))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", required=True)
    ap.add_argument("--from-json")
    ap.add_argument("--previous")
    args = ap.parse_args(argv)

    # Local files first: a fault here is the rules repository's, and must not read as Exodus's.
    try:
        first_party, common = dg.load_first_party_hosts(), tg.load_common_packages()
        supplement = load_supplement(SUPPLEMENT_FILE, first_party, common)
        previous = _previous(args.previous)
    except (OSError, ValueError, yaml.YAMLError) as e:
        print("ERROR: a file the mirror reads from the rules repository is missing or broken "
              f"({type(e).__name__})", file=sys.stderr)
        return 3

    # The exception's message is never printed: it can carry the response body.
    try:
        if args.from_json:
            api = json.loads(pathlib.Path(args.from_json).read_text(encoding="utf-8"))
        else:
            api = _fetch()
    except (OSError, ValueError, RecursionError, http.client.HTTPException) as e:
        return _unreadable(type(e).__name__)
    if not isinstance(api, dict) or not isinstance(api.get("trackers"), dict):
        return _unreadable("no trackers map")

    try:
        doc, report = render(api, previous, first_party, common, supplement)
    except (ArithmeticError, AttributeError, KeyError, RecursionError, TypeError, ValueError) as e:
        return _unreadable(f"an entry is not a tracker ({type(e).__name__})")
    for line in report:
        print(line, file=sys.stderr)
    # The size guards watch Exodus's answer, so our own entries are counted on neither side.
    n = _exodus_count(doc["trackers"])
    # /update-rules reads the first of these two lines by its exact shape; keep it as it is.
    print(f"{n} trackers kept, {len(report)} drop-report lines", file=sys.stderr)
    print(f"{len(doc['trackers']) - n} of AndroDR's own entries appended", file=sys.stderr)
    if n < MIN_TRACKERS:
        print(f"ERROR: only {n} trackers (< {MIN_TRACKERS})", file=sys.stderr)
        return 1
    if previous and previous["trackers"]:
        old = _exodus_count(previous["trackers"])
        if n < old * (1 - MAX_SHRINK):
            print(f"ERROR: tracker count shrank from {old} to {n} (> {MAX_SHRINK:.0%})", file=sys.stderr)
            return 1
    pathlib.Path(args.out).write_text(
        yaml.safe_dump(doc, sort_keys=False, allow_unicode=True, width=120), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
