#!/usr/bin/env python3
"""Summarise what changed between two tracker lists (ioc-data/trackers.yml format).

The summary is what a person reads before approving a tracker-list refresh, so
it is generated, never written by hand: the two files are compared as data
(formatting and list order are not changes) and every added signature, network
and code, is printed in full.

Tracker names, websites and signatures come from an external list. They are
printed one value per line, escaped to printable ASCII and cut at a fixed
length, so nothing in them can pose as part of the summary.

Usage:
    python3 validation/summarize-tracker-changes.py --old ioc-data/trackers.yml \
        --new CANDIDATE [--drop-report MIRROR_STDERR_FILE]

Exit codes: 0 summary printed (first line "Tracker list: no change" when the
two files hold the same data); 2 a file could not be read or is not a tracker
list (one "ERROR:" line on stderr, nothing on stdout).
"""
import argparse
import json
import pathlib
import re
import sys

import yaml

sys.path.insert(0, str(pathlib.Path(__file__).parent))
import tracker_guards as tg  # noqa: E402

NO_CHANGE = "Tracker list: no change"

SIGNATURE_KINDS = {
    "code_prefixes": "prefix",
    "code_segments": "segment",
    "domain_suffixes": "suffix",
    "domain_labels": "label",
    "domain_patterns": "pattern",
}
NETWORK_FIELDS = ("domain_suffixes", "domain_labels", "domain_patterns")
CODE_FIELDS = ("code_prefixes", "code_segments")
KNOWN_FIELDS = {"id", "name", "website", "categories", "excluded_domains", *SIGNATURE_KINDS}

# The validator refuses longer names, websites and signatures (tracker_guards), so a value in
# a candidate that passed validation is never cut. The cuts bound everything else.
NAME_MAX = tg.NAME_MAX
WEBSITE_MAX = tg.WEBSITE_MAX
LINE_MAX = tg.SIGNATURE_MAX + 2
CUT = " [cut]"

ALWAYS_SHOWN_REASON = "tracker dropped"
DROP_LINE = re.compile(r"^([a-z][a-z -]*[a-z]): ([0-9]{1,9}): ")


class SummaryError(ValueError):
    """An input is missing, unreadable or not a tracker list."""


def _text(value):
    return value if isinstance(value, str) else repr(value)


def _quoted(value, limit=NAME_MAX):
    """One line, in double quotes, printable ASCII only."""
    if value is None:
        return "(absent)"
    text = _text(value)
    out = json.dumps(text[:limit], ensure_ascii=True).replace("\x7f", "\\u007f")
    return out + (CUT if len(text) > limit else "")


def _plain(value, limit=LINE_MAX):
    """One line, unquoted, printable ASCII only."""
    text = _text(value)
    out = "".join(c if 32 <= ord(c) < 127 else c.encode("unicode_escape").decode("ascii") for c in text[:limit])
    return out + (CUT if len(text) > limit else "")


def _items(value):
    if value is None:
        return []
    if isinstance(value, list):
        return [_text(v) for v in value]
    return [_text(value)]


def _set_change(old, new):
    old_set, new_set = set(_items(old)), set(_items(new))
    return {"added": sorted(new_set - old_set), "removed": sorted(old_set - new_set)}


def _index(doc, label):
    if not isinstance(doc, dict) or not isinstance(doc.get("trackers"), list):
        raise SummaryError(f"{label}: not a tracker list (no 'trackers' list)")
    out = {}
    for t in doc["trackers"]:
        if not isinstance(t, dict) or type(t.get("id")) is not int:
            raise SummaryError(f"{label}: a tracker without a whole-number id")
        if t["id"] in out:
            raise SummaryError(f"{label}: repeated tracker id {t['id']}")
        out[t["id"]] = t
    return out


def _tracker_change(old, new):
    """The change record for one tracker present in both lists, or None when nothing differs."""
    signatures = {}
    for field in SIGNATURE_KINDS:
        change = _set_change(old.get(field), new.get(field))
        if change["added"] or change["removed"]:
            signatures[field] = change
    old_cats, new_cats = sorted(set(_items(old.get("categories")))), sorted(set(_items(new.get("categories"))))
    entry = {
        "id": new["id"],
        "name": new.get("name"),
        "renamed": (old.get("name"), new.get("name")) if old.get("name") != new.get("name") else None,
        "website": (old.get("website"), new.get("website")) if old.get("website") != new.get("website") else None,
        "categories": (old_cats, new_cats) if old_cats != new_cats else None,
        "signatures": signatures,
        "excluded": _set_change(old.get("excluded_domains"), new.get("excluded_domains")),
        "other": [(k, old.get(k), new.get(k)) for k in sorted((set(old) | set(new)) - KNOWN_FIELDS, key=_text)
                  if old.get(k) != new.get(k)],
    }
    differs = (entry["renamed"] or entry["website"] or entry["categories"] or signatures or entry["other"]
               or entry["excluded"]["added"] or entry["excluded"]["removed"])
    return entry if differs else None


def diff(old, new):
    """Compare two parsed tracker documents. Raises SummaryError when either is not a tracker list."""
    old_by_id, new_by_id = _index(old, "old list"), _index(new, "new list")
    added = [new_by_id[i] for i in sorted(set(new_by_id) - set(old_by_id))]
    removed = [old_by_id[i] for i in sorted(set(old_by_id) - set(new_by_id))]
    changed = []
    for i in sorted(set(old_by_id) & set(new_by_id)):
        entry = _tracker_change(old_by_id[i], new_by_id[i])
        if entry:
            changed.append(entry)

    def new_signatures(fields):
        out = []
        for t in added:
            for field in fields:
                for value in set(_items(t.get(field))):
                    out.append((t["id"], t.get("name"), SIGNATURE_KINDS[field], value))
        for c in changed:
            for field in fields:
                for value in c["signatures"].get(field, {}).get("added", []):
                    out.append((c["id"], c["name"], SIGNATURE_KINDS[field], value))
        return sorted(out, key=lambda n: (n[0], n[2], n[3]))

    header_keys = sorted((set(old) | set(new)) - {"trackers"}, key=_text)
    return {
        "old_count": len(old_by_id),
        "new_count": len(new_by_id),
        "header": [(k, old.get(k), new.get(k)) for k in header_keys if old.get(k) != new.get(k)],
        "added": added,
        "removed": removed,
        "changed": changed,
        "new_network": new_signatures(NETWORK_FIELDS),
        "new_code": new_signatures(CODE_FIELDS),
    }


def is_unchanged(d):
    return not (d["added"] or d["removed"] or d["changed"] or d["header"])


def _categories(values):
    return "[" + ", ".join(_plain(v, 40) for v in values) + "]"


def _added_lines(t):
    cats = _categories(sorted(set(_items(t.get("categories")))))
    lines = [f"  {t['id']} {_quoted(t.get('name'))}  {_quoted(t.get('website'), WEBSITE_MAX)}  {cats}"]
    for field, kind in SIGNATURE_KINDS.items():
        lines += [f"      {kind:<8} {_plain(v)}" for v in sorted(set(_items(t.get(field))))]
    lines += [f"      set aside as first-party: {_plain(v)}" for v in sorted(set(_items(t.get("excluded_domains"))))]
    return lines


def _changed_lines(c):
    lines = [f"  {c['id']} {_quoted(c['name'])}"]
    if c["renamed"]:
        lines.append(f"      renamed from {_quoted(c['renamed'][0])}")
    if c["website"]:
        old, new = c["website"]
        lines.append(f"      website {_quoted(old, WEBSITE_MAX)} -> {_quoted(new, WEBSITE_MAX)}")
    if c["categories"]:
        lines.append(f"      categories {_categories(c['categories'][0])} -> {_categories(c['categories'][1])}")
    for field, kind in SIGNATURE_KINDS.items():
        change = c["signatures"].get(field, {})
        lines += [f"      + {kind:<8} {_plain(v)}" for v in change.get("added", [])]
        lines += [f"      - {kind:<8} {_plain(v)}" for v in change.get("removed", [])]
    lines += [f"      set aside as first-party: + {_plain(v)}" for v in c["excluded"]["added"]]
    lines += [f"      set aside as first-party: - {_plain(v)}" for v in c["excluded"]["removed"]]
    lines += [f"      other field {_plain(k, 40)}: {_quoted(old, WEBSITE_MAX)} -> {_quoted(new, WEBSITE_MAX)}"
              for k, old, new in c["other"]]
    return lines


def _drop_lines(d, drop_lines):
    touched = {t["id"] for t in d["added"]} | {t["id"] for t in d["removed"]} | {c["id"] for c in d["changed"]}
    counts, shown = {}, []
    for line in drop_lines:
        m = DROP_LINE.match(line)
        if not m:
            continue
        reason = m.group(1)
        counts[reason] = counts.get(reason, 0) + 1
        if reason == ALWAYS_SHOWN_REASON or int(m.group(2)) in touched:
            shown.append(f"  {_plain(line)}")
    if not counts:
        return []
    return (["DROPPED BY THE MIRROR (counts, then the lines for trackers in this change and every dropped tracker)"]
            + [f"  {reason}: {counts[reason]}" for reason in sorted(counts)] + shown)


def render(d, drop_lines):
    """The review summary as text. `drop_lines` is the mirror's stderr, one line per item."""
    if is_unchanged(d):
        return NO_CHANGE + "\n"
    lines = [f"Tracker list: {len(d['added'])} added, {len(d['removed'])} removed, {len(d['changed'])} changed "
             f"({d['old_count']} -> {d['new_count']} trackers)", ""]
    if d["new_network"]:
        lines.append(f"NEW NETWORK SIGNATURES ({len(d['new_network'])}) - check each: "
                     "would it also match a host used for ordinary services?")
        lines += [f"  {tid}  {_quoted(name)}  {kind:<8} {_plain(value)}" for tid, name, kind, value in d["new_network"]]
    if d["new_code"]:
        lines.append(f"NEW CODE SIGNATURES ({len(d['new_code'])}) - check each: "
                     "would it also match a package that ordinary apps contain?")
        lines += [f"  {tid}  {_quoted(name)}  {kind:<8} {_plain(value)}" for tid, name, kind, value in d["new_code"]]
    if d["added"]:
        lines.append(f"ADDED ({len(d['added'])})")
        for t in d["added"]:
            lines += _added_lines(t)
    if d["removed"]:
        lines.append(f"REMOVED ({len(d['removed'])})")
        lines += [f"  {t['id']} {_quoted(t.get('name'))}" for t in d["removed"]]
    if d["changed"]:
        lines.append(f"CHANGED ({len(d['changed'])})")
        for c in d["changed"]:
            lines += _changed_lines(c)
    if d["header"]:
        lines.append("FILE HEADER")
        lines += [f"  {_plain(k, 40)}: {_quoted(old, WEBSITE_MAX)} -> {_quoted(new, WEBSITE_MAX)}"
                  for k, old, new in d["header"]]
    lines += _drop_lines(d, drop_lines)
    return "\n".join(lines) + "\n"


def _read_yaml(path, label):
    try:
        return yaml.safe_load(pathlib.Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as e:
        raise SummaryError(f"{label}: cannot be read as YAML ({type(e).__name__})") from None


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--old", required=True, help="the list in use (ioc-data/trackers.yml)")
    ap.add_argument("--new", required=True, help="the candidate list")
    ap.add_argument("--drop-report", help="a file holding the mirror script's stderr")
    args = ap.parse_args(argv)

    try:
        d = diff(_read_yaml(args.old, "old list"), _read_yaml(args.new, "new list"))
        drop_lines = []
        if args.drop_report:
            try:
                drop_lines = pathlib.Path(args.drop_report).read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError as e:
                raise SummaryError(f"drop report: cannot be read ({type(e).__name__})") from None
        text = render(d, drop_lines)
    except SummaryError as e:
        print(f"ERROR: {_plain(str(e))}", file=sys.stderr)
        return 2
    sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
