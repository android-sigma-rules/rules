#!/usr/bin/env python3
"""Add `reference:` to feed-mirrored ioc-data entries the feed confirms.

Usage: backfill-references.py --feed-dir DIR [--write] [files...]
Unconfirmed / report-sourced entries are written to validation/backfill-review.tsv.
"""
import argparse, csv, importlib.util, pathlib, re, sys
import yaml

HERE = pathlib.Path(__file__).parent
_spec = importlib.util.spec_from_file_location("check_reference", HERE / "check-reference.py")
cr = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(cr)

MIRROR_SOURCES = {"stalkerware-indicators", "mvt-indicators", "threatfox", "prodaft-malware-ioc",
                  "zimperium-ioc", "amnesty-investigations", "malwarebazaar"}
DEFAULT_FILES = ["c2-domains.yml", "package-names.yml", "cert-hashes.yml", "malware-hashes.yml"]


def backfill_file(path, feed_dir, write):
    path = pathlib.Path(path)
    entries = (yaml.safe_load(path.read_text()) or {}).get("entries", [])
    lines = path.read_text().split("\n")
    review, inserts = [], {}
    for e in entries:
        if "indicator" not in e or e.get("reference"):
            continue
        src, fam, ind = e.get("source", ""), e.get("family", ""), str(e["indicator"])
        if src not in MIRROR_SOURCES:
            review.append(dict(file=path.name, indicator=ind, family=fam, source=src,
                               status="NEEDS_REPORT_URL", detail=""))
            continue
        ref = f"feed:{src}#{fam or 'unknown'}"
        status, detail = cr.check(ind, ref, str(feed_dir))
        if status == "FOUND":
            inserts[ind] = ref
        else:
            review.append(dict(file=path.name, indicator=ind, family=fam, source=src,
                               status=status, detail=detail))
    if write and inserts:
        out, current = [], None
        for line in lines:
            m = re.match(r'\s*-\s+indicator:\s*"?([^"\s]+)"?', line)
            if m:
                current = m.group(1)
            out.append(line)
            sm = re.match(r'(\s*)source:\s*', line)
            if sm and current in inserts:
                out.append(f'{sm.group(1)}reference: {inserts.pop(current)}')
        assert not inserts, f"confirmed references not written (unexpected layout): {sorted(inserts)}"
        path.write_text("\n".join(out))
    return review


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--feed-dir", required=True)
    ap.add_argument("--write", action="store_true")
    ap.add_argument("files", nargs="*")
    a = ap.parse_args()
    root = HERE.parent / "ioc-data"
    files = [pathlib.Path(f) for f in a.files] or [root / f for f in DEFAULT_FILES]
    rows = []
    for f in files:
        rows += backfill_file(f, a.feed_dir, a.write)
    with open(HERE / "backfill-review.tsv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["file", "indicator", "family", "source", "status", "detail"],
                           delimiter="\t")
        w.writeheader(); w.writerows(rows)
    print(f"{len(rows)} entries need review -> validation/backfill-review.tsv")


if __name__ == "__main__":
    main()
