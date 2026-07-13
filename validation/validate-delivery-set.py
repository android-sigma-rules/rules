#!/usr/bin/env python3
"""Validate the DELIVERY SET (rules.txt) as a whole.

Per-file shape checks live in validate-rule.py; this script guards the
cross-file properties of what devices actually fetch. On-device,
SigmaRuleEngine merges remote rules by `associateBy { it.id }` (last wins),
so the delivery set — not any single file — is the security boundary:

  1. containment — every rules.txt path lives in a production service dir.
     correlation/ is cataloged-but-not-delivered (the on-device parser
     silently drops corr payloads fetched remotely) and staging/ is
     aspirational; a path into either is a policy violation, see
     decisions/2026-07-13-mirror-reconcile.yml.
  2. existence — every listed file exists.
  3. basename uniqueness — two entries with one basename make the
     bundled-parity check ambiguous (AndroDR's BundledMirrorParityTest
     matches by basename).
  4. id uniqueness — duplicate ids across the set mean last-listed silently
     shadows the other on-device.
  5. id ↔ filename consistency — androdr_078_*.yml must declare
     androdr-078; androdr_atom_x_y.yml must declare androdr-atom-x-y. A
     mismatch is how a "new" file shadows an existing rule's id past review.

Usage: python3 validate-delivery-set.py [--repo-root PATH]
Exit codes: 0 = valid, 1 = violations (printed to stderr).
"""

import importlib.util
import re
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent

# Single source of truth for the non-deliverable dir set lives in
# validate-rule.py (dash in filename → load by path, not import).
_spec = importlib.util.spec_from_file_location(
    "validate_rule", SCRIPT_DIR / "validate-rule.py"
)
_validate_rule = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_validate_rule)
NON_DELIVERABLE_DIRS = _validate_rule.NON_DELIVERABLE_DIRS

ID_RE = re.compile(r"^id:\s*(\S+)", re.M)


def expected_id_for(basename: str) -> str | None:
    """Derive the id a file's name promises, or None if unparseable."""
    stem = basename.removesuffix(".yml")
    parts = stem.split("_")
    if len(parts) < 2 or parts[0] != "androdr":
        return None
    if parts[1].isdigit():
        return f"androdr-{parts[1]}"
    if parts[1] == "atom" and len(parts) > 2:
        return "androdr-atom-" + "-".join(parts[2:])
    return None


def validate_delivery_set(repo_root: Path) -> list[str]:
    errors = []
    rules_txt = repo_root / "rules.txt"
    if not rules_txt.is_file():
        return ["rules.txt not found"]

    entries = [
        line.strip() for line in rules_txt.read_text().splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]

    seen_basenames: dict[str, str] = {}
    seen_ids: dict[str, str] = {}

    for entry in entries:
        top = entry.split("/", 1)[0]
        if "/" not in entry or top in NON_DELIVERABLE_DIRS or top.startswith("."):
            errors.append(
                f"{entry}: not a production service-dir path — correlation/ "
                "and staging/ are never deliverable (see decisions/"
                "2026-07-13-mirror-reconcile.yml)"
            )
            continue

        path = repo_root / entry
        if not path.is_file():
            errors.append(f"{entry}: listed in rules.txt but file does not exist")
            continue

        basename = entry.rsplit("/", 1)[-1]
        if basename in seen_basenames:
            errors.append(
                f"{entry}: basename collides with {seen_basenames[basename]} — "
                "parity checks match by basename, collisions make them ambiguous"
            )
        seen_basenames[basename] = entry

        m = ID_RE.search(path.read_text())
        if not m:
            errors.append(f"{entry}: no id: field found")
            continue
        rule_id = m.group(1)

        if rule_id in seen_ids:
            errors.append(
                f"{entry}: id {rule_id} duplicates {seen_ids[rule_id]} — "
                "on-device merge is last-wins by id, one silently shadows the other"
            )
        seen_ids[rule_id] = entry

        expected = expected_id_for(basename)
        if expected is None:
            errors.append(
                f"{entry}: filename does not follow androdr_NNN_*.yml / "
                "androdr_atom_*.yml naming"
            )
        elif rule_id != expected:
            errors.append(
                f"{entry}: declares id {rule_id} but filename promises {expected} — "
                "an id/filename mismatch is how a new file shadows an existing "
                "rule past review"
            )

    return errors


def main() -> None:
    repo_root = SCRIPT_DIR.parent
    if len(sys.argv) == 3 and sys.argv[1] == "--repo-root":
        repo_root = Path(sys.argv[2])

    errors = validate_delivery_set(repo_root)
    if errors:
        print(f"FAIL: delivery set — {len(errors)} violation(s):", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        sys.exit(1)
    print(f"PASS: delivery set ({repo_root / 'rules.txt'})")


if __name__ == "__main__":
    main()
