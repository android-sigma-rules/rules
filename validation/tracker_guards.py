"""Limits and breadth guards for the tracker list (ioc-data/trackers.yml).

Shared by the mirror (which sets aside what breaks them), the validator (which
refuses it) and the review summary (which therefore never has to cut a value
that passed validation).
"""
import pathlib
import unicodedata

# Exodus numbers its trackers from 1; nine digits is also all the review summary reads as an id.
ID_MAX = 999_999_999
# Ids from here up belong to AndroDR's own entries (validation/tracker-supplement.yml). An Exodus
# entry that reaches this range is set aside.
SUPPLEMENT_ID_MIN = 900_001
# The categories Exodus uses, and the ones only AndroDR's own entries may carry.
EXODUS_CATEGORIES = frozenset({"Advertisement", "Profiling", "Identification", "Location", "Analytics",
                               "Crash reporting", "Uncategorised"})
SUPPLEMENT_CATEGORIES = frozenset({"Proxyware"})
TRACKER_CATEGORIES = EXODUS_CATEGORIES | SUPPLEMENT_CATEGORIES
# (yaml field, domain_grammar.FIELD_CHECKS key, matches_host kind or None) for each signature list
# of a tracker entry. The mirror's supplement loader and the validator both walk this table.
SIGNATURE_LISTS = (
    ("code_prefixes", "prefix", None),
    ("code_segments", "segment", None),
    ("domain_suffixes", "suffix", "suffix"),
    ("domain_labels", "label", "label"),
    ("domain_patterns", "pattern", "pattern"),
)
NAME_MAX = 80
WEBSITE_MAX = 200
# A full host name; the app ignores longer hosts (TrackerSet.MAX_HOST_CHARS).
SIGNATURE_MAX = 253
# How much of an offending value an error or drop-report line repeats.
SHOWN_MAX = 60

_COMMON_PACKAGES_FILE = pathlib.Path(__file__).parent / "common_packages.txt"
# Control, formatting (bidi overrides, zero-width), surrogate, private-use, line and paragraph separators.
_UNPRINTABLE = {"Cc", "Cf", "Cs", "Co", "Zl", "Zp"}


def name_problem(name):
    """Why `name` cannot be a tracker's display name, or None when it can."""
    if not isinstance(name, str) or not name.strip():
        return "is missing or not text"
    if len(name) > NAME_MAX:
        return f"is longer than {NAME_MAX} characters"
    if any(unicodedata.category(c) in _UNPRINTABLE for c in name):
        return "has a control or formatting character"
    return None


def shown(value):
    """`value` as it may appear in an error or report line: one line of printable ASCII, cut short."""
    text = ascii(value)
    return text if len(text) <= SHOWN_MAX else text[:SHOWN_MAX] + "..."


def load_common_packages(path: pathlib.Path = _COMMON_PACKAGES_FILE) -> list[str]:
    return [ln.strip() for ln in path.read_text(encoding="utf-8").splitlines()
            if ln.strip() and not ln.startswith("#")]


def matches_package(kind: str, value: str, package: str) -> bool:
    """The app's code-signature rule (TrackerSet.matchPackages): a prefix matches a package it
    equals or is a dotted parent of; a segment matches a package that has it as one dotted part."""
    if kind == "prefix":
        return package == value or package.startswith(value + ".")
    if kind == "segment":
        return value in package.split(".")
    raise ValueError(f"unknown kind: {kind}")


def name_key(name):
    """What two tracker names are compared by: an Exodus entry must not carry the name of one of
    AndroDR's own, however it is cased or spaced."""
    return " ".join(name.split()).casefold() if isinstance(name, str) else ""
