"""Restricted domain-pattern grammar shared by the Exodus mirror and the validator.

Ported line-for-line to Kotlin (TrackerSet) in the app; keep it simple.

A pattern is a sequence of atoms, each optionally followed by one of * + ?.
An atom is a lower-case letter, digit or '-', an escaped \\. or \\-, a bare '.',
or a non-empty class [...] whose items are a single [a-z0-9], exactly a-z,
exactly 0-9, or a literal '-' in first or last position. The tokenizer is
hand-written (not a meta-regex) and rejects everything else, so no pattern
can be catastrophically backtracking.
"""
import pathlib
import re
from typing import Callable

MAX_PATTERNS_PER_TRACKER = 4
MAX_PATTERNS_TOTAL = 64
MAX_PATTERN_LENGTH = 200
MAX_QUANTIFIERS = 2

_LITERAL = set("abcdefghijklmnopqrstuvwxyz0123456789-")
_QUANTIFIERS = "*+?"
_FIRST_PARTY_FILE = pathlib.Path(__file__).parent / "first_party_hosts.txt"


def _tokenize_class(body: str):
    """Return the regex text for a class body, or None when it is not allowed."""
    if not body:
        return None
    out = []
    i = 0
    n = len(body)
    while i < n:
        c = body[i]
        if c == "-":
            if i != 0 and i != n - 1:
                return None
            out.append("\\-")
            i += 1
        elif c in _LITERAL:
            if i + 1 < n and body[i + 1] == "-" and i + 2 < n:
                if body[i:i + 3] not in ("a-z", "0-9"):
                    return None
                out.append(body[i:i + 3])
                i += 3
            else:
                out.append(c)
                i += 1
        else:
            return None
    return "[" + "".join(out) + "]"


def _tokenize(p: str):
    """Return a list of (regex_text, quantifier) atoms, or None when rejected."""
    atoms = []
    i = 0
    n = len(p)
    while i < n:
        c = p[i]
        if c == "\\":
            if i + 1 < n and p[i + 1] in ".-":
                text = "\\." if p[i + 1] == "." else "\\-"
                i += 2
            else:
                return None
        elif c == "[":
            end = p.find("]", i + 1)
            if end < 0:
                return None
            text = _tokenize_class(p[i + 1:end])
            if text is None:
                return None
            i = end + 1
        elif c == ".":
            text = "."
            i += 1
        elif c in _LITERAL:
            text = c
            i += 1
        else:
            return None
        quant = ""
        if i < n and p[i] in _QUANTIFIERS:
            quant = p[i]
            i += 1
        atoms.append((text, quant))
    return atoms


def compile_pattern(p):
    """Compile a restricted pattern, or return None when it is not accepted."""
    if not isinstance(p, str) or not p or len(p) > MAX_PATTERN_LENGTH:
        return None
    atoms = _tokenize(p)
    if not atoms:
        return None
    if sum(1 for _, q in atoms if q) > MAX_QUANTIFIERS:
        return None
    if all(q in ("*", "?") for _, q in atoms):
        return None  # would match the empty string
    try:
        return re.compile("".join(t + q for t, q in atoms))
    except re.error:
        return None


def is_restricted_pattern(p) -> bool:
    return compile_pattern(p) is not None


def _is_prefix(s) -> bool:
    return isinstance(s, str) and re.fullmatch(r"[a-z0-9_]+(\.[A-Za-z0-9_]+)+", s) is not None


def _is_segment(s) -> bool:
    return isinstance(s, str) and re.fullmatch(r"[a-z0-9_]+", s) is not None


def _is_suffix(s) -> bool:
    return isinstance(s, str) and re.fullmatch(r"[a-z0-9-]+(\.[a-z0-9-]+)+", s) is not None


def _is_label(s) -> bool:
    return isinstance(s, str) and re.fullmatch(r"[a-z0-9-]+", s) is not None


FIELD_CHECKS: dict[str, Callable[[str], bool]] = {
    "prefix": _is_prefix,
    "segment": _is_segment,
    "suffix": _is_suffix,
    "label": _is_label,
    "pattern": is_restricted_pattern,
}


def matches_host(kind: str, value: str, host: str) -> bool:
    """The single definition of suffix / label / pattern matching against a host."""
    host = host.lower()
    labels = host.split(".")
    if kind == "suffix":
        return host == value or host.endswith("." + value)
    if kind == "label":
        return value in labels
    if kind == "pattern":
        rx = compile_pattern(value)
        if rx is None:
            return False
        return any(rx.fullmatch(".".join(labels[i:])) for i in range(len(labels)))
    raise ValueError(f"unknown kind: {kind}")


def load_first_party_hosts(path: pathlib.Path = _FIRST_PARTY_FILE) -> list[str]:
    return [ln.strip() for ln in path.read_text().splitlines()
            if ln.strip() and not ln.startswith("#")]
