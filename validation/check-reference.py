#!/usr/bin/env python3
"""Does a cited source actually mention this IOC (and, for feeds, its family)?

Usage:
  check-reference.py --indicator VALUE --reference REF [--feed-dir DIR] [--allowed-prefixes FILE]
  check-reference.py --entries CANDIDATE.yml --allowed-sources allowed-sources.json [--feed-dir DIR]

Pipelines and agents use only the --entries form: values are read from the file, never
from a shell command line.

REF is https://... (fetched, HTML parsed) or feed:<source-id>#<family>
(looked up in DIR/<source-id>.txt, a pre-downloaded dump from fetch-feed-dumps.sh; no network).

Exit: 0 FOUND; 1 NOT_FOUND / WEAK_FOUND / FAMILY_MISMATCH;
      2 FETCH_UNSUPPORTED / FETCH_FAILED / BLOCKED_URL / BAD_INPUT.
"""
import argparse
import bisect
import functools
import html
import http.client
import ipaddress
import json
import multiprocessing
import os
import re
import socket
import sys
import unicodedata
import urllib.parse
import urllib.request
from html.parser import HTMLParser

UA = "Mozilla/5.0 (AndroDR reference check)"
MAX_BYTES = 8 * 1024 * 1024
DEADLINE_S = 45
MAX_REDIRECTS = 3
MAX_OCCURRENCES = 1000   # accepted occurrences per check, across sections and variants
TEXT_TYPES = ("text/html", "text/plain", "application/json", "text/csv", "application/xml", "text/xml")
EXIT = {"FOUND": 0, "NOT_FOUND": 1, "WEAK_FOUND": 1, "FAMILY_MISMATCH": 1, "SECTION_CITED": 1}   # CAPPED -> 2
JS_SHELL_MAX_PROSE = 400   # an HTML page with less static prose than this and a <script>/<noscript> is a JS shell

_SAFE_INDICATOR = re.compile(r"[A-Za-z0-9._:-]{1,253}")
# No query string and no port other than 443 (plan gate round 6, S6-2/S6-5): a site's search page
# (?s=<indicator>) echoes any indicator back as prose.
_SAFE_HTTPS = re.compile(r"https://[A-Za-z0-9.-]+(?::443)?(?:/[A-Za-z0-9._~%/+,=@-]*)?")
_STRIP_CATEGORIES = {"Cc", "Cf", "Zl", "Zp", "Co", "Cs"}   # controls, bidi/zero-width formats, separators


def _clean(text):
    """No control, bidi-override or invisible characters (round 7, S7-2: Trojan-Source-style snippets)."""
    return "".join(" " if unicodedata.category(c) in _STRIP_CATEGORIES else c for c in text)
_SAFE_FEED = re.compile(r"feed:([a-z0-9_-]{1,40})#([A-Za-z0-9 ._()+-]{1,80})")


def normalize(text: str) -> str:
    t = html.unescape(text)
    t = re.sub(r"\[\.\]|\(\.\)|\[dot\]|\(dot\)|\{\.\}", ".", t, flags=re.I)
    t = re.sub(r"\bhxxp", "http", t, flags=re.I)
    return t.lower()


class _Text(HTMLParser):
    """Prose = text outside <script>/<style>; weak = attribute values. Linear, no regex backtracking."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.prose, self.weak, self._skip = [], [], 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self._skip += 1
        self.weak.extend(v for _, v in attrs if v)

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self._skip:
            self._skip -= 1

    def handle_data(self, data):
        if not self._skip:
            self.prose.append(data)


def _variants(indicator):
    v = indicator.strip().lower()
    yield v
    if re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", v):
        yield ":".join(v[i:i + 2] for i in range(0, len(v), 2))


def _pattern(v):
    # Not preceded by [a-z0-9_-]; not followed by [a-z0-9_-] or ".<label>" —
    # so sub.ab.com mentions ab.com but grab.com and ab.com.au do not.
    return r"(?<![a-z0-9_-])" + re.escape(v) + r"(?![a-z0-9_-]|\.[a-z0-9])"


_URL = re.compile(r"""https?://[^\s"'<>]+""")


def _url_to_host(m):
    """Keep a URL's host as prose (a C2 listed as a URL is a mention); drop path/query."""
    try:
        return " " + (urllib.parse.urlparse(m.group(0)).hostname or "") + " "
    except ValueError:  # e.g. "https://[redacted].evil.example/" in a report
        return " "


def find_indicator(indicator, text):
    """(FOUND|WEAK_FOUND|NOT_FOUND, snippet). WEAK = only in a URL path/query or tag attribute."""
    p = _Text()
    p.feed(text)
    p.close()
    raw_prose = normalize(" ".join(p.prose))
    prose = _URL.sub(_url_to_host, raw_prose)
    weak = raw_prose + " " + normalize(" ".join(p.weak))
    for v in _variants(indicator):
        m = re.search(_pattern(v), prose)
        if m:
            s = max(0, m.start() - 70)
            return "FOUND", " ".join(prose[s:m.end() + 70].split())
    for v in _variants(indicator):
        if re.search(_pattern(v), weak):
            return "WEAK_FOUND", "indicator appears only inside a URL or link"
    return "NOT_FOUND", ""


_CGNAT = ipaddress.ip_network("100.64.0.0/10")
_CODE_HOSTS = {"github.com", "gitlab.com", "gist.github.com", "bitbucket.org", "codeberg.org"}
_CODE_HOST_DENIED = {"issues", "pull", "pulls", "discussions", "wiki", "commit", "commits", "compare",
                     "merge_requests", "merge-requests"}
_HEXSEG = re.compile(r"(?i)[0-9a-f]{7,40}")
_BAD_PATH = re.compile(r"(?i)%2e|%2f|%5c|\\")
# %XX that decodes to an unreserved character is never needed (RFC 3986 §2.3) and only serves to
# hide an indicator from the "indicator is in the URL itself" cap (round 7, S7-1: /search/%65vil.com/).
_ENCODED_UNRESERVED = re.compile(r"(?i)%(?:4[1-9a-f]|5[0-9a]|6[1-9a-f]|7[0-9a]|3[0-9]|2d|5f|7e|25)")   # + %25: no double encoding (S8-2)


def _url_text(url):
    """What a page could echo from its own URL: decoded and compatibility-folded (S8-2: full-width forms)."""
    return normalize(unicodedata.normalize("NFKC", urllib.parse.unquote(url)))


def _indicator_in_url(indicator, url):
    return any(v in _url_text(url) for v in _variants(indicator))
_PIN_REPO = re.compile(r"/[^/]+/[^/]+/(?:-/)?(?:blob|tree|raw)/([^/]+)/(?:[^/]+/)*")       # github.com, gitlab.com
_PIN_RAW = re.compile(r"/[^/]+/[^/]+/(?:refs/heads/)?([^/]+)/(?:[^/]+/)*")                  # raw.githubusercontent.com


def _is_code_host(host):
    return host in _CODE_HOSTS or host == "githubusercontent.com" or host.endswith(".githubusercontent.com")


def _is_public(ip):
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast
                or ip.is_reserved or ip.is_unspecified or (ip.version == 4 and ip in _CGNAT))


def code_host_problem(path):
    """Shared by url_problem and validate-ioc-data.py so the two copies can't drift (round 8, R8-7)."""
    segs = [s for s in urllib.parse.unquote(path).split("/") if s]
    if any(s.lower() in _CODE_HOST_DENIED for s in segs):
        return "user-writable page on a code host (issues/PRs/discussions/wiki/commits)"
    if any(_HEXSEG.fullmatch(s) for s in segs):
        return "commit-like path segment on a code host (fork commits are served under the parent)"
    return None


def _bad_path(path):
    if _BAD_PATH.search(path) or _ENCODED_UNRESERVED.search(path):
        return True
    return any(s in (".", "..") for s in urllib.parse.unquote(path).split("/"))


def _parse(url):
    try:
        p = urllib.parse.urlparse(url)
        return p, p.hostname   # .hostname raises ValueError on "https://[redacted]/x"
    except ValueError:
        return None, None


def prefix_problem(prefix):
    """None if `prefix` is an acceptable reference_prefixes entry (shared with validate-ioc-data.py)."""
    p, host = _parse(prefix)
    if p is None or p.scheme != "https" or not host:
        return "not an https URL"
    if p.username or p.password or p.query or p.fragment or p.port not in (None, 443):
        return "prefix must be scheme://host/path/ only"
    if host.endswith("."):
        return "trailing dot in host"
    if not p.path.endswith("/"):
        return "prefix must end with '/'"
    if _bad_path(p.path):
        return "prefix path has '.'/'..' segments or encoded separators"
    if not _is_code_host(host):
        return None
    pin = {"github.com": _PIN_REPO, "gitlab.com": _PIN_REPO, "raw.githubusercontent.com": _PIN_RAW}.get(host)
    if pin is None:
        return f"{host} serves arbitrary users' content and cannot be a reference prefix"
    m = pin.fullmatch(p.path)
    if not m:
        return "code-host prefix must be pinned to a branch: /<owner>/<repo>/(blob|tree)/<branch>/ (or raw: /<owner>/<repo>/<branch>/)"
    if _HEXSEG.fullmatch(m.group(1)) or m.group(1) == "refs":
        return "code-host prefix is pinned to a commit-like or refs segment, not a branch"
    return None


def url_problem(url, allowed_prefixes):
    p, host = _parse(url)
    if p is None:
        return "URL does not parse"
    if p.scheme != "https" or not host:
        return "not an https URL"
    if p.username or p.password:
        return "credentials in URL"
    if p.query or p.fragment or p.port not in (None, 443):
        return "query string, fragment or non-443 port"
    if host.endswith("."):
        return "trailing dot in host"     # github.com. would skip every code-host rule
    if host == "localhost" or host.endswith(".local"):
        return "local host"
    if _bad_path(p.path):
        return "path has '.'/'..' segments or encoded separators"
    try:
        addrs = {ipaddress.ip_address(a[4][0]) for a in socket.getaddrinfo(host, 443)}
    except (socket.gaierror, ValueError, UnicodeError):
        return "host does not resolve"
    if not addrs or not all(_is_public(a) for a in addrs):
        return "host resolves to a non-public address"
    if _is_code_host(host):
        problem = code_host_problem(p.path)
        if problem:
            return problem
    if allowed_prefixes is not None and not any(_under_prefix(p, host, a) for a in allowed_prefixes):
        return "URL not under an allowed reference prefix"
    return None


def _under_prefix(p, host, prefix):
    q, qhost = _parse(prefix)
    return q is not None and host == qhost and (p.path or "/").startswith(q.path or "/")


class RedirectRefused(Exception):
    pass


class _CheckedHTTPSConnection(http.client.HTTPSConnection):
    """Checks the address actually connected to before the request is sent (every hop)."""

    def connect(self):
        super().connect()
        peer = ipaddress.ip_address(self.sock.getpeername()[0])
        if not _is_public(peer):
            self.sock.close()
            raise RedirectRefused(f"connected to non-public address {peer}")


class _CheckedHTTPSHandler(urllib.request.HTTPSHandler):
    def https_open(self, req):
        return self.do_open(_CheckedHTTPSConnection, req, context=self._context)


class _Redirects(urllib.request.HTTPRedirectHandler):
    def __init__(self, allowed):
        self.allowed, self.count, self.hops = allowed, 0, []

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self.count += 1
        self.hops.append(newurl)
        problem = url_problem(newurl, self.allowed)
        if self.count > MAX_REDIRECTS or problem:
            raise RedirectRefused(problem or "too many redirects")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch(url, allowed):
    """(body, content type, final URL, redirect hop URLs) — the cap in _check_url looks at every URL (S8-3)."""
    redirects = _Redirects(allowed)
    # ProxyHandler({}): never route through an environment proxy — the peer check must see the target.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _CheckedHTTPSHandler(), redirects)
    with opener.open(urllib.request.Request(url, headers={"User-Agent": UA}), timeout=15) as r:
        ctype = r.headers.get("Content-Type", "").split(";")[0].strip().lower()
        return r.read(MAX_BYTES + 1)[:MAX_BYTES], ctype, r.geturl(), redirects.hops


def _check_url(indicator, reference, allowed_prefixes):
    """URL rules (incl. DNS) + fetch + parse. Runs in a child process (see _check_url_with_deadline)."""
    problem = url_problem(reference, allowed_prefixes)
    if problem:
        return "BLOCKED_URL", problem
    try:
        body, ctype, final_url, hops = fetch(reference, allowed_prefixes)
    except RedirectRefused as e:
        return "BLOCKED_URL", f"redirect refused: {e}"
    except Exception as e:  # network errors are a review item, never a removal
        cause = getattr(e, "reason", None)
        if isinstance(cause, RedirectRefused):
            return "BLOCKED_URL", str(cause)
        return "FETCH_FAILED", str(e)
    if body[:5] == b"%PDF-" or (ctype and not ctype.startswith(TEXT_TYPES)):
        return "FETCH_UNSUPPORTED", f"content-type {ctype or 'pdf'}"
    text = body.decode("utf-8", errors="ignore")
    status, snippet = find_indicator(indicator, text)
    if status == "FOUND" and any(_indicator_in_url(indicator, u) for u in [reference, final_url] + hops):
        # The page may just echo its own URL (a search or tag page): never stronger than WEAK.
        return "WEAK_FOUND", "indicator is part of the reference URL itself; cite the primary report"
    if status == "NOT_FOUND" and ctype == "text/html" and _is_js_shell(text):
        # A JS-rendered shell has no static text to check: manual review, never a removal (Review Focus #1).
        return "FETCH_UNSUPPORTED", "page looks JavaScript-rendered (little static text); check manually"
    return status, snippet or f"{indicator} not in {reference}"


def _is_js_shell(text):
    """HTML with little static prose that carries a script or noscript tag (the page is rendered client-side)."""
    p = _Text()
    p.feed(text)
    p.close()
    prose = normalize(" ".join(p.prose)).strip()
    raw = text.lower()
    return len(prose) < JS_SHELL_MAX_PROSE and ("<script" in raw or "<noscript" in raw)


def _child(q, indicator, reference, allowed_prefixes):
    q.put(_check_url(indicator, reference, allowed_prefixes))


def _check_url_with_deadline(indicator, reference, allowed_prefixes):
    """Hard wall-clock limit over fetch AND parse: the child is killed, not asked to stop."""
    ctx = multiprocessing.get_context("fork")   # Linux (CI, maintainer workstation); inherits test monkeypatches
    q = ctx.Queue()
    proc = ctx.Process(target=_child, args=(q, indicator, reference, allowed_prefixes), daemon=True)
    proc.start()
    proc.join(DEADLINE_S)
    if proc.is_alive():
        proc.kill()
        proc.join()
        return "FETCH_FAILED", f"no complete result within {DEADLINE_S}s"
    try:
        return q.get(timeout=1)
    except Exception:  # child crashed before reporting
        return "FETCH_FAILED", f"checker child exited with code {proc.exitcode}"


@functools.lru_cache(maxsize=16)
def _feed_sections(path):
    """[(header path, raw bodies, normalised lines, joined, line starts)] for a dump.

    Line-based on the RAW file (newline=""; every "\r" becomes a space) and classified before any
    decoding: only a raw line starting "## " is a header, only "| " is content. Unescaping happens per
    content line afterwards, and any line break it yields becomes a space, so feed text (an HTML
    entity &#10;, a bare \r, a JSON string) can never create a header or a record boundary
    (plan gate round 6, S6-1).
    """
    sections, cur = [], None
    with open(path, encoding="utf-8", errors="ignore", newline="") as f:
        for raw in f.read().split("\n"):
            raw = raw.replace("\r", " ")
            if raw.startswith("## "):
                cur = [raw[3:].strip().lower(), [], []]
                sections.append(cur)
            elif raw.startswith("| ") and cur is not None:
                cur[1].append(raw[2:])
                cur[2].append(_clean(normalize(raw[2:])))
    out = []
    for path_, bodies, norms in sections:
        starts, pos = [], 0
        for n in norms:
            starts.append(pos)
            pos += len(n) + 1
        out.append((path_, bodies, norms, "\n".join(norms), starts))
    return out


_STIX_LITERAL = re.compile(r"(?i)(\bNOT\s*)?(?<![!<>=])==?\s*'([^']{1,512})'")   # also "NOT == 'x'" (ultrareview #7)   # "!=" and "NOT =" never match (S12-3, S13-3)


def clear_caches():
    """Dump caches are linked: clear them together (tests, or a long-lived process re-reading dumps)."""
    _feed_sections.cache_clear()
    _stix_index.cache_clear()


@functools.lru_cache(maxsize=64)
def _stix_index(dump_path, sec_idx):
    """One STIX section -> ({indicator value: family names via its `indicates` links}, names if the bundle
    has exactly one malware/tool/intrusion-set object else ()). A bundle such as stalkerware-indicators'
    generated/stalkerware.stix2 (175 malware objects) must not let any of its families vouch for every
    indicator in it (round 11, S11-1); descriptions never count (round 10, S10-2)."""
    bodies = _feed_sections(dump_path)[sec_idx][1]
    try:
        doc = json.loads("\n".join(bodies))
    except (ValueError, TypeError, RecursionError):
        return {}, (), frozenset()
    objs = doc.get("objects") if isinstance(doc, dict) else None
    if not isinstance(objs, list):
        return {}, (), frozenset()
    names, ind_vals, links, family_objects = {}, {}, [], 0
    for o in objs:
        if not isinstance(o, dict):
            continue
        t = o.get("type")
        if t in ("malware", "tool", "intrusion-set"):
            family_objects += 1   # counted with or without a (unique) id (S12-3)
        if not isinstance(o.get("id"), str):
            continue
        if t in ("malware", "tool", "intrusion-set"):
            aliases = o.get("aliases") if isinstance(o.get("aliases"), list) else []
            names.setdefault(o["id"], []).extend(_clean(normalize(n)) for n in [o.get("name")] + aliases
                                                 if isinstance(n, str))
        elif t == "indicator" and isinstance(o.get("pattern"), str):
            ind_vals[o["id"]] = [_clean(normalize(v)) for neg, v in _STIX_LITERAL.findall(o["pattern"]) if not neg]
        elif t == "relationship" and o.get("relationship_type") == "indicates":
            links.append((o.get("source_ref"), o.get("target_ref")))
    by_value = {}
    for src, tgt in links:
        for v in ind_vals.get(src, []):
            by_value.setdefault(v, []).extend(names.get(tgt, []))
    single = tuple(next(iter(names.values()))) if (family_objects == 1 and len(names) == 1) else ()
    positives = frozenset(v for vs in ind_vals.values() for v in vs)   # non-negated pattern literals
    return by_value, single, positives


def _stix_family_names(dump_path, sec_idx, indicator):
    by_value, single, positives = _stix_index(dump_path, sec_idx)
    linked = [n for v in _variants(indicator) for n in by_value.get(v, [])]
    if linked:
        return linked
    # Single-family fallback only for an indicator the bundle asserts positively — a negated pattern
    # or a mention in prose never confirms the family (round 14, S14-1).
    return list(single) if any(v in positives for v in _variants(indicator)) else []


def _record_lines(path_, bodies, norms, i):
    """The record holding content line i — see the Interfaces block."""
    ext = os.path.splitext(path_)[1]
    if ext in (".yaml", ".yml"):   # top-level list item, decided on the RAW body
        start = next((j for j in range(i, -1, -1) if bodies[j].startswith("- ")), 0)
        end = next((j for j in range(i + 1, len(bodies)) if bodies[j].startswith("- ")), len(bodies))
        return norms[start:end]
    if ext in (".stix2", ".json") and not path_.startswith(("threatfox/", "malwarebazaar/")):
        return []   # handled by _stix_family_names in _check_feed (needs the indicator and the section)
    if path_.startswith(("threatfox/", "malwarebazaar/")):
        return _jsonl_family_fields(bodies[i], path_)
    if ext in (".csv", ".jsonl"):   # one structured record per line
        return [norms[i]]
    return []   # plain lists and prose (.txt, .md, …): the family comes from the file path only


# ThreatFox / MalwareBazaar: anyone can submit a record, so only the record's own indicator field
# may match and only its malware-name fields may credit a family (round 7, S7-3: a record's tags or
# "reference" URL must not vouch for another indicator or family).
_JSONL_IOC_FIELDS = ("ioc_value", "ioc", "sha256_hash", "md5_hash", "sha1_hash")
_JSONL_FAMILY_FIELDS = ("malware", "malware_printable", "malware_alias", "signature")


def _jsonl_family_fields(body, path_=""):
    try:
        rec = json.loads(body)
    except ValueError:
        return []
    out = []
    # ThreatFox tags are submitter-chosen and never count.
    # Tags are free text set by the first uploader (round 9, S9-5): only consulted when abuse.ch gave the
    # sample no signature, and generic words never count (token_problem refuses them as a family anyway).
    # (Tag text is returned separately by _mb_tags; a tag-only match is WEAK_FOUND, never FOUND —
    # tags are the uploader's free text, round 10 S10-4.)
    for k in _JSONL_FAMILY_FIELDS:
        v = rec.get(k)
        if isinstance(v, str):
            out.append(_clean(normalize(v)))
    return out


def _mb_tags(body):
    try:
        rec = json.loads(body)
    except ValueError:
        return []
    tags = rec.get("tags") if not rec.get("signature") else None
    return [_clean(normalize(str(t))) for t in tags] if isinstance(tags, list) else []


def _jsonl_ioc_matches(body, pats):
    try:
        rec = json.loads(body)
    except ValueError:
        return False
    vals = [_clean(normalize(str(rec.get(k)))) for k in _JSONL_IOC_FIELDS if rec.get(k)]
    # "host:port" records vouch for their host; URL records never do (S8-4: a submitted
    # https://drive.google.com/... payload URL must not make drive.google.com a C2 domain).
    if str(rec.get("ioc_type", "")).lower() in ("domain", "ip:port"):
        vals += [v.split(":")[0] for v in vals]
    return any(p.fullmatch(v) for p in pats for v in vals)


def norm_name(text):
    """'Graphite (Paragon)' -> 'graphite'; '2021-10-07_donot' -> '2021 10 07 donot' (shared with validate-ioc-data.py)."""
    return re.sub(r"\s+", " ", re.sub(r"\([^)]*\)", " ", str(text)).replace("-", " ").replace("_", " ")).strip().lower()


# Words that name file layouts, not families: a reference fragment equal to one of these would match
# every section of a dump (round 8, S8-1: "#txt", "#domains", "#threatfox" vouched for anything).
_GENERIC_TOKENS = {"domain", "domains", "ioc", "iocs", "hash", "hashes", "sample", "samples", "full", "indicator",
                   "indicators", "package", "packages", "readme", "txt", "csv", "json", "jsonl", "yaml", "yml",
                   "stix2", "md", "apk", "apks", "c2", "list", "data", "get info", "ip", "ips", "url", "urls",
                   "hosts", "generated", "android", "malware", "rat", "spy", "spyware", "banker", "trojan",
                   "stalkerware", "unknown"}


@functools.lru_cache(maxsize=1)
def campaign_names():
    """Normalised key / label / alias -> key, from ioc-data/campaigns.yml (shared with validate-ioc-data.py)."""
    f = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "ioc-data", "campaigns.yml")
    if not os.path.isfile(f):
        return {}
    import yaml
    with open(f) as fh:
        data = yaml.safe_load(fh) or {}
    out = {}
    for c in data.get("campaigns", []) or []:
        for n in [c.get("key"), c.get("label")] + list(c.get("aliases") or []):
            if isinstance(n, str) and n:
                k = norm_name(n)
                if out.setdefault(k, c["key"]) != c["key"]:
                    raise ValueError(f"campaigns.yml: '{n}' names both {out[k]} and {c['key']}")
    return out


def resolve_campaigns(family):
    """Every campaign a family names: exact key/label/alias, else whole-word mentions (round 10, S10-5)."""
    f, names = norm_name(family or ""), campaign_names()
    if f in names:
        return {names[f]}
    return {k for n, k in names.items() if re.search(r"(?<![a-z0-9])" + re.escape(n) + r"(?![a-z0-9])", f)}


def token_problem(token, feed_ids=()):
    t = norm_name(token)
    if len(re.sub(r"[^a-z0-9]", "", t)) < 3:
        return "reference fragment is too short to name a family or section"
    if t in _GENERIC_TOKENS or t in {norm_name(f) for f in feed_ids}:
        return f"reference fragment '{token}' names a file layout or feed, not a family or section"
    return None


_DATE_PREFIX = re.compile(r"^\d{4}( \d{2}){0,2} ")


def _strict_names(path_):
    """Folder segments / file stem with a leading date removed: '2026 08 toxicpanda' -> 'toxicpanda'."""
    return [_DATE_PREFIX.sub("", n) for n in _path_names(path_)]


def _path_names(path_):
    """Normalised folder segments and file stem of a section path — matched exactly, never by substring."""
    parts = [x for x in path_.split("/") if x]
    return [norm_name(x) for x in parts[:-1]] + ([norm_name(os.path.splitext(parts[-1])[0])] if parts else [])


def _check_feed(indicator, reference, feed_dir, family=None, campaign=None, resolve=True):
    m = _SAFE_FEED.fullmatch(reference)
    if not m or not feed_dir:
        return "FETCH_FAILED", "malformed feed reference or no --feed-dir"
    problem = token_problem(m.group(2), [m.group(1)])
    if problem:
        return "BAD_INPUT", problem
    path = os.path.join(feed_dir, m.group(1) + ".txt")
    if not os.path.isfile(path):
        return "FETCH_FAILED", f"no feed dump at {path}"
    token = norm_name(m.group(2))
    # A fragment that is not the entry's own family is a SECTION citation (Task A3 Step 2b): it may
    # only match one folder or file stem exactly, never record text, and it is reported as
    # SECTION_CITED, never FOUND — the feed confirms where the indicator is, not the family.
    section_cite = family is not None and norm_name(family) != token
    # Strict whenever the entry is a campaign entry — by its key OR by what its family names (round 11,
    # S11-2: omitting `campaign` at check time must not select the loose path), and then the fragment
    # must be that campaign's own key/label/alias ("Pegasus-vs-Predator" is not).
    resolved = resolve_campaigns(family) if (family is not None and resolve) else set()
    effective = campaign or (next(iter(resolved)) if len(resolved) == 1 else None)
    if len(resolved) > 1:
        return "BAD_INPUT", f"family '{family}' names more than one campaign: {sorted(resolved)}"
    own = {n for n, k in campaign_names().items() if k == effective} if effective else set()
    if effective and m.group(1) in ("threatfox", "malwarebazaar"):
        # Anyone can submit there, and unrelated malware shares campaign names ("Predator The Thief",
        # APT28's "Graphite", win.pegasus) — a campaign is never confirmed by a record feed (round 12, S12-1).
        return "BAD_INPUT", "campaign entries need a curated feed (folder/STIX) or a report, not a record feed"
    if effective:
        # A campaign entry cites one of the campaign's own names (key/label/alias, e.g. "#Pegasus" or
        # "#NSO" for family "NSO Group") — never a section (round 11, Q11-7).
        if own and token not in own:
            return "FAMILY_MISMATCH", f"a '{effective}' entry must cite the campaign's own name, not '{m.group(2)}'"
        section_cite = False
    campaign = effective
    if section_cite:
        if m.group(1) in ("threatfox", "malwarebazaar"):
            return "BAD_INPUT", "record feeds have one section; cite the family their record names, not a section"
        if len(re.sub(r"[^a-z0-9]", "", token)) < 4:
            return "BAD_INPUT", "a section token must have at least 4 letters or digits"
        dirs = {"/".join(p_.split("/")[:k + 1]) for p_, *_ in _feed_sections(path)
                for k, name in enumerate(_path_names(p_)) if name == token}
        if len(dirs) > 1:
            return "FAMILY_MISMATCH", f"section token '{m.group(2)}' is ambiguous in {m.group(1)}: {sorted(dirs)[:3]}"
    fam_names = sorted(own) if own else [token]
    fam = re.compile("|".join(r"(?<![a-z0-9])" + re.escape(n) + r"(?![a-z0-9])" for n in fam_names))
    pats = [re.compile(_pattern(v)) for v in _variants(indicator)]
    exact = [re.compile(re.escape(v)) for v in _variants(indicator)]
    hit_any, sections_hit, accepted = False, [], 0
    for sec_idx, (path_, bodies, norms, joined, starts) in enumerate(_feed_sections(path)):
        is_stix = (os.path.splitext(path_)[1] in (".stix2", ".json")
                   and not path_.startswith(("threatfox/", "malwarebazaar/")))
        for pat in pats:
            for occ in pat.finditer(joined):   # one C-level scan per section
                if accepted >= MAX_OCCURRENCES:
                    # a dump repeating one value can't make this quadratic (S11-3); decoys can't turn the
                    # answer into NOT_FOUND or FAMILY_MISMATCH either (round 12, S12-2)
                    return "CAPPED", f"{indicator} occurs over {MAX_OCCURRENCES} times in {m.group(1)}; verify by hand"
                i = bisect.bisect_right(starts, occ.start()) - 1
                if path_.startswith(("threatfox/", "malwarebazaar/")) and not _jsonl_ioc_matches(bodies[i], exact):
                    continue   # the indicator is only mentioned in another field of someone's record
                hit_any = True
                accepted += 1
                if path_ not in sections_hit:
                    sections_hit.append(path_)
                # Family references match a folder/file-stem segment on word boundaries (Zimperium keeps
                # families in date-prefixed folders, e.g. 2026-08-toxicpanda — round 9, Q9-1); section
                # citations must equal a whole segment exactly (round 8, S8-1).
                if section_cite:
                    in_path = token in _path_names(path_)
                elif campaign:
                    # A campaign entry needs the strict form: a whole folder or file name (after a leading
                    # date) IS one of the campaign's names — "2021-07-18_nso" and MVT "predator.stix2" do,
                    # "ghost-tap" or "pegasus-vs-predator" never (round 10 S10-3, round 11 Q11-7).
                    in_path = bool(set(fam_names) & set(_strict_names(path_)))
                else:
                    in_path = any(fam.search(seg) for seg in _path_names(path_))
                record = (_stix_family_names(path, sec_idx, indicator) if is_stix
                          else _record_lines(path_, bodies, norms, i))
                in_record = not section_cite and any(fam.search(r) for r in record)
                weak_tag = (not in_path and not in_record and path_.startswith("malwarebazaar/")
                            and any(fam.search(t) for t in _mb_tags(bodies[i])))
                if weak_tag:
                    return "WEAK_FOUND", f"{indicator}: family only in the uploader's MalwareBazaar tags"
                if in_path or in_record:
                    line = norms[i]
                    s = occ.start() - starts[i]
                    snippet = " ".join(line[max(0, s - 70): s + len(occ.group(0)) + 70].split())
                    if section_cite:
                        return "SECTION_CITED", f"in section {path_} (family '{family}' is not confirmed by the feed): {snippet}"
                    return "FOUND", snippet
    if hit_any:
        # The section path tells the reviewer where the feed has it (Task A3 Step 2b uses it).
        return "FAMILY_MISMATCH", (f"{indicator} is in {m.group(1)} but its record does not name "
                                   f"'{m.group(2)}'; found in section(s): {', '.join(sections_hit[:3])}")
    return "NOT_FOUND", f"{indicator} not in {m.group(1)}"


def bad_input(indicator, reference):
    if not isinstance(indicator, str) or not _SAFE_INDICATOR.fullmatch(indicator):
        return "indicator has characters outside [A-Za-z0-9._:-]"
    if not isinstance(reference, str):
        return "reference missing"
    if reference.startswith("feed:"):
        return None if _SAFE_FEED.fullmatch(reference) else "feed reference has unexpected characters"
    if reference.startswith("https://"):
        return None if _SAFE_HTTPS.fullmatch(reference) else "reference URL has characters outside the safe set"
    return "reference must be https://… or feed:<id>#<family>"


def check(indicator, reference, feed_dir, allowed_prefixes=None, family=None, campaign=None, not_campaign=False):
    problem = bad_input(indicator, reference)
    if problem:
        return "BAD_INPUT", problem
    if reference.startswith("feed:"):
        if not_campaign and (campaign or re.sub(r"[^a-z0-9 ]", "", norm_name(family or "")).strip() in campaign_names()):
            # A not_campaign entry may not carry a key, and its family may not BE a campaign's name —
            # only a distinct longer name like "Predator The Thief" qualifies (round 13, S13-1).
            return "BAD_INPUT", "not_campaign is only for a family that differs from every campaign name"
        if not_campaign:
            # `not_campaign: true` (validator-checked, owner-approved) marks a family that only shares a
            # campaign's name: checked as a plain family, never resolved to the campaign.
            status, detail = _check_feed(indicator, reference, feed_dir, family, None, resolve=False)
        else:
            status, detail = _check_feed(indicator, reference, feed_dir, family, campaign)
    else:
        status, detail = _check_url_with_deadline(indicator, reference, allowed_prefixes)
    # Page and feed text reach a terminal and an LLM's context: no control characters, bounded length.
    return status, _clean(detail)[:300]


def _batch(entries_path, sources_path, feed_dir, skip_prefixes=False):
    import yaml
    with open(sources_path) as f:
        prefixes = {s["id"]: (None if skip_prefixes else s.get("reference_prefixes", [])) for s in json.load(f)}
    # A source whose allowed prefixes are unsafe (no trailing '/', multi-tenant host, ...) gets no URL check:
    # every https entry of that source is refused (round: prefix validation shares prefix_problem with CI).
    bad_prefix = {}
    for src_id, plist in prefixes.items():
        for p_ in plist or []:
            problem = prefix_problem(p_)
            if problem:
                bad_prefix.setdefault(src_id, f"bad allowed prefix for source {src_id}: {problem}")
    with open(entries_path) as f:
        entries = (yaml.safe_load(f) or {}).get("entries", [])
    worst = 0
    for e in entries:
        ind, ref, src = e.get("indicator"), e.get("reference"), e.get("source")
        if src not in prefixes:
            status, detail = "BAD_INPUT", f"unknown source {src!r}"
        elif str(ref or "").startswith("https://") and src in bad_prefix:
            status, detail = "BAD_INPUT", bad_prefix[src]
        elif e.get("not_campaign") is not None or e.get("cold_start_seed") is not None:
            # Pipeline candidates may never carry these owner-only markers (Plan C Gate 2b, round 14 S14-2).
            # Owner steps that re-check cold_start_seed entries strip that marker first (the reference
            # check doesn't depend on it). not_campaign entries are re-checked one at a time with the
            # single form's --not-campaign flag; the marker itself is gated by the validator + owner approval.
            status, detail = "BAD_INPUT", "not_campaign / cold_start_seed are owner-only markers"
        elif str(ref or "").startswith("feed:") and not str(e.get("family") or "").strip():
            # Without the family a section token would be judged as a family (round 9, S9-3).
            status, detail = "BAD_INPUT", "a feed: reference needs the entry's family"
        else:
            status, detail = check(ind, ref, feed_dir, prefixes[src], e.get("family"), e.get("campaign"))
        print(json.dumps({"indicator": ind, "reference": ref, "source": src, "status": status, "detail": detail}))
        worst = max(worst, EXIT.get(status, 2))
    return worst


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--indicator")
    ap.add_argument("--reference")
    ap.add_argument("--entries", help="YAML file with an `entries:` list (batch mode)")
    ap.add_argument("--allowed-sources", help="allowed-sources.json (batch mode)")
    ap.add_argument("--feed-dir")
    ap.add_argument("--family", help="the entry's family (single mode); a different feed fragment is a section citation")
    ap.add_argument("--not-campaign", action="store_true",
                    help="single mode, owner use: check an owner-approved not_campaign entry as a plain family")
    ap.add_argument("--allowed-prefixes", help="file with one allowed URL prefix per line")
    ap.add_argument("--skip-prefixes", action="store_true",
                    help="batch mode: no per-source prefix check (Task A3 backfill only, before prefixes exist)")
    a = ap.parse_args()
    if a.entries:
        if not a.allowed_sources:
            ap.error("--entries needs --allowed-sources")
        sys.exit(_batch(a.entries, a.allowed_sources, a.feed_dir, a.skip_prefixes))
    if not (a.indicator and a.reference):
        ap.error("--indicator and --reference are required without --entries")
    allowed = None
    if a.allowed_prefixes:
        with open(a.allowed_prefixes) as prefix_file:
            allowed = [line.strip() for line in prefix_file if line.strip() and not line.startswith("#")]
        for prefix in allowed:
            problem = prefix_problem(prefix)
            if problem:
                print(f"BAD_INPUT: bad allowed prefix {prefix}: {problem}")
                sys.exit(2)
    status, detail = check(a.indicator, a.reference, a.feed_dir, allowed, a.family, not_campaign=a.not_campaign)
    print(f"{status}: {detail}")
    sys.exit(EXIT.get(status, 2))


if __name__ == "__main__":
    main()
