#!/usr/bin/env python3
"""Validate an AndroDR SIGMA rule YAML file against the rule schema.

Usage: python validate-rule.py <rule.yml> [--schema rule-schema.json]

Exit codes:
  0 = valid
  1 = validation errors (printed to stderr)
  2 = file not found / parse error
"""

import json
import re
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("pyyaml required: pip install pyyaml")

SCRIPT_DIR = Path(__file__).parent
# "all" is a combiner (trailing), not a base modifier. Grammar allowed:
#   field|base | field|base|all | field|all (standalone, maps to ALL semantics).
VALID_MODIFIERS = {
    "contains", "startswith", "endswith", "re",
    "gte", "lte", "gt", "lt", "ioc_lookup", "all",
}
MAX_REGEX_LENGTH = 500

# Device condition grammar (SigmaRuleEvaluator.evaluateConditionExpression):
# whitespace-split tokens, keywords and/or/not (case-insensitive), NO
# parentheses, NO quantifiers. Tokenization must match Java's \s exactly —
# ASCII only (space \t \n \x0B \f \r). Python's bare str.split() and \s are
# Unicode-aware: an NBSP-joined condition would tokenize valid here yet be a
# single unresolvable token on-device (?: false -> dead rule). Same
# divergence class as the [0-9]-vs-\d note below.
ASCII_WS_RE = re.compile(r"[ \t\n\x0b\f\r]+")

# Correlation-rule grammar — mirrors SigmaRuleParser.parseCorrelationRule in
# AndroDR (types, timespan units, and the 90-day cap must stay in sync with
# CORRELATION_TIMESPAN_CAP_DAYS there; the Kotlin side carries a reciprocal
# pointer to this file). [0-9] not \d: Python \d matches Unicode digits,
# Kotlin's does not — a Unicode-digit timespan would pass here and be
# dropped on-device.
VALID_CORRELATION_TYPES = {"temporal", "temporal_ordered", "event_count"}
TIMESPAN_RE = re.compile(r"^([0-9]+)([smhd])$")
TIMESPAN_UNIT_MS = {"s": 1_000, "m": 60_000, "h": 3_600_000, "d": 86_400_000}
MAX_TIMESPAN_MS = 90 * 86_400_000

# Top-level dirs that do NOT hold deliverable production rules. Everything
# else at repo root is a logsource-service rule directory. correlation/ and
# staging/ ARE rule dirs but are excluded from correlation-reference
# resolution: on-device, correlation.rules resolve against loaded DETECTION
# rules only — staging rules are never delivered and corr ids are never
# detection rules, so a reference into either passes nowhere at runtime
# (and one unresolved reference drops ALL correlation rules at bundle load).
NON_DELIVERABLE_DIRS = {
    "correlation", "staging", "validation", "ioc-data",
    "decisions", "pipeline-runs", "docs",
}


def load_schema(schema_path: Path) -> dict:
    with open(schema_path) as f:
        return json.load(f)


def load_permissions(perms_path: Path) -> set[str]:
    with open(perms_path) as f:
        return {line.strip() for line in f if line.strip() and not line.startswith("#")}


def load_taxonomy(path: Path) -> dict:
    """Load the logsource taxonomy — the single source of truth for services
    and their detection field names (AndroDR #268). FAIL CLOSED: a missing or
    unparseable taxonomy, or a service entry without a non-empty fields map,
    aborts the run — a silent default here would wave dead rules through the
    only gate the 12h remote-fetch path has."""
    try:
        with open(path) as f:
            doc = yaml.safe_load(f)
    except (OSError, yaml.YAMLError) as e:
        sys.exit(f"FATAL: cannot load logsource taxonomy ({path.name}): {e}")
    services = doc.get("services") if isinstance(doc, dict) else None
    if not isinstance(services, dict) or not services:
        sys.exit(f"FATAL: logsource taxonomy ({path.name}) has no services map")
    for name, svc in services.items():
        fields = svc.get("fields") if isinstance(svc, dict) else None
        if not isinstance(fields, dict) or not fields:
            sys.exit(f"FATAL: taxonomy service '{name}' lacks a non-empty fields map")
    return services


# Mirrors SeverityCapPolicy.kt severityOrder — the two must stay in lockstep.
SEVERITY_ORDER = ["critical", "high", "medium", "low", "informational"]


def cap_violated(declared: str, cap: str) -> bool:
    if declared not in SEVERITY_ORDER or cap not in SEVERITY_ORDER:
        return True  # unknown severities fail closed
    return SEVERITY_ORDER.index(declared) < SEVERITY_ORDER.index(cap)


def load_severity_caps(path: Path) -> dict:
    """Load the per-category severity caps — the single source of truth for
    the device-posture-style clamp (#136 R1, spec B3). FAIL CLOSED: a missing
    or unparseable caps file, or a caps map that isn't a mapping, aborts the
    run — the alternative (skip the cap) would silently let an above-cap
    rule through the only PR-time gate that catches it."""
    try:
        with open(path) as f:
            doc = yaml.safe_load(f)
    except (OSError, yaml.YAMLError) as e:
        sys.exit(f"FATAL: cannot load severity caps ({path.name}): {e}")
    caps = doc.get("caps") if isinstance(doc, dict) else None
    if not isinstance(caps, dict):
        sys.exit(f"FATAL: severity caps ({path.name}) has no 'caps' map")
    return caps


def load_judgment_allowlist(path: Path) -> dict:
    """Load the judgment-field allowlist (#136 R1, spec B5). FAIL CLOSED: a
    missing or unparseable allowlist, or an 'allowed' map that isn't a
    mapping, aborts the run — the alternative (skip the lint) would silently
    let a new judgment-field reference through during the strangler-fig
    parallel run."""
    try:
        with open(path) as f:
            doc = yaml.safe_load(f)
    except (OSError, yaml.YAMLError) as e:
        sys.exit(f"FATAL: cannot load judgment-field allowlist ({path.name}): {e}")
    allowed = doc.get("allowed") if isinstance(doc, dict) else None
    if not isinstance(allowed, dict):
        sys.exit(f"FATAL: judgment-field allowlist ({path.name}) has no 'allowed' map")
    return allowed


def load_ioc_lookup_names(path: Path) -> set[str]:
    """Load the registered ioc_lookup database names (#275). FAIL CLOSED: a
    missing or unparseable definitions file, or a 'lookups' map that isn't a
    mapping, aborts the run — the alternative (skip the check) would let an
    unregistered lookup name through, which an R1+ binary skips the whole
    rule for and a pre-R1 binary over-fires under negation for."""
    try:
        with open(path) as f:
            doc = yaml.safe_load(f)
    except (OSError, yaml.YAMLError) as e:
        sys.exit(f"FATAL: cannot load ioc-lookup definitions ({path.name}): {e}")
    lookups = doc.get("lookups") if isinstance(doc, dict) else None
    if not isinstance(lookups, dict) or not lookups:
        sys.exit(f"FATAL: ioc-lookup definitions ({path.name}) has no non-empty 'lookups' map")
    return set(lookups)


def check_condition_grammar(condition, selection_names: set[str]) -> list[str]:
    """Validate detection.condition against the device evaluator's grammar:

        ["not"] name (("and"|"or") ["not"] name)*

    Whitespace-split on the ASCII class only (ASCII_WS_RE), keywords matched
    case-insensitively, selection names case-sensitively, NO parentheses —
    the evaluator has none, so the old paren-stripping here was a false-pass
    divergence. Absent and explicit-null conditions both mirror the on-device
    parser default of "selection" (SigmaRuleParser's null-coalesce).

    Divergent shapes this rejects are silently dead or over-firing on-device:
    keyword-as-operand ("not and" -> the evaluator consumes 'and' as an
    operand, ?: false under not -> fires on everything), dangling "not"
    (negation silently dropped -> over-fires), empty condition (dead)."""
    if condition is None:
        condition = "selection"
    if not isinstance(condition, str):
        return [f"detection.condition must be a string, got: {type(condition).__name__}"]
    tokens = [t for t in ASCII_WS_RE.split(condition) if t]
    if not tokens:
        return ["empty detection.condition — the rule is dead on-device"]
    errors = []
    expect_operand = True
    i = 0
    n = len(tokens)
    while i < n:
        tok = tokens[i]
        low = tok.lower()
        if expect_operand:
            if low == "not":
                i += 1
                if i >= n:
                    errors.append(
                        "dangling 'not' at end of condition — the negation is "
                        "silently dropped on-device (over-fires)"
                    )
                    break
                tok = tokens[i]
                low = tok.lower()
            if low in ("and", "or", "not"):
                errors.append(
                    f"keyword '{tok}' where a selection name was expected — "
                    "the device evaluator consumes it as an operand "
                    "(?: false), silently inverting the expression"
                )
                break
            if tok not in selection_names:
                errors.append(f"Condition references undefined selection: {tok}")
            expect_operand = False
            i += 1
        else:
            if low in ("and", "or"):
                expect_operand = True
                i += 1
            else:
                errors.append(
                    f"expected 'and'/'or' before '{tok}' in condition — the "
                    "device grammar is [\"not\"] name ((\"and\"|\"or\") "
                    "[\"not\"] name)* with no parentheses"
                )
                break
    if not errors and expect_operand:
        errors.append(
            "condition ends with a dangling operator (the device evaluator "
            "silently ignores it — rejecting to keep the gates no laxer than "
            "the device)"
        )
    return errors


def load_retired_ids(path: Path) -> set[str]:
    """IDs listed in retired-rule-ids.txt may never be reused."""
    if not path.exists():
        return set()
    with open(path) as f:
        return {
            line.split("#")[0].strip()
            for line in f
            if line.split("#")[0].strip()
        }


def check_id_and_status(rule: dict, retired_ids: frozenset[str] | set[str]) -> list[str]:
    """Shared id/status checks for both rule shapes."""
    errors = []
    if "id" in rule:
        rule_id = rule["id"]
        if not isinstance(rule_id, str) or not rule_id.startswith("androdr-"):
            errors.append(f"Rule ID must match 'androdr-NNN', got: {rule_id}")
        elif rule_id in retired_ids:
            errors.append(
                f"Rule ID {rule_id} was retired and must not be reused "
                f"(see validation/retired-rule-ids.txt); allocate the next free ID"
            )
    if "status" in rule and rule["status"] not in ("experimental", "test", "production"):
        errors.append(f"Invalid status: {rule['status']}")
    return errors


def check_attack_tags(rule: dict) -> list[str]:
    errors = []
    for tag in rule.get("tags", []):
        if tag.startswith("attack.t") or tag.startswith("attack.T"):
            tid = tag.replace("attack.", "").upper()
            parts = tid.split(".")
            if not (len(parts) in (1, 2) and parts[0][0] == "T" and parts[0][1:].isdigit()):
                errors.append(f"Invalid ATT&CK tag format: {tag}")
    return errors


def validate_correlation_rule(rule: dict,
                              retired_ids: frozenset[str] | set[str] = frozenset(),
                              known_rule_ids: set[str] | None = None) -> list[str]:
    """Validate the correlation-rule shape (no logsource/detection/level/category;
    a `correlation:` block instead). Mirrors the Kotlin CorrelationParseException
    grammar so a rule that passes here cannot fail to parse on-device — plus
    repo-policy checks deliberately STRICTER than the parser (required title/
    status, androdr- reference prefix, display.category pinned to
    'correlation'). Extra strictness here is intentional, not divergence."""
    errors = []

    for field in ("title", "id", "status", "correlation"):
        if field not in rule:
            errors.append(f"Missing required field: {field}")

    errors += check_id_and_status(rule, retired_ids)
    errors += check_attack_tags(rule)

    # The Kotlin parser routes on the presence of the `correlation` key; a
    # hybrid carrying standard-rule structure would silently lose it on-device.
    for forbidden in ("logsource", "detection", "level", "category"):
        if forbidden in rule:
            errors.append(
                f"correlation rules must not declare '{forbidden}' "
                "(the on-device parser routes on the 'correlation' key and "
                "ignores standard-rule fields)"
            )

    corr = rule.get("correlation")
    if not isinstance(corr, dict):
        if corr is not None:
            errors.append(f"correlation must be a mapping, got: {type(corr).__name__}")
        return errors

    ctype = corr.get("type")
    if ctype not in VALID_CORRELATION_TYPES:
        errors.append(
            f"Invalid correlation.type: {ctype} "
            f"(must be one of {', '.join(sorted(VALID_CORRELATION_TYPES))})"
        )

    refs = corr.get("rules")
    if not isinstance(refs, list) or not refs:
        errors.append("correlation.rules must be a non-empty list of rule IDs")
    else:
        for ref in refs:
            if not isinstance(ref, str) or not ref.startswith("androdr-"):
                errors.append(f"correlation.rules entry is not an androdr- rule ID: {ref!r}")
            elif known_rule_ids is not None and ref not in known_rule_ids:
                errors.append(
                    f"correlation.rules references unknown rule ID: {ref} "
                    "(no rule file in this repo declares it)"
                )

    timespan = corr.get("timespan")
    m = TIMESPAN_RE.match(timespan.strip()) if isinstance(timespan, str) else None
    if m is None:
        errors.append(
            f"Invalid correlation.timespan: {timespan!r} (expected <int><s|m|h|d>, e.g. 30m)"
        )
    elif int(m.group(1)) * TIMESPAN_UNIT_MS[m.group(2)] > MAX_TIMESPAN_MS:
        errors.append(
            f"correlation.timespan {timespan} exceeds the on-device 90-day cap"
        )

    if ctype == "event_count":
        cond = corr.get("condition")
        gte = cond.get("gte") if isinstance(cond, dict) else None
        if not isinstance(gte, int) or isinstance(gte, bool):
            errors.append("event_count correlation requires condition.gte (Int)")

    # Presence checks use `in`, not None-coalescing get(): the Kotlin parser
    # keys on containsKey, so an explicit-null `group-by:` or `display:` line
    # (an easy YAML slip) throws on-device. Treating it as absent here would
    # be a false-pass that ships a silently-dropped rule.
    if "group-by" in corr:
        group_by = corr["group-by"]
        if not isinstance(group_by, list) or not all(isinstance(g, str) for g in group_by):
            errors.append(
                "correlation.group-by must be a list of field names "
                "(an empty/null 'group-by:' line also fails on-device)"
            )

    if "display" in rule:
        display = rule["display"]
        if not isinstance(display, dict):
            errors.append(
                f"display must be a mapping, got: {type(display).__name__} "
                "(an empty/null 'display:' line also fails on-device)"
            )
        elif display.get("category") not in (None, "correlation"):
            errors.append(
                f"Invalid display.category for a correlation rule: {display['category']} "
                "(must be 'correlation')"
            )

    return errors


def validate_rule(rule: dict, schema: dict, permissions: set[str],
                  retired_ids: frozenset[str] | set[str] = frozenset(),
                  known_rule_ids: set[str] | None = None,
                  taxonomy: dict | None = None,
                  in_staging: bool = False,
                  severity_caps: dict | None = None,
                  judgment_allowlist: dict | None = None,
                  ioc_lookup_names: set[str] | None = None) -> list[str]:
    """Return list of error strings. Empty list means valid."""
    # Correlation rules are a distinct shape (no logsource/detection); the
    # standard schema does not apply to them.
    if "correlation" in rule:
        return validate_correlation_rule(rule, retired_ids, known_rule_ids)

    errors = []

    # Required fields
    for field in schema.get("required", []):
        if field not in rule:
            errors.append(f"Missing required field: {field}")

    errors += check_id_and_status(rule, retired_ids)

    if "level" in rule and rule["level"] not in ("critical", "high", "medium", "low", "informational"):
        errors.append(f"Invalid level: {rule['level']}")

    # Category enum check — exact, case-sensitive. The Kotlin parser
    # lowercases category before mapping to RuleCategory, so a value like
    # 'Device_Posture' would be silently capped on-device while bypassing a
    # naive == comparison here. Rejecting non-canonical spellings closes
    # that bypass for every category-keyed lint below.
    if "category" in rule and rule["category"] not in ("incident", "device_posture"):
        errors.append(
            f"Invalid category: {rule['category']} (must be 'incident' or 'device_posture')"
        )

    # Severity-cap policy: findings in a capped category are clamped at
    # runtime via SeverityCapPolicy.applyCap(rule.category, rule.level) — the
    # TOP-LEVEL category field, NOT display.category (which only selects the
    # UI grouping bucket; cf. androdr-020/030: category incident, displayed
    # under device_posture, uncapped). Declaring above the cap is dead text —
    # reject so the pipeline never proposes it. Caps are data
    # (validation/severity-caps.yml, #136 R1 spec B3), not this hardcoded
    # comparison, so a future cap entry works with zero code here.
    posture = rule.get("category") == "device_posture"
    if severity_caps is None:
        severity_caps = load_severity_caps(SCRIPT_DIR / "severity-caps.yml")
    for cap_category, cap in severity_caps.items():
        if rule.get("category") == cap_category and cap_violated(rule.get("level"), cap):
            errors.append(
                f"{cap_category} rules are clamped to '{cap}' at runtime by "
                f"SeverityCapPolicy; declare level: {cap} or below (or "
                "reclassify as category: incident if a genuine HIGH/CRITICAL "
                "signal is intended)"
            )

    # Logsource — the taxonomy is the single source of truth for services
    # (the old hardcoded set here had already drifted from it, #268).
    # Non-active services are rejected outside staging/: staging exists to
    # hold rules ahead of Kotlin wiring (rules.txt can never list staging
    # paths, so a staged rule is provably not live); everywhere else a
    # non-active service means the engine cannot evaluate the rule and it
    # would ship dead.
    if taxonomy is None:
        taxonomy = load_taxonomy(SCRIPT_DIR / "logsource-taxonomy.yml")
    logsource = rule.get("logsource", {})
    if logsource.get("product") != "androdr":
        errors.append(f"logsource.product must be 'androdr', got: {logsource.get('product')}")
    service = logsource.get("service")
    service_fields = None
    if service not in taxonomy:
        errors.append(
            f"Invalid logsource.service: {service} — not in "
            f"validation/logsource-taxonomy.yml (the taxonomy is the single "
            f"source of truth; valid: {', '.join(sorted(taxonomy))})"
        )
    else:
        status = taxonomy[service].get("status")
        if status != "active" and not in_staging:
            errors.append(
                f"logsource.service '{service}' has taxonomy status "
                f"'{status}' — the engine cannot evaluate it and the rule "
                "would ship dead (allowed under staging/ only)"
            )
        service_fields = set(taxonomy[service]["fields"])

    if judgment_allowlist is None:
        judgment_allowlist = load_judgment_allowlist(SCRIPT_DIR / "judgment-field-allowlist.yml")
    if ioc_lookup_names is None:
        ioc_lookup_names = load_ioc_lookup_names(SCRIPT_DIR / "ioc-lookup-definitions.yml")
    rule_id = rule.get("id")

    # Detection — condition grammar, selection shape, field membership,
    # value lists, modifiers (#268: every miss here is a silently dead or
    # over-firing rule on-device; see the failure-polarity notes per check).
    detection = rule.get("detection", {})
    if not isinstance(detection, dict):
        errors.append(f"detection must be a mapping, got: {type(detection).__name__}")
        detection = {}
    selection_names = {k for k in detection if k != "condition"}

    errors += check_condition_grammar(detection.get("condition"), selection_names)

    # requested_permissions negation guard (#317): pre-emitter binaries do not
    # emit the field, a matcher on it evaluates false there, and `not` inverts
    # that to always-true — the negated filter stops subtracting and the rule
    # OVER-FIRES on the old fleet via the 12h feed (the #136 Phase-2 inversion
    # class; there is NO unknown-field skip floor). Positive references merely
    # no-op, so only negation context is rejected.
    _cond = detection.get("condition")
    _cond_tokens = [t for t in ASCII_WS_RE.split(_cond) if t] if isinstance(_cond, str) else []
    _negated = {
        _cond_tokens[i + 1]
        for i, t in enumerate(_cond_tokens[:-1])
        if t.lower() == "not"
    }
    for _neg_name in _negated:
        _neg_body = detection.get(_neg_name)
        if isinstance(_neg_body, dict) and any(
            str(k).split("|")[0].lower() == "requested_permissions" for k in _neg_body
        ):
            errors.append(
                f"selection '{_neg_name}' matches requested_permissions and is "
                "referenced under 'not' — on builds that predate the emitter the "
                "matcher is always false and negation inverts it to always-true, "
                "defeating the exemption and over-firing on the old fleet; gate "
                "the exemption on a field old builds emit, or wait for the fleet "
                "floor to cover the emitter"
            )

    for sel_name, sel_value in detection.items():
        if sel_name == "condition":
            continue
        # A selection body must be a NON-EMPTY mapping. The device parser
        # silently DROPS non-mapping selections (standard SIGMA list-of-maps
        # syntax included) — under `not`, the dropped name evaluates
        # ?: false -> not false -> the filter never subtracts and the rule
        # fires on everything. An empty {} parses to a zero-matcher
        # selection, which is vacuously TRUE.
        if not isinstance(sel_value, dict):
            errors.append(
                f"selection '{sel_name}' must be a mapping of field matchers, "
                f"got: {type(sel_value).__name__} — the device parser "
                "silently drops non-mapping selections; under 'not' the rule "
                "then fires on everything"
            )
            continue
        if not sel_value:
            errors.append(
                f"selection '{sel_name}' is an empty mapping — it parses to "
                "a zero-matcher selection on-device, which is vacuously TRUE"
            )
            continue
        for field_key in sel_value:
            # str(): the device parser does key.toString(); a non-string YAML
            # key must not crash this gate with a Traceback.
            key_str = str(field_key)
            base_field = key_str.split("|")[0]
            # Field membership: a typo'd field passes parsing but the
            # evaluator returns false for missing record fields — the rule
            # ships, loads, evaluates, and can never fire (or, in a negated
            # filter, fires on everything).
            if service_fields is not None and base_field not in service_fields:
                errors.append(
                    f"Unknown detection field '{base_field}' for service "
                    f"'{service}' — dead on-device (the evaluator returns "
                    f"false for missing fields). Valid fields: "
                    f"{', '.join(sorted(service_fields))}"
                )
            # #275: ioc_lookup names must be registered in
            # ioc-lookup-definitions.yml — an R1+ binary fail-closed skips
            # the whole rule for an unresolvable name, while a pre-R1 binary
            # resolves it to matcher-false and OVER-FIRES under negation. A
            # blank/non-string name is always a bug (checked regardless of
            # staging). The registration requirement itself is DELIVERED-only
            # (cf. the CAPABILITY CONSTRAINT note in
            # ioc-lookup-definitions.yml): staging is the documented holding
            # pen for rules ahead of the backing capability existing at all
            # (cf. androdr-030 / decisions/2026-07-13-mirror-reconcile.yml —
            # process_name_ioc_db is intentionally unregistered pending a
            # process-telemetry source with cross-app visibility), the same
            # exemption already granted to non-active taxonomy services.
            if "ioc_lookup" in key_str.split("|")[1:]:
                lookup_name = sel_value[field_key]
                if not isinstance(lookup_name, str) or not lookup_name.strip():
                    errors.append(
                        f"ioc_lookup value for '{field_key}' must be a "
                        "non-blank string naming a database registered in "
                        "validation/ioc-lookup-definitions.yml"
                    )
                elif lookup_name not in ioc_lookup_names and not in_staging:
                    errors.append(
                        f"ioc_lookup '{lookup_name}' is not registered in "
                        f"validation/ioc-lookup-definitions.yml (registered: "
                        f"{', '.join(sorted(ioc_lookup_names))}) — an R1+ binary skips "
                        f"the whole rule; a pre-R1 binary OVER-FIRES under negation"
                    )

            # B5: judgment-kind fields are deprecated for new use during the
            # strangler-fig parallel run (#136 R1) — only allowlisted rules
            # (grandfathered before the emitter contract) may still reference
            # them. delivered/staging are separate lists: a staging twin
            # never authorizes its delivered id.
            field_def = taxonomy.get(service, {}).get("fields", {}).get(base_field)
            if isinstance(field_def, dict) and field_def.get("kind") == "judgment":
                scope = "staging" if in_staging else "delivered"
                if rule_id not in judgment_allowlist.get(base_field, {}).get(scope, set()):
                    errors.append(
                        f"detection references judgment-kind field '{base_field}' — the "
                        f"emitter contract (#136) forbids new uses ({scope} allowlist); "
                        f"compute the judgment in the rule (e.g. installer|ioc_lookup) instead"
                    )
            # requested_permissions matching discipline (#317): the field is an
            # open-ended all-facts list of verbatim FQN permission strings, so
            # the dead-rule hazard inverts vs the curated `permissions` field —
            # any literal is "real", but SUBSTRING matching false-positives
            # (android.permission.NFC is a substring of
            # android.permission.NFC_TRANSACTION_EVENT). Exact element-wise
            # equals only; this is the ONLY gate on the 12h remote-fetch path.
            if base_field.lower() == "requested_permissions":
                if key_str not in ("requested_permissions", "requested_permissions|all"):
                    errors.append(
                        f"'{key_str}': requested_permissions allows only the bare "
                        "key (element-wise equals) or the '|all' combiner — "
                        "substring modifiers false-positive "
                        "(android.permission.NFC ⊂ android.permission.NFC_TRANSACTION_EVENT), "
                        "and the runtime field lookup is case-sensitive, so the "
                        "key must be exactly lowercase"
                    )
                _rp_value = sel_value[field_key]
                _rp_literals = _rp_value if isinstance(_rp_value, list) else [_rp_value]
                for _lit in _rp_literals:
                    if not isinstance(_lit, str) or "." not in _lit:
                        errors.append(
                            f"requested_permissions literal '{_lit}' must be a "
                            "fully-qualified permission name — the emitter emits "
                            "verbatim manifest strings like "
                            "'android.permission.NEARBY_WIFI_DEVICES', so a short "
                            "name can never match"
                        )
                    elif (
                        _lit.lower().startswith("android.permission.")
                        and permissions
                        and _lit.rsplit(".", 1)[1].upper() not in permissions
                    ):
                        errors.append(
                            f"requested_permissions literal '{_lit}' is not in "
                            "validation/android-permissions.txt — likely a typo; "
                            "add the permission there if it is real"
                        )

            # Empty/null value lists are constant-false matchers on-device
            # (dead positive selection / over-firing negated filter; for
            # standalone |all, vacuously TRUE instead).
            value = sel_value[field_key]
            if value is None or (isinstance(value, list) and len(value) == 0):
                errors.append(
                    f"empty value list for '{field_key}' is a vacuous "
                    "selection that can never match (or, for standalone "
                    "|all, matches everything)"
                )
            # Lone actively-exploited-CVE rule = duplicate of androdr-047
            # (CISA KEV catalog) once the severity cap lands. Only
            # named-campaign CVE *sets* (cf. androdr-048..052) justify a
            # dedicated rule. Checked before the modifier guard so the
            # plain-equality form (no modifier) is covered too.
            if base_field == "unpatched_cve_id" and posture:
                cve_values = sel_value[field_key]
                cve_count = len(cve_values) if isinstance(cve_values, list) else 1
                if cve_count == 1:
                    errors.append(
                        "single actively-exploited-CVE rules duplicate "
                        "androdr-047 (CISA KEV catalog); only named-campaign "
                        "CVE sets (cf. androdr-048..052) justify a dedicated rule"
                    )
            if "|" not in key_str:
                continue
            tokens = key_str.split("|")
            modifiers = tokens[1:]
            # Grammar: chain must be [base] or [base, "all"]. Mirrors Kotlin
            # SigmaRuleParser's single-base-modifier-plus-optional-|all rule.
            if "all" in modifiers[:-1]:
                errors.append(
                    f"'all' must be the trailing combiner in '{field_key}'"
                )
            if len(modifiers) > 2 or (len(modifiers) == 2 and modifiers[-1] != "all"):
                errors.append(
                    f"Chain too long in '{field_key}': expected at most one modifier "
                    f"(optionally followed by |all). Got: {'|'.join(modifiers)}"
                )
            # tokens[0] is the field name; tokens[1:] are modifiers (chain).
            for modifier in tokens[1:]:
                if modifier not in VALID_MODIFIERS:
                    errors.append(
                        f"Invalid modifier '{modifier}' in field '{field_key}'. "
                        f"Supported: {', '.join(sorted(VALID_MODIFIERS))}"
                    )
            # Regex checks fire whenever 're' appears anywhere in the modifier
            # chain (e.g. 'url|re|all' must still enforce them). Length: the
            # device parser drops >500-char patterns. Compilability: on-device
            # safeRegexMatch permanently caches uncompilable patterns as
            # constant-false (dead matcher / over-firing negated filter).
            # Python and Kotlin regex dialects differ (cf. the [0-9]-vs-\d
            # note above) — a pattern passing re.compile here can in rare
            # cases still fail to compile on-device; this check closes the
            # common class, not the dialect gap.
            if "re" in tokens[1:]:
                values = sel_value[field_key]
                if not isinstance(values, list):
                    values = [values]
                for v in values:
                    if not isinstance(v, str):
                        continue
                    if len(v) > MAX_REGEX_LENGTH:
                        errors.append(f"Regex pattern exceeds {MAX_REGEX_LENGTH} chars in '{field_key}'")
                        continue
                    try:
                        re.compile(v)
                    except re.error as e:
                        errors.append(
                            f"uncompilable regex in '{field_key}': {e} — "
                            "on-device this is cached as constant-false "
                            "(dead matcher / over-firing negated filter)"
                        )

    # Display block
    display = rule.get("display", {})
    if display is not None and not isinstance(display, dict):
        errors.append(f"display must be a mapping, got: {type(display).__name__}")
        display = {}
    if display:
        valid_categories = {"app_risk", "device_posture", "network"}
        if "category" in display and display["category"] not in valid_categories:
            errors.append(f"Invalid display.category: {display['category']}")
        valid_evidence = {"none", "cve_list", "ioc_match", "permission_cluster"}
        if "evidence_type" in display and display["evidence_type"] not in valid_evidence:
            errors.append(f"Invalid display.evidence_type: {display['evidence_type']}")

    # Tags — check ATT&CK format
    errors += check_attack_tags(rule)

    # implies_flags — orthogonal facts about the detection subject the
    # rule's selection structurally guarantees. Source of truth for the
    # allowed values is the schema's enum, so adding a new value there
    # is the single edit point.
    if "implies_flags" in rule:
        flags = rule["implies_flags"]
        if not isinstance(flags, list):
            errors.append("implies_flags must be an array")
        else:
            valid_implies = set(
                schema.get("properties", {})
                    .get("implies_flags", {})
                    .get("items", {})
                    .get("enum", [])
            )
            for flag in flags:
                if flag not in valid_implies:
                    errors.append(
                        f"Invalid implies_flag value: {flag!r}. "
                        f"Valid: {sorted(valid_implies)}"
                    )

    return errors


def main():
    if len(sys.argv) < 2:
        print("Usage: python validate-rule.py <rule.yml>", file=sys.stderr)
        sys.exit(2)

    rule_path = Path(sys.argv[1])
    if not rule_path.exists():
        print(f"File not found: {rule_path}", file=sys.stderr)
        sys.exit(2)

    schema_path = SCRIPT_DIR / "rule-schema.json"
    perms_path = SCRIPT_DIR / "android-permissions.txt"

    schema = load_schema(schema_path)
    permissions = load_permissions(perms_path) if perms_path.exists() else set()
    retired_ids = load_retired_ids(SCRIPT_DIR / "retired-rule-ids.txt")
    taxonomy = load_taxonomy(SCRIPT_DIR / "logsource-taxonomy.yml")
    severity_caps = load_severity_caps(SCRIPT_DIR / "severity-caps.yml")
    judgment_allowlist = load_judgment_allowlist(SCRIPT_DIR / "judgment-field-allowlist.yml")
    ioc_lookup_names = load_ioc_lookup_names(SCRIPT_DIR / "ioc-lookup-definitions.yml")

    # B4: completeness IS the contract — an unlabeled taxonomy field must
    # fail CI, so "absent = raw_fact" defaults are forbidden here.
    missing_kind = [
        f"{svc}/{fname}"
        for svc, sdef in taxonomy.items()
        for fname, fdef in sdef["fields"].items()
        if not isinstance(fdef, dict) or fdef.get("kind") not in ("raw_fact", "judgment")
    ]
    if missing_kind:
        sys.exit(
            "FATAL: logsource-taxonomy.yml field(s) missing kind: "
            f"raw_fact|judgment: {', '.join(missing_kind)}"
        )

    # B5: the judgment-marked set in the taxonomy IS the frozen judgment-field
    # set — the allowlist's top-level keys must match exactly (data, not
    # code); a drift here means either the taxonomy dropped a kind:judgment
    # marker unnoticed or the allowlist carries a stale/typo'd key.
    judgment_marked = {
        fname
        for sdef in taxonomy.values()
        for fname, fdef in sdef["fields"].items()
        if isinstance(fdef, dict) and fdef.get("kind") == "judgment"
    }
    if judgment_marked != set(judgment_allowlist):
        sys.exit(
            "FATAL: taxonomy kind:judgment fields "
            f"({', '.join(sorted(judgment_marked))}) do not match "
            "judgment-field-allowlist.yml's top-level keys "
            f"({', '.join(sorted(judgment_allowlist))})"
        )

    # Staging-ness by FIRST path component only (mirrors
    # validate-delivery-set.py's split("/", 1)[0] convention), so a file like
    # app_scanner/staging_foo.yml — which IS deliverable — never gets the
    # non-active-service exemption. CI passes repo-root-relative paths
    # (find staging ... -name '*.yml'); absolute paths are resolved against
    # the repo root, and paths outside the repo are never staging.
    repo_root = SCRIPT_DIR.parent
    if rule_path.is_absolute():
        try:
            rel_parts = rule_path.resolve().relative_to(repo_root.resolve()).parts
        except ValueError:
            rel_parts = ()
    else:
        rel_parts = rule_path.parts
    in_staging = bool(rel_parts) and rel_parts[0] == "staging"

    with open(rule_path) as f:
        try:
            rule = yaml.safe_load(f)
        except yaml.YAMLError as e:
            print(f"YAML parse error: {e}", file=sys.stderr)
            sys.exit(2)

    # Correlation rules reference other rules by ID; resolve against the
    # DELIVERABLE detection rules only (production service dirs — not staging,
    # not other correlation rules, not data/tooling dirs). On-device,
    # SigmaRuleEngine resolves correlation.rules against loaded detection
    # rules, and a single unresolved reference drops ALL correlation rules at
    # bundle load — so an id that merely exists somewhere in the repo is not
    # good enough.
    known_rule_ids = None
    if isinstance(rule, dict) and "correlation" in rule:
        repo_root = SCRIPT_DIR.parent
        id_re = re.compile(r"^id:\s*(androdr-\S+)", re.M)
        known_rule_ids = set()
        for d in repo_root.iterdir():
            if not d.is_dir() or d.name.startswith(".") or d.name in NON_DELIVERABLE_DIRS:
                continue
            for f in d.glob("*.yml"):
                m = id_re.search(f.read_text())
                if m:
                    known_rule_ids.add(m.group(1))

    errors = validate_rule(rule, schema, permissions, retired_ids,
                           known_rule_ids, taxonomy, in_staging,
                           severity_caps, judgment_allowlist, ioc_lookup_names)

    if errors:
        print(f"FAIL: {rule_path.name} — {len(errors)} error(s):", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        sys.exit(1)
    else:
        print(f"PASS: {rule_path.name}")
        sys.exit(0)


if __name__ == "__main__":
    main()
