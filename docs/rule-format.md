# AndroDR Rule Format Guide

This document describes the YAML format used for AndroDR SIGMA detection rules.
All rules are validated against `validation/rule-schema.json`.

---

## Required Fields

| Field | Type | Description |
|---|---|---|
| `title` | string | Human-readable rule name shown in the UI |
| `id` | string | Unique rule ID in the format `androdr-NNN` (zero-padded three digits) |
| `status` | string | Lifecycle stage: `experimental`, `test`, or `production` |
| `description` | string | One or two sentences explaining what the rule detects and why it matters |
| `logsource` | object | Defines the data source — must include `product` and `service` |
| `detection` | object | Named selection blocks plus a `condition` expression |
| `level` | string | Severity: `critical`, `high`, `medium`, or `low` |
| `tags` | array | ATT&CK technique tags (e.g. `attack.t1476`) or other labels |

---

## Optional Fields

| Field | Type | Description |
|---|---|---|
| `author` | string | Rule author name or team |
| `date` | string | Authoring date in `YYYY/MM/DD` format |
| `falsepositives` | array | Known scenarios that may produce false positives |
| `remediation` | array | Ordered list of user-facing remediation steps |
| `display` | object | UI rendering hints — see Display Block below |

---

## Display Block

The optional `display` block controls how a triggered rule appears in the AndroDR app UI.

| Sub-field | Type | Allowed Values | Description |
|---|---|---|---|
| `category` | string | `app_risk`, `device_posture`, `network` | Groups the finding under the correct UI section |
| `icon` | string | Any Material symbol name | Icon shown next to the finding card |
| `triggered_title` | string | — | Short title displayed when the rule fires |
| `safe_title` | string | — | Short title displayed when the rule does not fire |
| `evidence_type` | string | `none`, `cve_list`, `ioc_match`, `permission_cluster` | Controls the evidence detail sheet layout |
| `summary_template` | string | — | Mustache-style template for the finding summary line |

---

## Detection Modifiers

Field keys in a selection block can include a modifier after a `|` separator
(e.g. `patch_age_days|gte: 90`).

| Modifier | Description | Example |
|---|---|---|
| `contains` | Field value contains the substring | `package_name\|contains: "spy"` |
| `startswith` | Field value starts with the string | `process_name\|startswith: "su"` |
| `endswith` | Field value ends with the string | `file_path\|endswith: ".so"` |
| `re` | Field value matches a regular expression (max 500 chars) | `package_name\|re: "^com\\.spy"` |
| `gte` | Numeric field is greater than or equal to | `patch_age_days\|gte: 90` |
| `lte` | Numeric field is less than or equal to | `surveillance_permission_count\|lte: 0` |
| `gt` | Numeric field is strictly greater than | `file_size\|gt: 10485760` |
| `lt` | Numeric field is strictly less than | `patch_age_days\|lt: 30` |
| `ioc_lookup` | Field value is looked up against an IOC data list | `package_name\|ioc_lookup: package-names` |

---

## Condition Expressions

The `condition` field ties named selection blocks together using boolean logic.

| Expression | Meaning |
|---|---|
| `selection` | Single block must match |
| `selection_a and selection_b` | Both blocks must match |
| `selection_a or selection_b` | Either block must match |
| `selection_a and not selection_b` | First matches, second does not |
| `(selection_a or selection_b) and not filter` | Grouped precedence with exclusion |

Rules:
- All tokens that are not `and`, `or`, or `not` must be defined as selection keys in the same `detection` block.
- Parentheses can be used to control evaluation order.
- Token names are case-sensitive.

---

## Severity Levels

| Level | Criteria |
|---|---|
| `critical` | Indicates active compromise or an immediate security failure with no acceptable benign explanation (e.g. no screen lock, unlocked bootloader). |
| `high` | Strong indicator of risk or misconfiguration that significantly increases attack surface (e.g. USB debugging on, sideloaded app matching known IOC). |
| `medium` | Notable risk factor that may have a legitimate use case but requires user attention (e.g. app installed from unknown source). |
| `low` | Informational signal or minor risk; context-dependent (e.g. app requests network access without other risk factors). |

---

## Complete Example Rule

The following rule (`androdr-010`) detects apps that were not installed via a
trusted app store. It is a good template for new behavioral rules.

```yaml
title: App installed from untrusted source
id: androdr-010
status: production
description: App was not installed via a trusted app store.
author: AndroDR
date: 2026/03/27
tags:
    - attack.t1476
logsource:
    product: androdr
    service: app_scanner
detection:
    selection:
        is_system_app: false
        from_trusted_store: false
        is_known_oem_app: false
    condition: selection
level: medium
falsepositives:
    - Enterprise apps distributed via MDM without a store listing
    - Developer builds installed via ADB during testing
remediation:
    - "This app was not installed from a trusted app store. Verify you intended to install it."
display:
    category: app_risk
    icon: install_mobile
    triggered_title: Sideloaded App Detected
    safe_title: All Apps From Trusted Sources
    evidence_type: none
    summary_template: "{{app_name}} ({{package_name}}) was not installed from a trusted store."
```

---

## Validation

Run the validation script before submitting a rule:

```bash
python3 validation/validate-rule.py path/to/your-rule.yml
```

Exit code `0` means the rule is valid. Exit code `1` prints specific errors to
stderr. New rules should start with `status: experimental` and graduate to
`test` then `production` after review.
