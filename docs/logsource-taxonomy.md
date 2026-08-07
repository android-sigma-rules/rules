# AndroDR Logsource Taxonomy

The authoritative, machine-validated taxonomy of logsource services and their
detection fields lives at
[`validation/logsource-taxonomy.yml`](../validation/logsource-taxonomy.yml) —
it is the single source of truth, consumed by `validation/validate-rule.py`
(field lint) and gated by AndroDR's `LogsourceTaxonomyCrossCheckTest` /
`DetectionFieldCrossCheckTest` at the pinned submodule.

This page previously duplicated a subset of that data by hand and had
drifted; it was replaced by this pointer (AndroDR #268) so there is exactly
one place to edit. Before editing the YAML, read its SAFE ORDERING header
comment.
