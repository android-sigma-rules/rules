# Pipeline run ledger

One YAML file per AI rule-update pipeline run, written at the end of the
human-in-the-loop review (Step 8 of the dispatcher). Rules are the product;
this ledger is telemetry — a ledger write failure never blocks a rule commit.

File name: `YYYY-MM-DD-<mode>.yml` (mode: `full`, `source-<id>`, `threat`,
`discover`, or `e2e`; append `-2`, `-3`… for multiple same-day runs).

## Schema

```yaml
run: 2026-06-10
mode: full
candidates:
  - id: androdr-085          # rule ID, or the indicator for IOC-only candidates
    verdict: approved        # approved | approved_with_modification | rejected
    reason: ""               # reviewer's words; REQUIRED unless verdict=approved
    failure_class: null      # severity_judgment | fp_risk | duplicate_semantics |
                             # weak_sourcing | category_choice | other | null
totals:
  candidates: 7
  approved: 5
  approved_with_modification: 1
  rejected: 1
  approval_without_modification_rate: 0.71   # approved / candidates, 2 dp
```

`failure_class` feeds `validation/authoring-lessons.yml` curation: recurring
classes become candidate lessons, proposed by the dispatcher and approved by
the human like any other candidate.
