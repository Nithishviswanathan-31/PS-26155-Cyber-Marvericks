# P0.10-B Controlled Candidate Mapping Workflow

P0.10-B adds the first controlled adaptive-learning artifact for the fictional
AstraNet demonstration. It stores approved knowledge locally; it does not
retrain a foundation model and does not perform re-analysis.

## Trust boundary

```text
UnknownPattern
    ↓
controlled candidate suggestion
    ↓
Pydantic validation
    ↓
human approve / correct / reject
    ↓
versioned SQLite knowledge
```

The local demo adapter implements the same interface a future AI provider can
implement. It recognizes only `guard-channel lattice-secure` for vendor
`astranet` and proposes:

```json
{
  "management.ssh_enabled": true,
  "management.telnet_enabled": false
}
```

This is a candidate interpretation, not an established fact. The suggestion
has a demo confidence value of `0.94`; this is not a measured accuracy
percentage.

## Validation

Candidate mappings require matching `pattern_id`, `SUGGESTED` status, confidence
from `0.0` through `1.0`, at least one supported vendor-neutral property, strict
boolean semantic values, non-empty reasoning, and
`requires_human_approval: true`. Unsupported properties and approval-bypass
output are rejected. Suggestions do not modify
`SecurityIR.normalized_properties`.

## Human decisions

- **Approve** stores the candidate as an `APPROVED`, `ACTIVE` mapping.
- **Correct + approve** stores the reviewer-edited meaning as a new approved
  version.
- **Reject** stores an inactive `REJECTED` version and leaves the pattern
  unresolved.

Every decision stores a demo reviewer identity, action, timestamp, and mapping
version. A later approved version marks the previous version `INACTIVE`; old
versions are retained for lineage.

The decision response explicitly reports `compliance_impact: UNCHANGED`.
Approval never creates PASS or FAIL and never invokes remediation or device
commands. The original `UnknownPattern` is not retroactively rewritten.

## API

```text
GET  /api/mappings/unknown/{pattern_id}
POST /api/mappings/{pattern_id}/suggest
POST /api/mappings/{pattern_id}/approve
POST /api/mappings/{pattern_id}/correct
POST /api/mappings/{pattern_id}/reject
GET  /api/mappings/{pattern_id}/versions
```

Suggestions are returned for review. Only explicit approve/correct/reject
operations are persisted in the local SQLite mapping tables.

## Explicit re-analysis

P0.10-C consumes an active approved mapping only through an explicit
`POST /api/analyze/{analysis_id}/reanalyze` request. It deep-copies the stored
original Security IR, applies the mapping, reruns the deterministic engine, and
creates a new child analysis with `parent_analysis_id`, mapping version, fresh
evidence, and `RECOGNIZED_VIA_APPROVED_MAPPING` state. The original analysis,
its Security IR snapshot, and its evidence remain unchanged. Approval alone
never triggers this operation.

P0.11 integrity hardening verifies that the original analysis, Security IR, and
evidence remain unchanged. Each explicit re-analysis is an independent child
record with its own ID and the exact active mapping version used at that time.
If v1 is later inactivated for v2, historical children continue to report v1;
new re-analysis uses v2.
