# P0.10-C Explicit Re-analysis Workflow

P0.10-C is the explicit bridge between approved mapping knowledge and a new
deterministic audit result.

```text
original analysis
  → active approved mapping
  → deep Security IR copy
  → deterministic controls
  → fresh evidence
  → child analysis
```

## API

```http
POST /api/analyze/{analysis_id}/reanalyze
```

The endpoint supports the synthetic AstraNet flow. It loads the stored
original analysis and Security IR snapshot, requires an active `APPROVED`
mapping for each unknown pattern, applies the mapping to a copy, and evaluates
that copy with the existing generic deterministic engine.

There is no automatic call after approval. Missing, inactive, rejected, or
invalid mappings return an explicit conflict/error response.

## Immutability and lineage

The parent retains its original `UNKNOWN` results and source evidence. The new
response has:

- a new `analysis_id`
- `parent_analysis_id`
- `reanalyzed: true`
- `mapping_id` and `mapping_version`
- `reanalyzed_at`
- a completion message

The mapped property values are recorded in `SecurityIR.mapping_provenance`.
The original unknown pattern remains in `unknown_patterns`, while an explicit
`recognized_patterns` record states
`RECOGNIZED_VIA_APPROVED_MAPPING`.

## Evidence

Re-analysis evidence has `evidence_source: APPROVED_MAPPING`, mapping identity
and version, and the original pattern/source location. It does not fabricate a
configuration line for a value that came from a mapping.

Approval still does not mean PASS or FAIL. The deterministic engine evaluates
the enriched copy; in the AstraNet demo, the SSH/Telnet control can PASS while
controls without mapped properties remain UNKNOWN.
