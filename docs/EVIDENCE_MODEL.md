# Evidence model

P0.5 provides a dedicated `EvidenceRecord` and `build_evidence()` function for
turning a deterministic control evaluation into reusable, traceable evidence.

## Evidence purpose

Evidence is consumed later by findings, the frontend evidence view, reports,
and audit history. It preserves the relationship between a control result and
the exact normalized property and source configuration that supported it.

## Schema

Each record contains:

- `control_id` and `control_name`
- normalized `property`
- `expected` and `actual`
- final deterministic `result`
- property-level `condition_result`
- `source_file`
- `line_start` and `line_end`
- `raw_excerpt`
- property explanation and overall control explanation
- vendor and configuration version when available

## Provenance lookup

`build_evidence(security_ir, control_evaluation)` calls
`SecurityIR.trace_property()` for every property in the control evaluation.
It does not reconstruct provenance lookup logic and does not trust generated
source values from elsewhere.

## Multi-property controls

Each property receives its own evidence record. For example, `CTRL-001`
produces separate records for `management.ssh_enabled` and
`management.telnet_enabled`. Their source locations are never merged into one
ambiguous record.

## Missing provenance

When a property exists but has no provenance, the evidence record contains no
fabricated source file, line, or raw excerpt. The existing deterministic engine
keeps the control result compatible with `UNKNOWN` when evidence is required.

When the property itself is missing, `actual` is `null` and source fields remain
empty.

## Relationship to compliance

The evidence module does not evaluate conditions and does not change the
control result. It copies the final result produced by the deterministic engine
and adds traceability:

> Evidence supports the result; it does not decide the result.
