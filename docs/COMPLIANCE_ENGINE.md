# Deterministic compliance engine

V2 expands the catalogue contract and rejects invalid property types as UNKNOWN.
See [Control & Framework Foundation](CONTROL_FOUNDATION_V2_1.md) for metadata,
enabled-control selection, evidence requirements, and compatibility details.

P0.3 adds the first compliance evaluation layer. It consumes a validated
`SecurityIR` and the YAML control catalogue and returns a structured
`ControlEvaluationResult`.

## Evaluation flow

1. Read the control's evaluation type and conditions from YAML.
2. Resolve each condition path against `SecurityIR.normalized_properties`.
3. Resolve source evidence with `SecurityIR.trace_property()`.
4. Evaluate the supported operator deterministically.
5. Combine condition results according to the YAML group.
6. Return the result and evidence as Pydantic models.

The engine is vendor-neutral. Vendor-specific syntax belongs to future parser
modules and must not be placed in `control_engine.py`.

## Supported logic

P0.3 supports:

- `equals` for property comparison
- `all` for requiring every condition to pass
- explicit `not_applicable`/`na` controls

New controls can be added by extending `controls/demo_controls.yaml` with the
existing control-definition shape. The Python engine does not contain a branch
for each demo control.

## Result semantics

- `PASS`: every required condition passed.
- `FAIL`: at least one condition explicitly failed and no condition was unknown.
- `UNKNOWN`: a required property or provenance record is unavailable, or the
  evaluation type/operator is unsupported.
- `PARTIAL`: reserved for a later control type; P0.3 does not manufacture
  partial conclusions.
- `NOT_APPLICABLE`: returned only when the control explicitly declares it.

Missing data is never converted into `FAIL`.

## Evidence

Each condition produces evidence containing the property path, expected value,
actual value, condition result, source file, line range, raw excerpt, and a
deterministic explanation. If provenance is missing, the control becomes
`UNKNOWN` so the system cannot claim an evidence-backed result.

## Trust boundary

There is no AI call in P0.3. The final result is calculated only by explicit
control logic and validated Security IR data:

> AI proposes → deterministic engine validates → evidence proves
