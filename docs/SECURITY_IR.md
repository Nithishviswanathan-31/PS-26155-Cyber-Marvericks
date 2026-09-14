# Security IR and source provenance

P0.2 defines the vendor-neutral contract between future vendor parsers and the
deterministic compliance engine.

## Shape

`SecurityIR` contains:

- `schema_version`
- `device.vendor`, `device.version`, and optional hostname, model, serial number,
  and device ID
- extensible `normalized_properties`
- a `provenance` map keyed by normalized property
- `unknown_patterns`

The normalized property dictionary is intentionally extensible. The current demo
properties are not the only properties permitted by the model.

## Provenance

Each provenance record contains:

- source file
- optional one-based start and end lines
- raw source excerpt

`SecurityIR.trace_property(name)` returns the normalized value together with its
provenance record. This is the contract the future Evidence module will consume.

## Unknown patterns

Unknown patterns preserve the raw text and source location with status
`UNKNOWN`. P0.2 does not interpret, approve, or learn unknown patterns.

## Trust boundary

P0.2 only validates and traces data. It does not determine compliance. The
approved project principle remains:

> AI proposes → deterministic engine validates → evidence proves
