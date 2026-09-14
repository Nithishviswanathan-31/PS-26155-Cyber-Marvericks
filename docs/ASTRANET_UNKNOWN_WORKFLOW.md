# P0.10-A AstraNet UNKNOWN-Pattern Workflow

This phase adds a deliberately fictional AstraNet input to demonstrate safe
handling of an unfamiliar configuration pattern. AstraNet is not a real
vendor, and the fixture is not customer or production configuration data.

## Synthetic input

The fixture is:

```text
configs/astranet/unknown-pattern.conf
```

It contains the synthetic directive:

```text
guard-channel lattice-secure
```

That directive has no approved mapping to a normalized Security IR property in
P0.10-A. The parser therefore does not infer SSH, Telnet, logging, password
protection, or NTP state from it.

## Workflow behavior

The focused parser detects the synthetic marker and `astranet-device` line,
then records the `guard-channel` line as an `UnknownPattern` with:

- `pattern_id`
- `status: UNKNOWN`
- raw pattern text
- source filename
- exact one-based source line
- a `SourceLocation` containing the raw excerpt
- a reason and synthetic-parser context

The Security IR has `vendor: astranet`, device hostname metadata, an empty
normalized property map, and one unknown pattern. Since no required property
has been guessed, the existing deterministic control engine returns
`UNKNOWN` for the four demo controls. This is safe unresolved-state behavior,
not a compliance failure.

The API exposes the result through `POST /api/analyze`, and the existing
frontend displays the unknown pattern, source, line, and reason. No AI call,
candidate mapping, approval, persistence, or re-analysis is part of this
phase.

## Provenance

The unknown pattern itself is traceable to the exact original line. Because no
normalized property exists yet, control evidence for a required property has
no fabricated source location. P0.10-A keeps those two facts distinct:

```text
unknown pattern → exact source provenance
unresolved property → no invented semantic provenance
```

## Follow-on phase: P0.10-B

P0.10-B adds the controlled candidate-mapping suggestion and explicit human
approval contract in a separate workflow. It preserves the rule that AI cannot
directly set compliance outcomes. P0.10-A itself does not include those
operations.
