# V2 — Control Foundation and Hardening

“AI proposes → deterministic engine validates → evidence proves.”

## Control contract

`backend/app/domain/schemas.py` defines the expanded `ControlDefinition`.
The existing `control_id`, `name` (the display title), `description`,
`expected_value`, `evaluation`, `evidence_rule`, and `remediation` fields remain
compatible with V1. Evidence schemas remain unchanged. New result summaries
persist `diagnostic_of` so counting uses stored relationships rather than the
live catalogue. Historical JSON is not rewritten; legacy summaries without
relationships remain readable and retain their original counting behavior.

| Field | Meaning |
| --- | --- |
| category | Validated category; null for legacy definitions without metadata |
| severity | LOW, MEDIUM, HIGH, or CRITICAL; null for legacy definitions |
| enabled | Strict boolean, default true; loader selects enabled controls after validating the whole catalogue |
| applicable_vendors | Validated list of existing vendor identifiers; informational direct parser support |
| framework_mappings | List of framework references; empty until verified |
| evidence_requirements | Evaluated property paths and display field names; optional for legacy definitions |
| remediation_reference | Vendor-to-existing-remediation-ID mapping, or null |
| diagnostic_of | Existing root control ID for a diagnostic child, or null |

Categories are MANAGEMENT_ACCESS, LOGGING_MONITORING, AUTHENTICATION,
CREDENTIAL_PROTECTION, TIME_SYNCHRONIZATION, NETWORK_SECURITY,
CONFIGURATION_SECURITY, and CRYPTOGRAPHY. Severity is local prioritization
metadata, not an official framework rating or input to compliance evaluation.

Vendor identifiers are `cisco_iosxe`, `fortigate_fortios`, `paloalto_panos`, and
`astranet`. All six catalogue controls declare the first three, whose focused
parsers expose the required properties. This does not imply complete vendor
syntax coverage. AstraNet emits no normalized properties before its existing
approved-mapping workflow; it is accepted by the schema but not advertised as
direct parser support. Applicability never filters evaluations or creates N/A.
The existing AstraNet UNKNOWN and explicit mapping/re-analysis behavior remains.

## Framework and evidence metadata

Each framework mapping has `framework_name`, optional `framework_version`,
`reference_id`, and optional `title` and `description`. Required text must not
be blank. All shipped mappings are empty: no official IDs or verified mappings
are claimed. Schema validation checks structure, not authority or correctness
of an external framework reference. Framework verification is future work.

Evidence requirements use `include_paths` and `display_fields`. Paths must
cover exactly the evaluation properties without duplicates and agree with
legacy `evidence_rule.include_paths` when present. Default display fields are
actual, expected, source_file, line_start, line_end, raw_excerpt, evidence_source,
result, and condition_result. These describe evidence already generated from
Security IR; they do not populate values, manufacture provenance, suppress
missing evidence, or override the existing evidence builder/UI. All existing
mapping and simulation provenance remains preserved by the evidence model.

Historical checkpoint scope: this control-foundation slice originally shipped
only CTRL-001 remediation IDs (`REM-CTRL-001-CISCO`,
`REM-CTRL-001-FORTIGATE`, and `REM-CTRL-001-PALOALTO`). Current V2 also has
deterministic, simulation-only support for CTRL-002 logging, CTRL-003 credential
protection and CTRL-004 time synchronization where parser-backed vendor
properties exist. Unsupported vendor/control combinations remain explicitly
unsupported; no remediation executes commands or changes a real device.

The loader verifies each remediation reference against the implementation's
vendor/control/ID tuple, including disabled controls. Nonexistent or mismatched
references fail with `CatalogueError.error_code = INVALID_CATALOGUE`.

`display_fields` is explicitly advisory presentation metadata. Its names are
validated, but it is not a filter: all existing evidence remains available even
when the advisory list is empty. It cannot change compliance.

## Catalogue and limits

The first four controls retain their IDs, names, conditions, expected values,
order, evidence rules, and remediation behavior.

| ID | Name | Category | Severity |
| --- | --- | --- | --- |
| CTRL-001 | Secure management transport | MANAGEMENT_ACCESS | HIGH |
| CTRL-002 | Audit logging enabled | LOGGING_MONITORING | MEDIUM |
| CTRL-003 | Secret protection enabled | CREDENTIAL_PROTECTION | HIGH |
| CTRL-004 | Time synchronization configured | TIME_SYNCHRONIZATION | MEDIUM |
| CTRL-005 | SSH management enabled | MANAGEMENT_ACCESS | HIGH |
| CTRL-006 | Telnet management disabled | MANAGEMENT_ACCESS | HIGH |

The two new checks independently evaluate `management.ssh_enabled == true`
and `management.telnet_enabled == false`. They expose separate outcomes when
CTRL-001 has mixed or incomplete information. They overlap CTRL-001 and must
not be interpreted as independent risk coverage or a new weighted score.
Both declare `diagnostic_of: CTRL-001`. All six results and their evidence remain
visible. Dashboard and PDF independent requirement totals count only root
results: four requirements, plus two separately labeled diagnostics. There is
no weighted score. An UNKNOWN parent remains UNKNOWN even if a child fails;
the child failure stays visible in details. Relationships are snapshotted for
analysis, re-analysis, and simulation. A child must reference an existing root,
use its conditions, and cannot be enabled while its parent is disabled.

The requested approximate 10–15 target is deliberately not filled: the parsers
provide only five distinct security properties. Additional combinations would
inflate the catalogue without adding independent checks. More coverage requires
future parser/property work outside this pass. Existing vendor normalization is also
coarse: password protection represents different platform mechanisms, not a
new assertion of equivalent cryptographic strength.

## Deterministic boundary and presentation

The engine still evaluates only conditions and actual Security IR traces.
Missing values, missing provenance, ambiguous values, and unsupported operators
remain UNKNOWN. FAIL requires an explicit mismatch without unknown conditions;
PASS requires all supported conditions to match with provenance. Only an
explicit `na`/`not_applicable` evaluation creates NOT_APPLICABLE. PARTIAL remains
reserved. Metadata, including framework, category, severity, applicability,
evidence requirements, and remediation references, cannot change the result.
Disabled controls are omitted by catalogue loading, never relabeled PASS or N/A;
direct evaluation of a control is unchanged by its enabled flag.

## Type and catalogue safety

`domain/properties.py` defines exact boolean types for the five existing
normalized properties. The engine checks both actual and expected values before
comparison: integers, floats, strings, unregistered properties, and other invalid
representations produce UNKNOWN with an explanation. There is no coercion.
Missing values and None still produce UNKNOWN. The IR retains original values
for evidence, and the vendor parsers are unchanged.

The catalogue must be a mapping with a `controls` key containing a nonempty
list. Missing/null/wrong-shaped catalogues, malformed entries, duplicate IDs,
invalid expectations/properties, references, or relationships raise structured
`INVALID_CATALOGUE` configuration errors. YAML/read failures are wrapped too.
A valid nonempty catalogue with all controls disabled returns an intentionally
empty selection. Startup validates the catalogue; API failures expose the same
configuration error code.

## Approved mapping identity

Uploaded pattern locators retain the parser occurrence ID plus a SHA-256
configuration-content fingerprint. Source locations remain unchanged. Identical
configuration content can reuse its locator; distinct configurations do not
share a locator just because a directive appears on the same line.

Approval stores an identity snapshot on the exact mapping version: normalized
context, allowed target properties, original source pattern/location, and source
analysis ID, alongside vendor/signature/version. Application requires an active,
approved positive integer version and matching vendor, signature, context,
source-pattern signature, and target-property set. Allowed properties/values are
strictly validated. A locator alone never authorizes application. Matching
semantic identity can apply to a different occurrence when explicitly selected.

Legacy mappings without identity snapshots remain available for historical
reports; new application requires explicit re-approval. No guessed context is
backfilled. SQLite adds a nullable `identity_json` column without deleting old
rows. Corrections preserve prior approval payloads/identity and follow the
existing active/inactive lifecycle. Conflicting legacy occurrence contexts are
rejected with `INVALID_MAPPING`, not resolved by choosing the latest analysis.
Original analyses and previously created children remain unchanged.

No AI provider, bulk ingestion, new parser, remediation expansion, authentication,
or deployment change is included. Full catalogue versioning and migration of
historical pre-relationship six-control summaries remain future work.

## Device, configuration, and IR context

The analysis path now records a local `Device` observation and a linked
`Configuration` event without changing the existing parser-to-engine flow.
Reliable hostname/vendor metadata produces a stable derived device ID; missing
hostname keeps uploads as separate observations. Serial numbers and hardware
identifiers remain empty unless a parser actually detects them. Configuration
records retain source filename, upload time, parser status, detected vendor,
SHA-256 content fingerprint, and analysis history linkage. Identical content is
marked as a duplicate configuration while every analysis remains preserved.

The property registry also describes three parser-backed facts outside the
current control catalogue: `logging.buffered_enabled` for Cisco,
`credentials.password_policy_enabled` for FortiGate, and
`credentials.username_exclusion_enabled` for Palo Alto. They have strict
boolean types, source provenance, descriptions, and capability states. Existing
five control properties remain unchanged. `GET /api/parser-capabilities` exposes
SUPPORTED, PARTIAL, and UNSUPPORTED status by vendor; capability metadata does
not fabricate an IR value or change compliance.
