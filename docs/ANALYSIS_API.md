# Basic configuration analysis API

P0.6 exposes the first end-to-end HTTP path for the emergency demo MVP:

```text
multipart file upload
  → CiscoParser, FortiGateParser, PaloAltoParser, or AstraNetParser
  → SecurityIR
  → DeterministicControlEngine
  → build_evidence()
  → AnalysisResponse JSON
```

## Endpoint

```http
POST /api/analyze
Content-Type: multipart/form-data
```

The form field is named `file`. P0.6 accepts `.conf`, `.cfg`, and `.txt` files
up to 1 MB and supports the focused Cisco IOS/IOS-XE, FortiGate/FortiOS, Palo
Alto/PAN-OS, and fictional AstraNet synthetic demonstration input. The
frontend remains a shared result/evidence view without vendor-specific
compliance logic and displays AstraNet unknown patterns.

P0.10-B adds separate mapping-review endpoints. `POST /api/analyze` remains
unchanged and continues to return AstraNet as UNKNOWN until a later explicit
re-analysis phase.

Mapping review endpoints are documented in
`docs/ADAPTIVE_MAPPING_WORKFLOW.md`. They store only explicit human decisions;
they do not alter an existing analysis response.

P0.10-C adds:

```http
POST /api/analyze/{analysis_id}/reanalyze
```

This endpoint requires an active approved mapping, creates a new child analysis,
and leaves the parent analysis immutable. The response includes
`parent_analysis_id`, `reanalyzed`, `mapping_id`, `mapping_version`,
`recognized_patterns`, and mapping-aware evidence. Approval does not invoke
this endpoint automatically.

## Response

The response contains:

- unique `analysis_id`
- safe uploaded `filename`
- detected `vendor`
- device metadata
- deterministic control result summaries
- traceable evidence records
- unknown patterns from the parser

The original uploaded configuration is not persisted. Only the structured
analysis response is stored in the minimal SQLite demo table.

## Batch analysis

Batch analysis reuses the same parser, Security IR, deterministic control,
evidence, and persistence pipeline as single-file analysis:

```http
POST /api/batches/analyze
Content-Type: multipart/form-data
```

The repeated form field is `files`. A batch accepts at most 25 `.conf`, `.cfg`,
or `.txt` files, each up to 1 MB, with a 10 MB total limit. Items are processed
independently, so a malformed or unsupported item does not discard valid
analyses. The response reports batch processing status separately from each
analysis's PASS, FAIL, UNKNOWN, or MIXED compliance status.

```http
GET /api/batches/{batch_id}
GET /api/batches/{batch_id}/items
GET /api/analyze/{analysis_id}
```

Identical content is retained as a new analysis history entry and marked with
the earlier configuration ID. ZIP/archive uploads are rejected in this
checkpoint; bounded multi-file upload keeps file extraction and archive-bomb
risk out of the application until a separately reviewed archive design exists.

## Error behavior

- Empty files, invalid encoding, unsupported extensions, and unsupported input
  return HTTP 400.
- Parser and client validation failures do not become PASS or FAIL.
- Unexpected processing/storage failures return a safe HTTP 500 message without
  stack traces.

Expected errors include a stable `error_code` alongside the backwards-compatible
`detail` message. Current codes include `ANALYSIS_NOT_FOUND`,
`UNSUPPORTED_INPUT`, `MALFORMED_CONFIGURATION`, `UNKNOWN_PATTERN`,
`NO_ACTIVE_MAPPING`, `INVALID_MAPPING`, `INACTIVE_MAPPING`,
`REANALYSIS_FAILED`, and `STORAGE_FAILURE`. Request-body validation uses
`VALIDATION_ERROR` and includes an `errors` array.

Example:

```json
{
  "detail": "No active approved mapping exists for unknown pattern 'astranet-unknown-5'.",
  "error_code": "NO_ACTIVE_MAPPING"
}
```

Historical analyses are immutable. Re-analysis creates a new child analysis
and records the exact approved mapping version used; it never dynamically
reinterprets an earlier result.

## Controlled interpretation

Unknown patterns can request a provider-neutral interpretation proposal:

```http
POST /api/interpretations/{analysis_id}
GET  /api/interpretations/{analysis_id}
GET  /api/interpretations/proposals/{proposal_id}
GET  /api/interpretations/proposals/{proposal_id}/history
```

The offline provider is explicitly named `DEMO_INTERPRETATION_PROVIDER`. It
recognizes only the synthetic AstraNet demonstration pattern and produces a
versioned proposal containing its identity, source context, candidate mapping,
confidence, explanation, and provider version. It is not an AI model and its
confidence value is not an accuracy claim.

The existing mapping review endpoints accept `proposal_id` so approval,
correction, and rejection remain human actions while preserving proposal
history. Approval stores a versioned mapping but reports unchanged compliance;
only explicit re-analysis applies the mapping through the hardened identity
checks and deterministic control engine. An AI proposal alone cannot create
PASS or FAIL, and AI text is never used as compliance evidence.

The boundary remains:

```text
AI proposes → deterministic engine validates → evidence proves.
```

P0.12 remediation simulation is exposed separately through:

```http
GET  /api/remediation/{analysis_id}
POST /api/remediation/{analysis_id}/simulate
```

These endpoints return only deterministic, simulation-only recommendations for
supported FAIL findings. They operate on a deep copy, perform a deterministic
re-audit, and never contact or modify production devices. See
`docs/REMEDIATION_SIMULATION.md`.

P0.13 adds the read-only evidence-first PDF export:

```http
GET /api/reports/{analysis_id}/pdf
```

It returns a downloadable PDF assembled from the stored analysis response,
evidence, exact mapping lineage, and stored simulation data. It does not run
compliance evaluation or modify any stored record. Missing analyses return the
structured `ANALYSIS_NOT_FOUND` error; incomplete report data returns
`REPORT_DATA_INCOMPLETE`; safe generation failures return
`REPORT_GENERATION_FAILED`.

P0.14 adds the local development/demo reset:

```http
POST /api/demo/reset
```

It deletes local demo analyses, mappings, and simulations while preserving the
SQLite schema. The route returns `DEMO_RESET_DISABLED` with HTTP 403 when
`APP_ENV=production`. It is not a production database-administration endpoint.

## Device and configuration context

Each successful upload creates a `Device` observation and a linked
`Configuration` record in the local SQLite store. The analysis response keeps
the existing device fields and adds a configuration summary containing its ID,
device association, source filename, SHA-256 fingerprint, detected vendor,
parser status, and timestamps. Raw uploaded text remains transient.

The read APIs are:

```http
GET /api/devices/{device_id}
GET /api/devices/{device_id}/analyses
GET /api/configurations/{configuration_id}
GET /api/parser-capabilities
```

Repeated uploads with the same reliable hostname/vendor identity reuse the
device ID and create separate configuration and analysis records. Identical
content is marked with `duplicate_of_configuration_id`; no analysis history is
deleted. An upload may submit `device_id` to associate with an existing device,
and vendor mismatch is rejected. Missing hostname produces a separate local
observation because no stable device identity was detected.

## Manual test

From the repository root:

```bash
curl -X POST \
  -F "file=@configs/cisco/compliant.conf" \
  http://127.0.0.1:8000/api/analyze
```

Windows PowerShell:

```powershell
curl.exe -X POST `
  -F "file=@configs/cisco/compliant.conf" `
  http://127.0.0.1:8000/api/analyze
```

FastAPI exposes the same contract at `/docs` and `/openapi.json`.
