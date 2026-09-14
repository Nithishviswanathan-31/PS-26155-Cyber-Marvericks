# P0.13 Evidence-First PDF Reporting

P0.13 adds a read-only export layer for the emergency demo MVP. The report
service formats stored analysis results, evidence, mapping lineage, and
simulation records; it does not run the control engine or make new compliance
decisions.

## Data flow

```text
Stored analysis → stored deterministic results → stored evidence → PDF export
```

The report preserves three evidence sources when present:

- `CONFIGURATION` — source file, line range, and raw configuration excerpt.
- `APPROVED_MAPPING` — a property enriched by an approved mapping, with the
  original unknown pattern and mapping version retained.
- `SIMULATED_REMEDIATION` — a property changed only on a simulation copy, with
  original source provenance retained separately.

Missing provenance is rendered as `Not available`; the report never invents a
source location or raw excerpt.

## API

```http
GET /api/reports/{analysis_id}/pdf
```

The endpoint loads the immutable analysis by ID and returns a downloadable PDF.
For a re-analysis it loads the exact mapping ID/version recorded on that child
analysis. For an analysis with a simulation result it includes the latest
stored simulation record. It never dynamically recalculates or reinterprets
historical results.

## Report sections

The PDF contains an executive summary, stored control results, evidence
details, analysis lineage, adaptive mapping details when applicable, and
remediation simulation details when applicable. The final disclaimer states:

```text
AI interpretation ≠ compliance decision
Simulation ≠ production remediation
UNKNOWN ≠ FAIL
```

The report explicitly states that compliance decisions came from the
deterministic engine, AI-assisted interpretation does not independently prove
compliance, and no production device was contacted or modified.

## Frontend

The analysis page provides **Generate PDF Report** for an original analysis,
**Generate Re-analysis Report** for an explicit mapping-based child analysis,
and **Generate Report** in the simulation result card. The browser downloads
the backend-generated PDF; it does not construct report content.

This remains a prototype report for implemented controls and available
evidence, not a certification or complete security assessment.
