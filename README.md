# PS 26155 — Emergency Demo MVP

AI-Driven Multi-Vendor Network Security Compliance Auditor for the internal
college hackathon demonstration by CYBER MARVERICKS.

This repository is intentionally limited to the verified P0.1 foundation, the
P0.2 Security IR/source-provenance contract, the P0.3 deterministic compliance
engine, the focused P0.4 Cisco IOS/IOS-XE parser, the P0.5 evidence module, the
P0.6 basic analysis API, the P0.7 frontend upload/analysis workflow, and the
focused P0.8 FortiGate/FortiOS parser, the focused P0.9 Palo Alto/PAN-OS
parser, the P0.10-A synthetic AstraNet UNKNOWN-pattern workflow, and the
P0.10-B controlled candidate-mapping workflow, P0.10-C explicit
mapping-aware re-analysis, P0.11 integrity/demo hardening, P0.12 safe
remediation simulation/re-audit, and P0.13 evidence-first PDF reporting. It is an
emergency demo MVP, not the complete production-grade system.

## Technology stack

- Backend: Python, FastAPI, Pydantic, PyYAML, ReportLab, SQLite
- Frontend: React, TypeScript, Vite, Material UI
- Controls: YAML catalogue

SQLite is used for the emergency local demo. The storage module is kept separate
so PostgreSQL can be introduced in a later phase.

## Local setup

From the repository root:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r backend/requirements.txt
```

On Windows PowerShell, activate with:

```powershell
.venv\Scripts\Activate.ps1
```

## Start the backend

```bash
python -m uvicorn app.main:app --app-dir backend --reload --port 8000
```

Health check:

```bash
curl http://127.0.0.1:8000/health
```

Expected response:

```json
{"status":"ok"}
```

## Start the frontend

```bash
cd frontend
npm install
npm run dev
```

Open the Vite URL shown in the terminal, normally `http://localhost:5173`.

## Run tests

From the repository root:

```bash
PYTHONPATH=backend pytest backend/tests -q
```

## Current MVP scope

P0.1 and P0.2 currently include:

- Compliance and pattern status enums
- Extensible Security IR contract with device metadata
- Source provenance with file, line range, and raw excerpt
- Unknown-pattern records with explicit source fields and `UNKNOWN` status
- `SecurityIR.trace_property()` source traceability helper
- Representative JSON Security IR fixture at `configs/fixtures/sample_security_ir.json`
- SQLite initialization without the future application schema
- Four validated demo control definitions
- Minimal FastAPI health endpoint
- Minimal React/MUI application shell

P0.3 additionally includes:

- Generic YAML-driven deterministic control evaluation
- `PASS`, `FAIL`, `UNKNOWN`, and explicit `NOT_APPLICABLE` handling
- Evidence returned from Security IR provenance
- Structured control evaluation result models
- Repeatability coverage

P0.4 additionally includes:

- Focused Cisco IOS/IOS-XE configuration parser
- Cisco synthetic compliant, non-compliant, and unknown fixtures
- Source provenance for every parsed normalized property
- Cisco parser-to-control-engine integration tests

P0.5 additionally includes:

- Reusable Pydantic `EvidenceRecord`
- `build_evidence()` provenance-based evidence generation
- Separate evidence for each property in multi-property controls
- Missing-provenance protection and evidence serialization tests

P0.6 additionally includes:

- `POST /api/analyze` multipart upload endpoint
- Cisco upload-to-evidence JSON response
- Minimal persisted analysis response in SQLite
- Safe file validation and error handling
- FastAPI OpenAPI/Swagger exposure

P0.7 additionally includes:

- Typed frontend client for `POST /api/analyze`
- Cisco-only configuration upload and drag-and-drop workflow
- Explicit upload, loading, success, and error states
- Deterministic result table with PASS, FAIL, PARTIAL, NOT APPLICABLE, and UNKNOWN labels
- Traceable evidence detail dialog with source file, line range, and raw excerpt
- Minimal session dashboard with navigation between Dashboard and Analyze Configuration

P0.8 additionally includes:

- Focused FortiGate/FortiOS parser with vendor-neutral Security IR output
- Synthetic FortiGate compliant, non-compliant, and unknown fixtures
- FortiGate provenance and parser-to-engine/evidence integration tests
- Cross-vendor normalization coverage for Cisco and FortiGate

P0.9 additionally includes:

- Focused Palo Alto/PAN-OS `set`-statement parser with vendor-neutral Security IR output
- Synthetic Palo Alto compliant, non-compliant, and unknown fixtures
- Minimal API routing for Cisco, FortiGate, and Palo Alto
- Three-vendor normalization and control-engine integration coverage

P0.10-A additionally includes:

- Fictional AstraNet detection and focused parser
- Synthetic unknown-pattern fixture with exact source provenance
- Safe UNKNOWN results through the existing deterministic engine
- Minimal API and frontend display of unresolved patterns

Not yet implemented: authentication and advanced dashboards. This remains an
emergency demo MVP, not a production deployment.

## P0.9 status

P0.9 adds focused Palo Alto/PAN-OS parsing while preserving the Cisco and
FortiGate parsers, generic deterministic engine, evidence module, and existing
frontend result/evidence workflow. The Palo Alto parser is intentionally limited
to the documented `set`-statement patterns; unsupported or ambiguous input
remains UNKNOWN.

## P0.10-A status

P0.10-A adds only a fictional AstraNet configuration used to prove that an
unfamiliar `guard-channel lattice-secure` pattern is retained as `UNKNOWN`
with exact source provenance. The phase itself added no mapping approval or
re-analysis. See `docs/ASTRANET_UNKNOWN_WORKFLOW.md` for the phase contract.

## P0.10-B status

P0.10-B adds a schema-validated local candidate suggestion adapter, explicit
human approve/correct/reject operations, and versioned SQLite mapping history.
Approval stores knowledge only; it does not modify Security IR or produce
PASS/FAIL. P0.10-C now adds explicit copy-based re-analysis using the active
approved mapping. See
`docs/ADAPTIVE_MAPPING_WORKFLOW.md`.

## P0.10-C status

P0.10-C adds explicit `POST /api/analyze/{analysis_id}/reanalyze`. It creates a
new child analysis, applies the active approved mapping to a deep Security IR
copy, reruns the deterministic controls, and records mapping-aware evidence.
The original analysis remains immutable; mapped patterns are marked
`RECOGNIZED_VIA_APPROVED_MAPPING`. Reporting remains outside this phase.

## P0.11 status

P0.11 hardens the existing MVP without adding a new functional layer.
Historical analyses, Security IR snapshots, and evidence are immutable.
Explicit re-analysis creates a new child analysis and records the exact
approved mapping version used; repeated re-analysis creates independent
children. API failures include stable machine-readable `error_code` values
alongside the legacy `detail` message. AI suggestions never directly
determine compliance.

## P0.12 status

P0.12 adds deterministic remediation recommendations for the supported
CTRL-001 management-transport finding on Cisco IOS/IOS-XE, FortiGate/FortiOS,
and Palo Alto/PAN-OS. Simulation deep-copies the stored Security IR, applies a
controlled property transformation, reruns the deterministic engine, and
stores fresh before/after evidence. No command is executed and no production
device is contacted or modified. AstraNet remains focused on adaptive mapping.

## P0.13 status

P0.13 adds an evidence-first, read-only PDF export at
`GET /api/reports/{analysis_id}/pdf`. It formats stored deterministic results,
source evidence, analysis lineage, approved mapping/version provenance, and
simulation-only before/after data without recalculating compliance or mutating
stored records. Historical analyses remain immutable. See
`docs/PDF_REPORTING.md`.

## P0.14 demo quick-start

The following uses only checked-in synthetic fixtures and local SQLite data:

```bash
# From the repository root
python -m venv .venv
source .venv/bin/activate
python -m pip install -r backend/requirements.txt

# Terminal 1 — backend
PYTHONPATH=backend python -m uvicorn app.main:app --app-dir backend --reload --port 8000

# Terminal 2 — frontend
cd frontend
npm install
npm run dev
```

Open the Vite URL, choose `configs/cisco/noncompliant.conf`, and run:

```text
Analyze → CTRL-001 FAIL → Evidence → View remediation → Simulate → PASS → Generate PDF
```

Then choose `configs/astranet/unknown-pattern.conf` and run:

```text
Analyze → UNKNOWN → Generate suggestion → Human approve → Mapping v1 → Re-analyze → Recognized → Generate PDF
```

Reset local demo records without changing the schema:

```bash
curl -X POST http://127.0.0.1:8000/api/demo/reset
```

The reset route is development/demo-only and is disabled when `APP_ENV` is
`production`. To seed the two reproducible walkthroughs (including a Cisco
simulation and AstraNet mapping/re-analysis), run from the repository root:

```bash
python -m backend.scripts.seed_demo
```

The seed uses the checked-in synthetic files and prints the generated IDs for
the current local run. It does not create production statistics or contact
devices.
