# PS 26155 — AI-Driven Multi-Vendor Network Security Compliance Auditor

**SIH 2026** · **Team CYBER MARVERICKS**
**Team Leader:** NITHISH V · **Mentor:** PAVITHARA K

## Overview

Network-device configurations differ by vendor and platform, which makes manual compliance reviews slow, difficult to reproduce, and inconsistent in their evidence. Unfamiliar syntax makes the problem harder: an auditor must avoid treating an unrecognised pattern as compliant simply because it appears similar to a known setting.

This V2 prototype audits multi-vendor network configurations through vendor-specific parsing, a vendor-neutral Security IR, deterministic controls, evidence-first results, controlled AI-assisted interpretation of unknown patterns, human-reviewed adaptive knowledge, explicit re-analysis, reporting, and integrity verification.

> **AI proposes → deterministic engine validates → evidence proves.**

## Current V2 capabilities

### Deterministic audit platform

- Focused parsers for Cisco IOS / IOS-XE, FortiGate / FortiOS, and Palo Alto / PAN-OS.
- A synthetic AstraNet workflow for demonstrating safe handling of unfamiliar configuration patterns.
- Vendor-neutral Security IR with typed normalized properties and parser provenance.
- Deterministic `PASS`, `FAIL`, and `UNKNOWN` control evaluation with evidence records containing actual value, expected value, source, source location, and provenance.
- A YAML-backed control catalogue. `CTRL-005` and `CTRL-006` are diagnostics of `CTRL-001`, and are not counted as independent security coverage.
- Persistent Device and Configuration domains, SHA-256 configuration fingerprints, duplicate detection, and durable analysis history.
- Single-file and bounded bulk/batch analysis with per-item results and batch history.

### Unknown-pattern interpretation and adaptive knowledge

- Controlled, offline/demo AI interpretation proposals with confidence-gated human review.
- Explicit approve, correct, and reject actions; an AI proposal never establishes compliance.
- Versioned mappings, mapping approvals, conflict-aware adaptive knowledge entries, and audit history.
- Exact identity-safe knowledge reuse only across vendor, pattern signature, normalized context, and target property.
- Explicit mapping-aware re-analysis that creates a new analysis; the stored original remains unchanged.

### Auditor workflow and product experience

- Persistent auditor console with dashboard, Devices, Configurations, Analyses, Findings, Batches, Knowledge Review, Integrity, and Users views.
- Device, configuration, analysis, batch, finding, mapping, knowledge, and report history with backend pagination and filtering.
- Evidence, source provenance, AI proposal state, mapping/re-analysis lineage, remediation simulation information, and PDF report access in analysis detail.
- PDF reporting with report ID, version/history metadata, generating actor, stored lineage, and integrity references.

### Security, remediation, and integrity

- Local authentication with `ADMIN`, `AUDITOR`, and `REVIEWER` roles, enforced server-side.
- Expiring signed bearer sessions, revocation, salted PBKDF2-SHA256 password hashing, login throttling, and server-derived actor identity for auditable mutations.
- Deterministic, parser-backed remediation **simulation** for `CTRL-001` through `CTRL-004` where supported by Cisco, FortiGate, and Palo Alto parser properties.
- SHA-256 artifact integrity records and a **TAMPER-EVIDENT LOCAL AUDIT LEDGER** with deterministic canonicalization, append-only previous-hash linkage, and explicit verification.

## Architecture

### Deterministic audit path

```text
Configuration
    ↓
Vendor Detection
    ↓
Vendor Parser
    ↓
Vendor-Neutral Security IR
    ↓
Deterministic Control Engine
    ↓
PASS / FAIL / UNKNOWN
    ↓
Evidence and Provenance
    ↓
Report / Integrity Record / Audit Ledger
```

### Unknown-pattern path

```text
UNKNOWN
    ↓
AI Interpretation Provider
    ↓
Confidence Gate
    ↓
Human Review
    ↓
Approved Versioned Mapping
    ↓
Adaptive Knowledge
    ↓
Explicit Re-analysis
    ↓
Security IR
    ↓
Deterministic Compliance and Evidence
```

AI may inform a reviewer, but it does not independently establish a `PASS` or `FAIL`. Knowledge reuse also cannot directly create a compliance result. Only an approved mapping followed by explicit re-analysis and deterministic evaluation can do so.

## Remediation is simulation-only

The prototype provides deterministic remediation capability discovery and simulations for the following parser-backed controls:

| Control | Capability |
| --- | --- |
| `CTRL-001` | Secure management transport: SSH enabled and Telnet disabled |
| `CTRL-002` | Audit logging enabled |
| `CTRL-003` | Secret / credential protection enabled |
| `CTRL-004` | Time synchronization configured |

Supported Cisco IOS / IOS-XE, FortiGate / FortiOS, and Palo Alto / PAN-OS combinations operate on a deep copy of the stored Security IR. Each simulation records the remediation ID, control, vendor, actor, timestamp, original configuration fingerprint, before/after state, evidence provenance, and integrity linkage. Unsupported vendor/control combinations return `UNSUPPORTED_REMEDIATION`; AstraNet remediation is not implemented.

> **SIMULATION ONLY — NO DEVICE WAS MODIFIED.**

The backend does not connect to network devices, execute CLI commands, call device APIs, SSH, or Telnet. A simulation has `compliance_final: false`; only explicit re-analysis of the simulated copy produces a deterministic simulated compliance result. The original configuration and analysis remain unchanged.

## Integrity and future blockchain boundary

The current mechanism is a **TAMPER-EVIDENT LOCAL AUDIT LEDGER**, not a public or distributed blockchain.

- Important configuration, analysis, evidence, mapping-version, AI-proposal, remediation-simulation, and report artifacts receive SHA-256 integrity records.
- Canonical artifact JSON uses UTF-8, sorted keys, compact separators, and preserved array order so whitespace and JSON key order do not alter a logical hash.
- Each append-only ledger record binds immutable record content to the prior record hash, allowing verification to detect altered artifacts, altered hashes, broken links, missing records, and truncation.
- Configuration records retain the existing SHA-256 content fingerprint. Analysis verification reads stored snapshots; it does not re-run the compliance engine.
- Reports link their generated report ID and metadata to integrity records and the analysis lineage.

`IntegrityLedger` and `LocalHashChainLedger` form an abstraction boundary for a future anchored or distributed ledger backend. The local ledger does not provide public-chain finality, distributed consensus, encryption, or independent external timestamping. See [Evidence integrity ledger](docs/EVIDENCE_INTEGRITY_LEDGER.md).

## Authentication and RBAC

Authentication is local/offline and enforced by the backend; hiding a frontend control is never the authorization mechanism.

| Role | Main permissions |
| --- | --- |
| `ADMIN` | Audit access, user administration, and local demo administration |
| `AUDITOR` | Upload configurations, run batch analysis and remediation simulations, view audit data and reports, and explicitly re-analyze approved mappings |
| `REVIEWER` | View audit data and evidence, generate/review interpretations, approve/correct/reject mappings, manage knowledge state, and inspect mapping/knowledge history |

The service uses HMAC-signed bearer tokens with expiry and session IDs. Logout and user role/password/enabled-state changes revoke sessions. Passwords are stored only as salted PBKDF2-HMAC-SHA256 hashes. For new sensitive actions, the server derives actor identity and role from the authenticated session; request-body reviewer or user identifiers cannot impersonate another user.

`AUTH_REQUIRED=false` preserves the offline development workflow and is not a secured deployment. `AUTH_REQUIRED=true` requires a configured signing secret and authenticated user. Enterprise SSO, MFA, password recovery, and multi-tenant authorization are not implemented. See [Authentication and RBAC](docs/AUTHENTICATION_RBAC.md).

## Technology stack

| Area | Technology |
| --- | --- |
| Backend | Python, FastAPI, Pydantic, SQLite, PyYAML, Uvicorn |
| Reporting | ReportLab and pypdf |
| Frontend | React, TypeScript, Vite, Material UI |
| Controls | Validated YAML control catalogue |
| Integrity | SHA-256 canonical artifact hashes and local hash-chain ledger |

## Repository structure

```text
backend/                 FastAPI application, domain models, services, storage, APIs, and tests
backend/tests/           Backend unit, integration, security, integrity, reporting, and regression tests
frontend/                React/TypeScript/MUI auditor console
controls/                Validated deterministic YAML control catalogue
configs/                 Synthetic vendor fixtures and Security IR examples
docs/                    Architecture, workflow, security, remediation, reporting, and integrity documentation
```

## Local setup (Windows PowerShell)

### Backend

From the repository root:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r backend\requirements.txt
$env:PYTHONPATH = "backend"
python -m uvicorn app.main:app --app-dir backend --reload --port 8000
```

In another PowerShell window, confirm the service is running:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/health
```

### Frontend

```powershell
Set-Location frontend
npm install
npm run dev
```

Open the local Vite URL shown by the terminal, normally `http://localhost:5173`.

### Secured local demo users

Authentication is optional only for the local offline workflow. For a secured local demo, set environment values before starting the backend. Do not put real values in tracked files.

```powershell
$env:AUTH_REQUIRED = "true"
$env:AUTH_SECRET = "replace-with-a-local-random-secret-of-at-least-32-bytes"
$env:DEMO_ADMIN_PASSWORD = "replace-with-a-local-12-or-more-character-password"
$env:DEMO_AUDITOR_PASSWORD = "replace-with-a-local-12-or-more-character-password"
$env:DEMO_REVIEWER_PASSWORD = "replace-with-a-local-12-or-more-character-password"
$env:PYTHONPATH = "backend"
python -m app.seed_users
```

Seeding is explicit, local-only, idempotent, and disabled in production. It creates configured demo users only when their passwords are supplied; no default credentials or signing secret ship with the repository. See [Authentication and RBAC](docs/AUTHENTICATION_RBAC.md) for environment details and the permission matrix.

### Tests and frontend validation

```powershell
# From the repository root, with the virtual environment active
$env:PYTHONPATH = "backend"
python -m pytest backend\tests -q -p no:cacheprovider

# From frontend/
npm run build
node --test tests/auth-http.test.mjs
```

## Authenticated demo workflows

1. **Standard audit:** sign in, upload a Cisco, FortiGate, or Palo Alto configuration, inspect extracted device metadata, deterministic controls, multi-framework compliance mappings (CIS Controls v8, NIST SP 800-53 r5, DISA STIG, ISO/IEC 27001:2022), and source evidence, then generate an evidence-backed PDF report and verify integrity.
2. **Remediation simulation:** begin with a non-compliant configuration, inspect evidence, review device-specific step-by-step CLI remediation guidance, simulate a supported remediation, review before/after state, explicitly re-analyze the simulation, and inspect the deterministic result.
3. **Unknown / AI:** upload the synthetic AstraNet unknown-pattern fixture, retain `UNKNOWN`, generate an interpretation proposal, have a reviewer approve a mapping, then explicitly re-analyze to produce deterministic evidence and an adaptive knowledge record.
4. **Bulk fleet audit:** switch to the **Bulk Fleet Ingestion** dashboard, select up to 25 configuration files across multiple vendors (Cisco, FortiGate, Palo Alto, AstraNet), inspect fleet summary metrics and per-device compliance breakdowns, inspect any device directly, and export individual device PDF reports.
5. **RBAC:** use `ADMIN` for user administration, `AUDITOR` for audit workflows, and `REVIEWER` for interpretation, mapping, and knowledge review. Forbidden operations return `403` from the server.

## Validation status

The final V2 validation for the frozen implementation recorded:

- **Backend:** 420 passed, 0 failed, 0 skipped.
- **Frontend:** TypeScript validation passed, Vite production build passed, and frontend authentication tests passed.
- **Coverage:** authentication/RBAC, parsers, Security IR, deterministic controls, batch processing, interpretations, adaptive knowledge, mappings/re-analysis, remediation, integrity, PDF reporting, and auditor console workflows.

## Limits and safety boundaries

- AstraNet is a synthetic demo vendor for the unknown-pattern workflow; it has no remediation implementation.
- The interpretation provider is local/offline demo functionality. There is no external LLM integration or semantic embedding/vector search.
- Vendor parser and control coverage is focused; this is not a claim of complete production syntax or compliance-framework coverage.
- The local audit ledger is tamper-evident, not a public blockchain or a distributed-consensus system.
- Remediation is simulation-only. It never contacts or modifies a device.
- Authentication is local single-workspace RBAC; MFA, enterprise SSO, password recovery, and multi-tenant authorization are future work.
- Report metadata and lineage are persisted, while generated raw PDF binaries are not retained as long-term stored artifacts.
- Stored audit records retain normalized state and evidence/provenance rather than acting as a second repository for full raw uploaded configuration text.

## Future work

Possible future work includes independently reviewed wider parser/control coverage, production identity and tenant boundaries, secure deployment architecture, externally anchored ledger implementations, external AI providers with appropriate data controls, semantic retrieval, and separately authorized vendor configuration deployment workflows.

## Additional documentation

- [Control foundation](docs/CONTROL_FOUNDATION_V2_1.md)
- [Adaptive mapping workflow](docs/ADAPTIVE_MAPPING_WORKFLOW.md)
- [Remediation simulation](docs/REMEDIATION_SIMULATION.md)
- [PDF reporting](docs/PDF_REPORTING.md)
- [Evidence integrity ledger](docs/EVIDENCE_INTEGRITY_LEDGER.md)
- [Authentication and RBAC](docs/AUTHENTICATION_RBAC.md)
