# PS 26155 Evidence-Backed PDF Audit Reporting

## Overview

The audit reporting subsystem provides a single, comprehensive, evidence-backed PDF report per analyzed network device. The report synthesizes deterministic compliance results, device identification, multi-framework traceability, source-backed evidence excerpts, adaptive-learning lineage, remediation simulation outcomes, and cryptographic audit ledger records.

### Core Architectural Invariants

- **AI proposes → human reviews → approved knowledge is versioned → deterministic engine validates → evidence proves.**
- **Compliance determinations are produced by the deterministic control engine. Framework mappings provide advisory traceability.**
- **Remediation guidance is simulation-only and does not modify production devices.**
- **The PDF report is a strictly read-only artifact.** Generating an audit report never mutates stored database analyses, does not recalculate compliance independently, and never connects to live network infrastructure.

---

## Data Flow & Generation Lifecycle

```text
Uploaded Configuration (CLI / Batch)
   │
   ▼
Parser & Feature Extraction (Vendor / Platform / Device Identity)
   │
   ▼
Deterministic Control Engine (YAML Rules / Security IR)
   │
   ▼
Stored Immutable Analysis (PASS / FAIL / UNKNOWN / NOT_APPLICABLE)
   │
   ├─► Optional: Adaptive Mapping & Re-analysis (Lineage Chain)
   ├─► Optional: Simulation Engine (Simulated Remediation Diff)
   │
   ▼
Report Service (`build_analysis_pdf`)
   │
   ├─► Cryptographic SHA-256 Analysis Hash Verification
   ├─► Ledger Hash-Chain Registration (`REPORT` Artifact Type)
   │
   ▼
Read-Only Single PDF per Device
```

---

## Report Structure (10 Standardized Sections)

The hardened PDF report is formatted on A4 paper using a strict 495 pt grid layout to prevent text clipping, overlapping columns, and horizontal overflow:

### Section 1: Executive Summary & Device Identification
- **Device Identity Metadata**: Report ID, Analysis ID, Device ID (where supported), Hostname, Vendor, Platform, OS / Firmware Version, Hardware Model, Serial Number, Configuration Filename, Assessment Timestamp, Evaluation Basis (`Deterministic YAML Engine`), Framework Context, Ledger Record, and Report Version.
- **Accurate Identity Extraction**: When hardware model or serial number is absent from the configuration, the system explicitly preserves `null` internally and renders `"Not present in configuration"`. Values are never inferred, guessed, or fabricated.
- **Compliance Results Summary Table**: Quantitative breakdown of deterministic control outcomes across `PASS`, `FAIL`, `UNKNOWN`, and `NOT_APPLICABLE`.
- **Severity Distribution Table**: Categorized count of findings across `CRITICAL`, `HIGH`, `MEDIUM`, and `LOW`.

### Section 2: Control Results Table
- Tabular display of all evaluated controls: Control ID, Control Name, Category, Severity, Result (`PASS`, `FAIL`, `UNKNOWN`, `NOT_APPLICABLE`), and Framework Cross-References (e.g., CIS Controls v8, NIST SP 800-53 r5, DISA STIG, ISO/IEC 27001:2022).

### Section 3: Multi-Framework Cross-References (Advisory)
- Detailed mapping breakdown per control against four primary industry security frameworks:
  - **CIS Controls v8**
  - **NIST SP 800-53 Revision 5**
  - **DISA STIG**
  - **ISO/IEC 27001:2022**
- Displays verification state (`VERIFIED` vs `PROTOTYPE`).
- Includes prominent advisory notice: *"Compliance determinations are produced by the deterministic control engine. Framework mappings provide advisory traceability."*

### Section 4: Evidence Details & Source Provenance
- Complete provenance for every evaluated control:
  - Line numbers and line ranges (`line 12 - 18`).
  - Normalized IR property names and extracted boolean/string values.
  - Verbatim raw configuration excerpt from the uploaded device file.
  - Evidence source type:
    - `CONFIGURATION`: Extracted directly from uploaded device configuration.
    - `APPROVED_MAPPING`: Synthesized via human-approved adaptive learning mapping.
    - `SIMULATED_REMEDIATION`: Generated within a sandboxed simulation session.

### Section 5: Analysis Lineage
- Audit traceability establishing whether the analysis is an original assessment or an approved-mapping child re-analysis.
- Records Parent Analysis ID, Current Analysis ID, Re-analysis flag (`YES` / `NO`), Applied Mapping ID, and Applied Mapping Version.

### Section 6: Adaptive Mapping (Applicable Child Re-analyses)
- Rendered when an analysis was re-evaluated following human approval of unrecognized vendor syntax (e.g., AstraNet adaptive workflow).
- Documents: Unrecognized Syntax, Pattern ID, Mapping ID, Version, Status (`Human approved`), Human Review Action (`APPROVED` / `CORRECTED`), Reviewer Attribution (email/role), Recognized State (`RECOGNIZED_VIA_APPROVED_MAPPING`), and the full approved target IR property dictionary.

### Section 7: Device-Specific Step-by-Step CLI Remediation Guidance (Simulation Only)
- Vendor- and platform-specific CLI remediation for non-compliant controls (Cisco IOS/IOS-XE, FortiGate FortiOS, Palo Alto PAN-OS):
  - Problem statement & technical rationale.
  - Applicability and firmware version constraints.
  - Risk assessment (`LOW`, `MEDIUM`, `HIGH`).
  - Numbered step-by-step CLI command sequence.
  - Parameter placeholders guide (`<management-interface>`, `<password>`, `<server-ip>`).
- Includes prominent safety disclaimer: *"Remediation guidance is simulation-only and does not modify production devices."*

### Section 8: Remediation Simulation Execution Results (When Present)
- Rendered when a safe dry-run remediation simulation has been performed on the analysis:
  - Simulation ID, Parent Analysis ID, Remediation ID, Target Control ID, Vendor/Platform.
  - Before/After control compliance state change.
  - Simulated IR property delta.
  - Simulation evidence provenance.
  - Confirmation that no live network communication or device configuration changes occurred.

### Section 9: Cryptographic Integrity Ledger Audit
- Verifiable cryptographic linkage binding the report to the tamper-evident SHA-256 hash-chain ledger:
  - Artifact Type: `REPORT`
  - Report ID and Target Analysis ID
  - Target Analysis Content SHA-256
  - Report Ledger Record ID and Record Hash
  - Preceding Ledger Record Hash (hash chaining)
  - Chain Verification Status: `VALID`
  - Verification Engine: Internal cryptographic ledger

### Section 10: Regulatory Disclaimers & Governance Notice
- Formal statement of evaluation scope, boundaries, and safety:
  - `Deterministic Control Engine`: All evaluations are grounded in immutable YAML rules and extracted facts.
  - `Advisory Traceability`: Framework alignments do not alter deterministic logic.
  - `Simulation Boundary`: Zero live SSH, Telnet, NETCONF, or REST API connections to physical or virtual appliances.
  - `Prototype Notice`: Designed for NTRO PS 26155 evaluation.

---

## API Reference

### Download Audit Report PDF

```http
GET /api/reports/{analysis_id}/pdf
```

- **Authentication**: Bearer Token (`ADMIN`, `AUDITOR`, `REVIEWER`).
- **Response Headers**:
  - `Content-Type: application/pdf`
  - `Content-Disposition: attachment; filename="audit-report-{device_id|analysis_id}.pdf"`
- **Response Body**: Binary PDF stream.
- **Side Effects**: Registers a read-only `REPORT` artifact in the cryptographic integrity ledger; does not mutate the target analysis.

---

## Frontend Integration

The unified analysis interface provides a direct action:

- **Button Label**: `Download Individual Device Audit Report (PDF)`
- **Helper Description**: *"Comprehensive audit report covering device identification, deterministic pass/fail results, severity, multi-framework traceability, line evidence, CLI remediation (simulation-only), and cryptographic ledger verification."*
- **Execution**: Triggers browser download of backend-rendered PDF without client-side DOM capture or loss of cryptographic integrity.
