# Multi-Framework Compliance Foundation

**Problem Statement:** PS 26155 — AI-Driven Multi-Vendor Network Security Compliance Auditor  
**Organization:** NTRO | **Team:** CYBER MARVERICKS  
**Branch:** `sih-final-submission`

---

## Core Invariant

> **AI proposes → deterministic engine validates → evidence proves.**

1. **Deterministic Compliance Authority:** Compliance decisions (`PASS`, `FAIL`, `UNKNOWN`, `NOT_APPLICABLE`) are computed strictly and exclusively by the deterministic YAML-driven control engine (`DeterministicControlEngine`) against normalized Security IR properties.
2. **Advisory Framework Cross-References:** Security framework metadata (CIS, NIST, DISA STIG, ISO) serves solely as informational cross-referencing and traceability context. Framework metadata **never** participates in compliance evaluation calculation, threshold adjustments, or AI decision logic.
3. **No AI Compliance Authority:** Generative AI is used strictly for suggesting syntactic/semantic parser mappings for unknown patterns during the human-in-the-loop review queue. AI **never** decides whether a device passes or fails a security control.

---

## Supported Frameworks Registry

The system provides a framework registry accessible via `GET /api/frameworks`:

| Framework ID | Standard / Display Name | Target Version | Status | Authoritative Scope |
|---|---|---|---|---|
| `CIS` | CIS Critical Security Controls | `v8` | `SUPPORTED` (Verified) | Prescriptive, prioritized cybersecurity best practices (Controls 4, 5, 8). |
| `NIST_SP_800_53` | NIST SP 800-53 | `Rev. 5` | `SUPPORTED` (Verified) | Security and Privacy Controls for Information Systems and Organizations (AC, AU, IA, SC families). |
| `DISA_STIG` | DISA Security Technical Implementation Guides | `Network Device STIG` | `PROTOTYPE` (Explicit Prototype/Internal) | DoD security requirements for network infrastructure devices. Cross-references are explicitly labeled as prototype/internal mappings. |
| `ISO_27001` | ISO/IEC 27001 | `2022` | `SUPPORTED` (Verified) | Annex A Information Security Controls (A.5.17, A.8.15, A.8.17, A.8.20). |

---

## Authoritative vs. Prototype Mapping Guidelines

To prevent misleading claims or fabricated compliance assurances, every mapping carries an explicit `mapping_status`:

- **`VERIFIED`**: An authoritative, semantically accurate mapping directly verified against the published standard text.
- **`PROTOTYPE`**: An explicit prototype/internal cross-reference used when an authoritative equivalence cannot be guaranteed without deep site-specific tailoring. Clearly marked as `PROTOTYPE` in API payloads, PDF reports, and the UI.
- **`INTERNAL`**: An organization-specific internal control cross-reference.

### Shipped Control Mappings

| Control ID | Control Name | Severity | CIS Controls v8 | NIST SP 800-53 Rev 5 | DISA STIG (Prototype) | ISO/IEC 27001:2022 |
|---|---|---|---|---|---|---|
| **CTRL-001** | Secure management transport | HIGH | `4.2` (Verified) | `AC-17`, `SC-8` (Verified) | `STIG-NET-MGT-001-PROTO` (Prototype) | `A.8.20` (Verified) |
| **CTRL-002** | Audit logging enabled | MEDIUM | `8.2` (Verified) | `AU-12` (Verified) | `STIG-NET-AUDIT-001-PROTO` (Prototype) | `A.8.15` (Verified) |
| **CTRL-003** | Secret protection enabled | HIGH | `5.2` (Verified) | `IA-5` (Verified) | `STIG-NET-CRED-001-PROTO` (Prototype) | `A.5.17` (Verified) *(Note: A.5.17 Authentication info, not A.8.24)* |
| **CTRL-004** | Time synchronization configured | MEDIUM | `8.4` (Verified) | `AU-8` (Verified) | `STIG-NET-TIME-001-PROTO` (Prototype) | `A.8.17` (Verified) |
| **CTRL-005** | SSH management enabled *(diagnostic)* | HIGH | `4.2` (Verified) | `AC-17` (Verified) | `STIG-NET-SSH-001-PROTO` (Prototype) | `A.8.20` (Verified) |
| **CTRL-006** | Telnet management disabled *(diagnostic)* | HIGH | `4.2` (Verified) | `SC-8` (Verified) | `STIG-NET-TELNET-001-PROTO` (Prototype) | `A.8.20` (Verified) |

---

## Architectural Propagation

1. **Domain Models (`schemas.py`):**
   - `FrameworkMapping`: carries `framework_name`, `framework_version`, `reference_id`, `title`, `description`, and `mapping_status`.
   - `ControlEvaluationResult`: populated with `severity`, `category`, and `framework_mappings` from `ControlDefinition`. Custom equality operator preserves evaluation result comparisons.
   - `ControlResultSummary`: exposes metadata in all analysis, re-analysis, and simulation responses.
2. **Engine (`control_engine.py`):**
   - Propagates metadata transparently across all outcomes (`PASS`, `FAIL`, `UNKNOWN`, `NOT_APPLICABLE`).
   - Ensures deterministic evaluation algorithm is 100% isolated from metadata.
3. **Services (`analysis_service.py`, `reanalyze.py`, `remediation.py`):**
   - Preserves metadata throughout the entire analysis lifecycle, including adaptive re-analysis and simulation.
4. **PDF Reporting (`report_service.py`):**
   - Control Results table includes dedicated `Severity` column.
   - Distinct "Framework Cross-References (Advisory)" section details cross-references, versions, references, and verification status with an explicit disclaimer.
5. **Frontend UI (`AnalyzeConfigurationPage.tsx`, `analyze.ts`, `framework-parsers.ts`):**
   - Results table displays `Severity` chips and `Frameworks` badges.
   - Prominent disclaimer banner explains deterministic compliance vs. advisory framework mappings.
   - Evidence detail modal displays severity and category chips alongside a structured Framework Cross-References table.
   - Backward-compatible parsing falls back safely to `null` severity and `[]` framework mappings.
