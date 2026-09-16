# Presentation Talking Points

## One-sentence explanation

The project is an evidence-first, multi-vendor network security compliance auditor: vendor configurations become a normalized Security IR, deterministic controls produce compliance results, and AI-assisted unknown interpretation remains subject to human approval and explicit re-analysis.

## Core trust model

- Security IR preserves parser provenance for every supported normalized property.
- Deterministic controls produce PASS, FAIL, or UNKNOWN; UNKNOWN is not FAIL.
- AI proposals are not compliance evidence and do not directly create a result.
- Human-approved mappings create versioned knowledge; re-analysis remains explicit.
- Remediation is simulation-only; no production device is contacted or modified.

## Tamper-evident local audit ledger

The V2 prototype implements a **tamper-evident local audit ledger**: an append-only SHA-256 hash chain over canonical artifact records. It covers configurations, analyses, evidence, mapping versions, interpretation proposals, remediation simulations, and report metadata. The application supports artifact and chain verification and links analysis/report integrity metadata to audit lineage.

This is not a public blockchain, distributed blockchain, consensus network, or public-chain finality system. A future distributed/public blockchain backend may be introduced behind the existing ledger abstraction.

## Judge answers

**Where is AI used?** Candidate semantic interpretation and explanation assistance for unknown patterns. It never independently sets PASS, FAIL, certification, or authoritative compliance.

**Why human approval?** Approval prevents a candidate interpretation becoming knowledge without review. Approved mapping plus explicit re-analysis is still required before deterministic evaluation.

**Can remediation affect a real router?** No. Simulation transforms a copy of Security IR only. No device-write path exists.

**Which vendors and controls are implemented?** Cisco IOS/IOS-XE, FortiGate/FortiOS, Palo Alto/PAN-OS, and synthetic AstraNet are supported within a focused deterministic control catalogue. The prototype does not claim broad certification-framework coverage.

**Is it production-ready?** No. It is an offline, file-based prototype using SQLite, local demo data, and demo authentication. Enterprise identity, external LLM integration, public blockchain, cloud deployment, and real device remediation are future work.

## Demo flow

1. Upload a Cisco configuration and inspect deterministic results and evidence.
2. Show a simulation-only remediation preview, then explicit deterministic re-analysis.
3. Show AstraNet UNKNOWN, AI proposal, human approval, versioned mapping, and re-analysis.
4. Show PDF report and integrity verification.

## Closing

AI helps the system understand unknown configuration patterns, but deterministic control evaluation and evidence remain authoritative for compliance.
