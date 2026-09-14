# Presentation Talking Points

## One-sentence explanation

We built an AI-assisted multi-vendor network security compliance auditor that converts heterogeneous device configurations into a vendor-neutral Security IR, uses deterministic controls to evaluate compliance, learns unknown vendor patterns through human-approved mappings, and provides evidence, simulation-only remediation, re-audit, and reporting.

## Core story

Problem → heterogeneous vendor configurations → common Security IR → deterministic compliance → evidence → adaptive learning → human approval → re-analysis → safe remediation simulation → auditable report.

### Problem — 30 seconds

Different network vendors express equivalent security settings differently. Vendor-specific scanners are difficult to extend, unfamiliar patterns can be misinterpreted, and an audit result without traceable evidence is difficult to trust. Our MVP addresses this with a common representation, deterministic checks, and safe simulation.

### Security IR — 30 seconds

Each focused parser translates vendor syntax into common properties such as secure management, logging, password protection, and NTP. Provenance stays attached to each property, so a finding can be traced back to a file, line, and raw excerpt.

### Deterministic compliance — 30 seconds

The engine evaluates explicit YAML control conditions. It produces PASS, FAIL, or UNKNOWN from the available Security IR. Missing evidence remains UNKNOWN; UNKNOWN is not FAIL.

### AI and adaptive learning — 45 seconds

AI assistance is limited to candidate semantic interpretation. For the synthetic AstraNet pattern, the system first shows UNKNOWN. A candidate mapping is schema-validated, reviewed by a human, and stored as version 1 only after approval. Explicit re-analysis then enriches a copy of the IR and reruns deterministic controls. Foundation-model retraining is not claimed.

### Evidence — 30 seconds

Evidence includes control, property, expected and actual values, result, source location, raw excerpt, explanation, and evidence source. Configuration evidence, approved-mapping evidence, and simulated-remediation evidence remain distinct.

### Remediation — 30 seconds

The prototype never writes to a device. It recommends controlled remediation, transforms only a copy of the IR, performs a deterministic re-audit, and shows before/after results. The safety boundary is simulation-only.

### Current scope — 20 seconds

The MVP supports Cisco IOS/IOS-XE, FortiGate/FortiOS, Palo Alto/PAN-OS, and fictional AstraNet. It demonstrates four deeply validated controls rather than claiming broad framework coverage.

## Judge answers

**Where is AI used?** Semantic interpretation, candidate mapping suggestions, unknown-pattern interpretation, and explanation assistance. It never independently sets PASS, FAIL, certification, or authoritative compliance.

**What is your AI accuracy?** We do not claim a trained-model accuracy metric for the synthetic demonstration adapter. Its confidence is only a candidate-suggestion signal. A labeled multi-vendor dataset would be required for a meaningful benchmark.

**Why human approval?** It prevents an uncertain interpretation from silently becoming compliance knowledge. Approval creates versioned knowledge; it does not directly create PASS or FAIL.

**How do you prevent hallucination?** Schema validation, supported-property allowlists, provenance, human approval, deterministic controls, and UNKNOWN when evidence is insufficient.

**Why not one parser for all vendors?** Vendor syntax and semantics differ. Modular parsers normalize into one common IR, allowing the control engine to remain vendor-neutral.

**How is Security IR different?** It separates vendor-specific syntax from normalized security meaning and preserves provenance at the property level.

**Why does UNKNOWN exist?** Lack of evidence is not proof of insecurity. UNKNOWN prevents unsupported PASS/FAIL claims.

**Can an approved mapping change an old report?** No. Re-analysis creates a new child analysis; historical analyses and mapping versions remain immutable.

**What happens when v2 replaces v1?** v1 becomes inactive but remains stored. New re-analysis uses active v2; earlier results continue to record v1.

**Can remediation affect a real router?** No. There is no device-write path. Only a copied Security IR is transformed.

**Which frameworks are supported?** The MVP implements a small deterministic control catalogue informed by the project’s references. It does not claim full CIS, NIST, STIG, or ISO certification mapping.

**Why only four controls?** We prioritized a deeply validated vertical slice covering the complete lifecycle over many shallow controls.

**Does it use blockchain?** Blockchain is part of the broader SIH theme, but this MVP does not implement a blockchain ledger. SQLite is local demo storage.

**Is it production-ready?** No. It is an offline, file-based prototype using local SQLite, synthetic/demo data, and no production-device write path.

**What would you build next?** Broader validated controls, larger labeled evaluation data, production-grade storage/deployment, and further vendor/version coverage—without changing the trust boundary.

## Three-minute demo

- `0:00–0:30` Problem and architecture.
- `0:30–1:15` Cisco FAIL → evidence → simulation → PASS.
- `1:15–2:30` AstraNet UNKNOWN → suggestion → approval → mapping v1 → re-analysis → recognized.
- `2:30–3:00` PDF, evidence, and trust model.

Closing: “Our key idea is simple: AI can help the system understand unknown configurations, but compliance is decided deterministically and every result is tied to evidence.”

## Five-minute demo

`0:00–0:45` problem · `0:45–1:30` architecture · `1:30–2:45` Cisco/evidence · `2:45–3:30` simulation · `3:30–4:40` AstraNet · `4:40–5:00` PDF and conclusion.

## Presenter assignments

| Presenter | Responsibility |
| --- | --- |
| NITHISH V | Opening, problem, project overview |
| NAVEEN S | Solution, Security IR, deterministic engine |
| GOPIKA K | Technical architecture, AI, adaptive mapping |
| THICHANA K | Feasibility, safety, remediation simulation |
| DHARSHINI R | Impact, benefits, demo outcome |
| PRIYA DHARSHINI D | Evidence, reporting, closing |

## Fifteen-second closing

CYBER MARVERICKS built an evidence-first, multi-vendor security compliance auditor where AI assists with unknown configuration interpretation, humans approve new mappings, deterministic controls make the compliance decision, and remediation is safely simulated rather than pushed to production.
