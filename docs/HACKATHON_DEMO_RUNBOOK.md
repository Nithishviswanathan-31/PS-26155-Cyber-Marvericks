# PS 26155 Hackathon Demo Runbook

Team: CYBER MARVERICKS · Problem Statement: PS 26155

## Demo A — Compliance and safe remediation

1. Start backend and frontend; open the application.
2. Select **Reset Demo** through `POST /api/demo/reset` or start clean.
3. Open **Analyze Configuration** and select `configs/cisco/noncompliant.conf`.
4. Click **Analyze Configuration**.
5. Show Cisco/device information and the four FAIL findings.
6. Open `CTRL-001` and show its configuration source line and raw excerpt.
7. Open the remediation recommendation.
8. Point out **SIMULATION ONLY**.
9. Click **Simulate Remediation**.
10. Show copied-state re-audit: `CTRL-001 FAIL → PASS`, fresh evidence, and the unchanged original analysis.
11. Click **Generate PDF Report** and show the report’s results, evidence, and simulation disclaimer.

Say explicitly: “The system does not change the real device. It creates a copy of the Security IR, applies the remediation transformation to that copy, and runs the deterministic control engine again.”

## Demo B — adaptive vendor learning

1. Reset the demo state.
2. Select `configs/astranet/unknown-pattern.conf` and analyze it.
3. Show `guard-channel lattice-secure` as **UNKNOWN**, including its source line.
4. Click **Generate candidate mapping**.
5. Show the proposed `management.ssh_enabled = true` and `management.telnet_enabled = false` mapping.
6. Explain that confidence is a demo suggestion value, not model accuracy.
7. Enter/review the human reviewer and click **Approve**.
8. Show **Mapping v1 · APPROVED · ACTIVE**.
9. Click **Re-analyze** explicitly.
10. Show **RECOGNIZED VIA APPROVED MAPPING**, deterministic results, and mapping evidence.
11. Generate the re-analysis PDF.

Say explicitly: “AI does not decide compliance. AI only proposes a candidate interpretation. Human approval activates the mapping, and the deterministic engine produces the compliance result.”

## Safety language

AI suggestions require human approval. Compliance results are deterministic.
Remediation is simulation-only. No production device is contacted or modified.
AstraNet is fictional/synthetic demonstration data.
