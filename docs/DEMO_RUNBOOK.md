# PS 26155 Emergency Demo Runbook

This runbook is for the internal hackathon MVP. All configuration files are
checked-in DEMO / SYNTHETIC DATA. No production device is contacted or
modified.

## Start clean

Start the backend and frontend using the commands in the README, then reset
the local SQLite records:

```bash
curl -X POST http://127.0.0.1:8000/api/demo/reset
```

The reset preserves the database schema and is disabled when `APP_ENV=production`.

For a reproducible prepared state instead:

```bash
python -m backend.scripts.seed_demo
```

## Demo A — compliance and simulation

1. Open **Analyze Configuration**.
2. Select `configs/cisco/noncompliant.conf`.
3. Analyze and open the `CTRL-001` FAIL evidence.
4. View the deterministic remediation recommendation.
5. Select **Simulate Remediation**.
6. Confirm `FAIL → PASS`, fresh simulated evidence, and `SIMULATION ONLY`.
7. Generate the PDF report.

The stored original analysis remains FAIL; the simulation is a separate copy-only
re-audit result.

## Demo B — adaptive mapping

1. Select `configs/astranet/unknown-pattern.conf`.
2. Analyze and show `guard-channel lattice-secure` as UNKNOWN.
3. Generate the local candidate suggestion.
4. Review and explicitly approve it.
5. Confirm `Mapping v1 · APPROVED · ACTIVE`.
6. Select **Re-analyze** explicitly.
7. Show `RECOGNIZED VIA APPROVED MAPPING`, deterministic results, and evidence.
8. Generate the re-analysis PDF.

Approval does not alter the original analysis or trigger re-analysis automatically.

## Safety language

- AI-assisted candidate mappings require human approval.
- Compliance decisions come from the deterministic engine.
- UNKNOWN is not FAIL.
- Remediation is simulation-only.
- AstraNet is fictional/synthetic demonstration data.
