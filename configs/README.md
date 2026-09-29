# Demo configurations

These files are synthetic demonstration configurations for the PS 26155 multi-vendor compliance auditor.
They are not customer exports and contain no sensitive or production infrastructure credentials.

- `cisco/` contains compliant, non-compliant, and incomplete Cisco IOS/IOS-XE fixtures.
- `fortigate/` contains compliant, non-compliant, and incomplete FortiGate/FortiOS fixtures.
- `paloalto/` contains compliant, non-compliant, mixed, and incomplete Palo Alto/PAN-OS fixtures.
- `astranet/unknown-pattern.conf` is fictional/synthetic data for the UNKNOWN
  pattern and approved-mapping demonstration.

## Synthetic Fixture Matrix

| Filename | Vendor | Purpose | Expected behavior |
| --- | --- | --- | --- |
| `cisco/compliant.conf` | Cisco IOS/IOS-XE | Known secure demo case | Supported controls are PASS |
| `cisco/noncompliant.conf` | Cisco IOS/IOS-XE | Primary remediation demo | CTRL-001 is FAIL; simulation can produce PASS |
| `cisco/unknown.conf` | Cisco IOS/IOS-XE | Insufficient evidence case | Missing properties remain UNKNOWN |
| `fortigate/compliant.conf` | FortiGate/FortiOS | Cross-vendor secure case | Supported controls are PASS |
| `fortigate/noncompliant.conf` | FortiGate/FortiOS | Cross-vendor failure case | Supported controls are FAIL |
| `fortigate/unknown.conf` | FortiGate/FortiOS | Insufficient evidence case | Missing properties remain UNKNOWN |
| `paloalto/compliant.conf` | Palo Alto/PAN-OS | Cross-vendor secure case | Supported controls are PASS |
| `paloalto/noncompliant.conf` | Palo Alto/PAN-OS | Cross-vendor failure case | Supported controls are FAIL |
| `paloalto/mixed.conf` | Palo Alto/PAN-OS | Realistic mixed compliance case | SSH & logging PASS; password policy FAIL; NTP UNKNOWN |
| `paloalto/unknown.conf` | Palo Alto/PAN-OS | Insufficient evidence case | Missing properties remain UNKNOWN |
| `astranet/unknown-pattern.conf` | AstraNet (fictional) | Adaptive-learning demo | UNKNOWN until an approved mapping is explicitly re-analyzed |

## Bulk Fleet Ingestion Testing

The auditor supports single-file or multi-file fleet ingestion (up to 25 files):
- **UI Bulk Ingestion**: Switch to the **Bulk Fleet Ingestion** tab in the audit interface, drag-and-drop or select multiple configuration files across any supported vendors, and click **Analyze Fleet**.
- **Automated Seeding**: Run `python backend/scripts/seed_demo.py` to reset the database and seed individual device analyses for Cisco, FortiGate, Palo Alto, and AstraNet, along with a 4-vendor fleet batch audit (`status: COMPLETED`).
- **Device-Level Reporting**: From the bulk results table, click **Inspect** to review deep evidence and remediation simulation, or click **PDF** to download an individual device compliance audit report.
