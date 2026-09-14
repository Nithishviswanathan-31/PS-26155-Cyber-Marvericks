# Demo configurations

These files are synthetic demonstration configurations for the emergency MVP.
They are not customer exports.

- `cisco/` contains compliant, non-compliant, and incomplete Cisco IOS/IOS-XE fixtures.
- `fortigate/` contains compliant, non-compliant, and incomplete FortiGate/FortiOS fixtures.
- `paloalto/` contains compliant, non-compliant, and incomplete Palo Alto/PAN-OS fixtures.
- `astranet/unknown-pattern.conf` is fictional/synthetic data for the UNKNOWN
  pattern and approved-mapping demonstration.

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
| `paloalto/unknown.conf` | Palo Alto/PAN-OS | Insufficient evidence case | Missing properties remain UNKNOWN |
| `astranet/unknown-pattern.conf` | AstraNet (fictional) | Adaptive-learning demo | UNKNOWN until an approved mapping is explicitly re-analyzed |
