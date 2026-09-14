# P0.12 Safe Remediation Simulation

P0.12 demonstrates a safe remediation loop for the emergency MVP:

```text
FAIL finding
  → deterministic remediation recommendation
  → explicit human simulation request
  → deep copy of Security IR
  → controlled property transformation
  → deterministic re-audit
  → fresh before/after result and evidence
```

## Safety boundary

Every remediation has `simulation_only: true`. The API accepts only a
remediation identifier and never accepts executable commands. The backend has
no SSH, Telnet, Netmiko, Paramiko, firewall-write, or vendor-management write
integration. Command strings are display-only guidance. No production device is
contacted or modified.

## Supported MVP recommendations

The current deterministic catalogue supports `CTRL-001 Secure management
transport` for:

- Cisco IOS/IOS-XE — `transport input ssh`
- FortiGate/FortiOS — reviewed `allowaccess` guidance with SSH and without Telnet
- Palo Alto/PAN-OS — reviewed interface-management-profile guidance with SSH and
  without Telnet

The transformation targets the common properties
`management.ssh_enabled = true` and `management.telnet_enabled = false`. Other
failed controls return no available remediation rather than invented commands.
AstraNet remediation is not implemented.

## API

```http
GET  /api/remediation/{analysis_id}
POST /api/remediation/{analysis_id}/simulate
```

The GET operation returns recommendations only for explicit FAIL findings. The
POST operation creates an independent `simulation_id`, stores the result in the
SQLite `simulation_results` table, and returns the original `before_result`,
deterministic `after_result`, simulated property changes, re-audit summaries,
and fresh evidence marked `SIMULATED_REMEDIATION`.

For simulated properties, original source file/line/raw excerpt values are
preserved under `original_*` evidence fields. The simulation does not fabricate
a source line for a value that was not present in the original configuration.

## Manual demo

```bash
curl -X POST \
  -F "file=@configs/cisco/noncompliant.conf" \
  http://127.0.0.1:8000/api/analyze
```

Use the returned `analysis_id` to list remediation, then POST the returned
`remediation_id` to `/api/remediation/{analysis_id}/simulate`.

The expected primary result is `FAIL → PASS` for CTRL-001, while the original
analysis remains `FAIL` and unchanged.
