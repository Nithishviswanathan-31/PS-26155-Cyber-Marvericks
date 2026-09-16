# Safe Remediation Simulation

## Implemented deterministic capabilities

The V2 prototype supports parser-backed, Security IR-only simulations for Cisco IOS/IOS-XE, FortiGate/FortiOS, and Palo Alto/PAN-OS:

- `CTRL-001` secure management transport: SSH enabled and Telnet disabled.
- `CTRL-002` audit logging: logging enabled.
- `CTRL-003` credential protection: credential protection enabled.
- `CTRL-004` time synchronization: NTP enabled.

Each capability has a remediation ID, vendor/control identity, safety classification, deterministic transformation type, and simulation-only status. Unsupported vendor/control combinations, including AstraNet remediation, are unavailable rather than invented.

## Safety boundary

**SIMULATION ONLY - NO REAL DEVICE IS MODIFIED.** Every transformation applies to a deep copy of stored Security IR. Command text is display-only guidance; the backend has no SSH, Telnet, device API, Netmiko, Paramiko, firewall-write, or vendor-management write integration.

The original analysis remains unchanged. A simulation records its ID, original analysis, configuration fingerprint, vendor, authenticated actor, timestamp, before/after values, evidence provenance, and integrity linkage.

## Required deterministic workflow

```text
FAIL finding -> simulation preview -> explicit remediation re-analysis -> new deterministic analysis result and evidence
```

A simulation has `compliance_final: false`; it never creates a final PASS or FAIL. Only explicit re-analysis of the simulated copy produces the final deterministic simulated result.

## API

```http
GET  /api/remediation/capabilities
GET  /api/remediation/{analysis_id}
POST /api/remediation/{analysis_id}/simulate
POST /api/remediation/simulations/{simulation_id}/reanalyze
```

Simulation evidence is labelled `SIMULATED_REMEDIATION`; original source provenance remains available under `original_*` evidence fields.

## Demo-only limitations and future work

This offline prototype does not generate production configuration, connect to devices, or execute commands. AstraNet remediation is not implemented. Future work requires independently reviewed vendor-specific configuration generation and a separately authorized deployment workflow.
