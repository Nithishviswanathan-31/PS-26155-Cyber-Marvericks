# P0.8 FortiGate/FortiOS Parser

This is a focused MVP parser for synthetic FortiGate/FortiOS configuration
demonstrations. It is not complete FortiOS coverage.

## Input and detection

The parser accepts FortiOS text configuration exports. Detection is deliberately
small and returns `true` when the input contains a recognized FortiOS marker such
as `config system global`, `config system interface`, `config system ntp`, or a
`config log ...` section. The normalized vendor identifier is:

```text
fortigate_fortios
```

The parser does not attempt FortiOS release or product-family detection.

## Supported patterns

The following exact section/setting forms are supported:

| FortiOS configuration form | Security IR property | Semantics |
| --- | --- | --- |
| `config system interface` → `set allowaccess ... ssh` | `management.ssh_enabled` | `true` when SSH is explicitly listed |
| `config system interface` → `set allowaccess ... telnet` | `management.telnet_enabled` | `true` when Telnet is explicitly listed |
| `config log disk setting` → `set status enable/disable` | `logging.enabled` | Mirrors explicit local disk log status |
| `config system password-policy` → `set status enable/disable` | `password_protection.enabled` | Mirrors explicit administrator password-policy status |
| `config system ntp` → `set ntpsync enable/disable` | `time_sync.ntp_enabled` | Mirrors explicit system NTP synchronization status |

These forms are based on Fortinet’s documented CLI references for interface
administrative access, local disk logging, password policy, and system NTP:

- [FortiGate system administrator best practices](https://docs.fortinet.com/document/fortigate/6.4.0/hardening-your-fortigate/582009/system-administrator-best-practices)
- [FortiGate local disk logging CLI](https://docs.fortinet.com/document/fortigate/8.0.0/cli-reference/188501544/config-log-disk-setting)
- [FortiGate password-policy CLI](https://docs.fortinet.com/document/fortigate/8.0.0/cli-reference/127236326/config-system-password-policy)
- [FortiGate system NTP CLI](https://docs.fortinet.com/document/fortigate/8.0.0/cli-reference/105110478/config-system-ntp)

## Metadata

The parser extracts `hostname` from:

```text
config system global
    set hostname "example"
end
```

It extracts a version from the common configuration header form:

```text
#config-version=FGT60F v7.4.3,build2573
```

Model and serial number remain unset unless a later parser phase adds a reliable
source form.

## Provenance

Every emitted normalized property gets a `SourceLocation` containing the caller’s
source filename, the original 1-based line range, and the original raw line.
`management.ssh_enabled` and `management.telnet_enabled` both point to the
`set allowaccess ...` line that supplied their value.

The parser does not trim or rewrite the stored excerpt.

## UNKNOWN and ambiguity rules

- Missing FortiOS settings are omitted from Security IR; the generic control
  engine then returns `UNKNOWN` for controls that require them.
- Unsupported or empty `allowaccess` tokens create an `UNKNOWN` pattern and do
  not create fabricated SSH/Telnet values.
- Conflicting explicit values for logging, password policy, or NTP are emitted
  as `None` with provenance, which the generic engine evaluates as `UNKNOWN`.
- Access capabilities are aggregated across explicitly parsed interface
  `allowaccess` lists. A capability is true when explicitly present on at least
  one recognized interface; no recognized list means no property is emitted.
- The parser never returns `PASS` or `FAIL`; those decisions remain owned by the
  deterministic control engine.

## Fixtures and limitations

`configs/fortigate/compliant.conf`, `noncompliant.conf`, and `unknown.conf` are
synthetic demonstration configurations only. They are not customer exports.

This phase does not support the complete FortiOS configuration grammar, VDOM
semantics, all logging destinations, all administrative access controls, device
inventory extraction, or vendor-specific compliance logic. Palo Alto, AstraNet,
AI, adaptive learning, remediation, and reporting remain out of scope.
