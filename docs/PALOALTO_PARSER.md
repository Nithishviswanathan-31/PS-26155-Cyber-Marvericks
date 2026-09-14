# P0.9 Palo Alto PAN-OS Parser

This is focused MVP PAN-OS parsing, not complete PAN-OS coverage.

## Selected input format

The parser accepts bare PAN-OS configuration-mode `set` statements, one command
per line. This matches the CLI form documented by Palo Alto Networks, including
the complete hierarchy required for NTP configuration. XML exports, `show`
output, prompt prefixes, and other representations are intentionally out of
scope for this phase.

## Supported patterns

| PAN-OS `set` statement | Security IR property | Semantics |
| --- | --- | --- |
| `set network profiles interface-management-profile <name> ssh yes/no` plus an assigned profile | `management.ssh_enabled` | Uses the explicit SSH value of an assigned interface management profile |
| `set network profiles interface-management-profile <name> telnet yes/no` plus an assigned profile | `management.telnet_enabled` | Uses the explicit Telnet value of an assigned interface management profile |
| `set shared log-settings system match-list <name> send-to-panorama yes/no` | `logging.enabled` | Focused proxy for system/audit log forwarding to Panorama |
| `set mgt-config password-complexity block-username-inclusion yes/no` | `password_protection.enabled` | Focused password-complexity protection setting |
| `set deviceconfig system ntp-servers primary-ntp-server ntp-server-address <address>` | `time_sync.ntp_enabled` | A configured primary NTP server is explicit evidence of enabled time synchronization |
| `set deviceconfig system hostname <hostname>` | device hostname | Preserves explicit hostname metadata |

The interface-management-profile and assignment forms are documented in the
[PAN-OS CLI hierarchy](https://docs.paloaltonetworks.com/ngfw/pan-os-cli-quick-start/cli-command-hierarchy/pan-os-11-1-configure-cli-command-hierarchy)
and [interface-management guidance](https://docs.paloaltonetworks.com/ngfw/help/12-1/network/network-network-profiles/network-network-profiles-interface-mgmt).
The NTP form follows Palo Alto’s [CLI configuration example](https://docs.paloaltonetworks.com/ngfw/pan-os-cli-quick-start/use-the-cli/modify-the-configuration).

The `logging.enabled` and `password_protection.enabled` mappings are deliberately
narrow MVP proxies, not claims that every PAN-OS logging or password setting has
been evaluated. PAN-OS exposes system log match-list settings and password
complexity settings through its CLI hierarchy; broader semantic coverage is
deferred.

## Vendor and metadata

The normalized vendor identifier is:

```text
paloalto_panos
```

Hostname is extracted when the `deviceconfig system hostname` statement is
present. PAN-OS version, model, and serial number are left unset because the
selected `set`-statement representation does not provide a reliable inventory
source in this MVP.

## Provenance and UNKNOWN behavior

Every emitted normalized property retains the original source filename, exact
1-based source line, and raw command line in `SourceLocation`.

- Missing statements are omitted from Security IR; the generic engine returns
  `UNKNOWN` for controls requiring them.
- An interface management profile must be assigned before SSH/Telnet properties
  are emitted.
- Conflicting explicit values are represented as `None` with provenance and are
  evaluated as `UNKNOWN`.
- Unsupported statements create an `UNKNOWN` pattern when they match a known PAN-OS
  configuration family; they never fabricate a normalized value.
- The parser never returns `PASS` or `FAIL`.

## Fixtures and limitations

`configs/paloalto/compliant.conf`, `noncompliant.conf`, and `unknown.conf` are
synthetic demonstration configurations only, not production or customer data.

The parser does not support XML, `show config` output, Panorama template
resolution, inherited settings, VDOM-like scope resolution, all log-forwarding
destinations, all password-profile semantics, or complete PAN-OS command
coverage. AstraNet, AI, adaptive learning, remediation, simulation, and reporting
remain out of scope.
