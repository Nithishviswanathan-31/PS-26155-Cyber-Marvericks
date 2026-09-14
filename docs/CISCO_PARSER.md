# Cisco IOS / IOS-XE parser

P0.4 provides a focused parser for synthetic Cisco IOS/IOS-XE demo
configurations. It converts configuration text into the existing vendor-neutral
`SecurityIR` contract. It does not produce compliance results.

## Supported input style

The parser recognizes the small configuration shape used by the demo fixtures:

- `version <value>`
- `hostname <value>`
- `line vty ...` followed by an indented `transport input ...` directive
- `logging buffered ...`
- `no logging buffered ...`
- `service password-encryption`
- `no service password-encryption`
- `ntp server <server>`
- `no ntp server <server>`

The parser identifies supported demo input using focused Cisco markers. This is
not comprehensive IOS/IOS-XE product or version detection.

## Normalized properties

The parser currently produces only:

- `management.ssh_enabled`
- `management.telnet_enabled`
- `logging.enabled`
- `password_protection.enabled`
- `time_sync.ntp_enabled`

The control engine, not this parser, determines `PASS`, `FAIL`, or `UNKNOWN`.

## Provenance

Every normalized property produced by the parser has a `SourceLocation` with:

- caller-provided source filename
- one-based original line numbers
- original raw source line text

When repeated equivalent directives contribute to one property, the provenance
spans the first through last observation and preserves the raw lines joined by a
newline.

## UNKNOWN and conflicts

Missing directives are omitted from the Security IR. The control engine then
returns `UNKNOWN`; missing configuration is never interpreted as disabled.

If supported directives conflict, the parser stores the property value as
`null` with provenance. The deterministic engine interprets that explicit
ambiguity as `UNKNOWN`.

Unsupported security-related directives are recorded as `UnknownPattern` with
their source line. They do not create guessed normalized properties.

## Current limitations

- Focused demo syntax only
- No complete Cisco command grammar
- No model or serial-number extraction
- No device connection or configuration changes
- No vendor comparison logic
- No AI or adaptive learning
- Synthetic fixtures only; no customer configuration data
