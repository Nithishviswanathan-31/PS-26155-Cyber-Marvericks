"""Types at the normalized-property/evaluation boundary; never coerce input."""
from types import MappingProxyType
from dataclasses import dataclass
from enum import StrEnum


class ParserCapability(StrEnum):
    SUPPORTED = "SUPPORTED"
    PARTIAL = "PARTIAL"
    UNSUPPORTED = "UNSUPPORTED"


@dataclass(frozen=True)
class PropertyDefinition:
    value_type: type
    description: str
    vendors: tuple[str, ...]
    capability: ParserCapability = ParserCapability.PARTIAL
    provenance_expectation: str = "Exact source file, line range and raw directive; conflicting observations remain None."


REAL_VENDORS = ("cisco_iosxe", "fortigate_fortios", "paloalto_panos")
PROPERTY_DEFINITIONS = MappingProxyType({
    "management.ssh_enabled": PropertyDefinition(bool, "SSH management access in the focused parsed scope.", REAL_VENDORS),
    "management.telnet_enabled": PropertyDefinition(bool, "Telnet management access in the focused parsed scope.", REAL_VENDORS),
    "logging.enabled": PropertyDefinition(bool, "Legacy vendor-specific logging enablement indicator.", REAL_VENDORS),
    "password_protection.enabled": PropertyDefinition(bool, "Legacy vendor-specific credential protection indicator; mechanisms differ.", REAL_VENDORS),
    "time_sync.ntp_enabled": PropertyDefinition(bool, "Parsed NTP enablement/server configuration, not operational synchronization.", REAL_VENDORS),
    "logging.buffered_enabled": PropertyDefinition(bool, "Cisco buffered logging explicitly enabled/disabled by parsed directives.", ("cisco_iosxe",), ParserCapability.SUPPORTED),
    "credentials.password_policy_enabled": PropertyDefinition(bool, "FortiOS system password-policy status enable/disable.", ("fortigate_fortios",), ParserCapability.SUPPORTED),
    "credentials.username_exclusion_enabled": PropertyDefinition(bool, "PAN-OS password-complexity block-username-inclusion yes/no.", ("paloalto_panos",), ParserCapability.SUPPORTED),
})


PROPERTY_TYPES = MappingProxyType({path: definition.value_type for path, definition in PROPERTY_DEFINITIONS.items()})


def parser_capability(path: str, vendor: str) -> ParserCapability:
    definition = PROPERTY_DEFINITIONS.get(path)
    if definition is None or vendor not in definition.vendors:
        return ParserCapability.UNSUPPORTED
    return definition.capability


def valid_property_value(path: str, value: object) -> bool:
    expected_type = PROPERTY_TYPES.get(path)
    return expected_type is not None and type(value) is expected_type
