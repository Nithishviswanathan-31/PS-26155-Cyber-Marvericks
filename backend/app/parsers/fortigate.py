import re
import shlex
from dataclasses import dataclass
from typing import Any

from ..domain.security_ir import DeviceInfo, SecurityIR, SourceLocation, UnknownPattern


@dataclass(frozen=True)
class _Observation:
    value: bool
    line_number: int
    raw_line: str


class FortiGateParser:
    """Parse the small FortiOS pattern set used by the emergency demo."""

    vendor = "fortigate_fortios"

    _CONFIG_RE = re.compile(r"^config\s+(?P<section>.+?)\s*$", re.IGNORECASE)
    _SET_RE = re.compile(r"^set\s+(?P<key>\S+)\s*(?P<value>.*?)\s*$", re.IGNORECASE)
    _VERSION_RE = re.compile(
        r"^#config-version=.*?\bv(?P<version>\d+(?:\.\d+)+)\b",
        re.IGNORECASE,
    )
    _CONFIG_VERSION_MARKER_RE = re.compile(r"^#config-version=", re.IGNORECASE)
    _FORTIGATE_MARKER_RE = re.compile(
        r"^(?:#(?:config-version|buildno|global_vdom)|config\s+(?:system\s+global|system\s+interface|system\s+ntp|log\b))",
        re.IGNORECASE,
    )

    _LOG_SECTIONS = {
        "log disk setting",
        "log memory setting",
        "log syslogd setting",
        "log fortianalyzer setting",
        "log fortiguard setting",
    }
    _KNOWN_ALLOWACCESS = {
        "fgfm",
        "fabric",
        "ftm",
        "http",
        "https",
        "ping",
        "probe-response",
        "radius-acct",
        "snmp",
        "ssh",
        "telnet",
    }

    @classmethod
    def detect(cls, configuration_text: str) -> bool:
        """Return true for the focused FortiOS configuration shape."""

        if not isinstance(configuration_text, str) or not configuration_text.strip():
            return False

        return any(cls._FORTIGATE_MARKER_RE.match(line.strip()) for line in configuration_text.splitlines())

    @classmethod
    def parse(
        cls,
        configuration_text: str,
        *,
        source_file: str = "fortigate_config.txt",
    ) -> SecurityIR:
        """Convert supported FortiOS text into Security IR with provenance."""

        if not isinstance(configuration_text, str):
            raise TypeError("configuration_text must be a string")
        if not source_file.strip():
            raise ValueError("source_file cannot be empty")
        if not cls.detect(configuration_text):
            raise ValueError("configuration is not recognized as supported FortiGate/FortiOS demo input")

        lines = configuration_text.splitlines()
        current_config: str | None = None
        version: str | None = None
        hostname: str | None = None
        observations: dict[str, list[_Observation]] = {}
        unknown_patterns: list[UnknownPattern] = []
        access_syntax_is_ambiguous = False

        def add_observation(property_name: str, value: bool, line_number: int, raw_line: str) -> None:
            observations.setdefault(property_name, []).append(
                _Observation(value=value, line_number=line_number, raw_line=raw_line)
            )

        def add_unknown(raw_line: str, line_number: int, reason: str) -> None:
            unknown_patterns.append(
                UnknownPattern(
                    pattern_id=f"fortigate-unknown-{line_number}",
                    raw_pattern=raw_line,
                    source_file=source_file,
                    line_start=line_number,
                    line_end=line_number,
                    reason=reason,
                    context="Focused FortiGate/FortiOS MVP parser",
                )
            )

        for line_number, raw_line in enumerate(lines, start=1):
            stripped_line = raw_line.strip()
            if not stripped_line:
                continue

            version_match = cls._VERSION_RE.match(stripped_line)
            if version_match:
                version = version_match.group("version")
                continue

            if stripped_line.startswith("#") or stripped_line.startswith("!"):
                continue

            config_match = cls._CONFIG_RE.match(stripped_line)
            if config_match:
                current_config = " ".join(config_match.group("section").lower().split())
                continue

            if stripped_line.lower() == "end":
                current_config = None
                continue
            if stripped_line.lower() == "next":
                continue

            set_match = cls._SET_RE.match(stripped_line)
            if not set_match:
                continue

            key = set_match.group("key").lower()
            value = set_match.group("value").strip()

            if current_config == "system global" and key == "hostname":
                try:
                    hostname_values = shlex.split(value)
                except ValueError:
                    hostname_values = []
                if len(hostname_values) == 1 and hostname_values[0].strip():
                    hostname = hostname_values[0]
                else:
                    add_unknown(raw_line, line_number, "The FortiOS hostname value is malformed or ambiguous.")
                continue

            if current_config == "system interface" and key == "allowaccess":
                protocols = value.replace('"', "").split()
                if not protocols or any(protocol.lower() not in cls._KNOWN_ALLOWACCESS for protocol in protocols):
                    access_syntax_is_ambiguous = True
                    add_unknown(
                        raw_line,
                        line_number,
                        "The interface allowaccess list contains an unsupported or empty access token.",
                    )
                    continue
                add_observation("management.ssh_enabled", "ssh" in {protocol.lower() for protocol in protocols}, line_number, raw_line)
                add_observation("management.telnet_enabled", "telnet" in {protocol.lower() for protocol in protocols}, line_number, raw_line)
                continue

            if current_config in cls._LOG_SECTIONS and key == "status":
                if value.lower() in {"enable", "disable"}:
                    add_observation("logging.enabled", value.lower() == "enable", line_number, raw_line)
                else:
                    add_unknown(raw_line, line_number, "The FortiOS log status value is unsupported or ambiguous.")
                continue

            if current_config == "system password-policy" and key == "status":
                if value.lower() in {"enable", "disable"}:
                    add_observation("password_protection.enabled", value.lower() == "enable", line_number, raw_line)
                else:
                    add_unknown(raw_line, line_number, "The FortiOS password-policy status value is unsupported or ambiguous.")
                continue

            if current_config == "system ntp" and key == "ntpsync":
                if value.lower() in {"enable", "disable"}:
                    add_observation("time_sync.ntp_enabled", value.lower() == "enable", line_number, raw_line)
                else:
                    add_unknown(raw_line, line_number, "The FortiOS NTP synchronization value is unsupported or ambiguous.")

        normalized_properties: dict[str, Any] = {}
        provenance: dict[str, SourceLocation] = {}

        for property_name, property_observations in observations.items():
            first = property_observations[0]
            last = property_observations[-1]
            values = {observation.value for observation in property_observations}
            if property_name.startswith("management."):
                # allowaccess is a per-interface list. A capability is enabled when
                # explicitly present on at least one interface; unsupported syntax
                # keeps the result safely ambiguous.
                value = None if access_syntax_is_ambiguous else any(
                    observation.value for observation in property_observations
                )
            else:
                value = next(iter(values)) if len(values) == 1 else None
            normalized_properties[property_name] = value
            provenance[property_name] = SourceLocation(
                source_file=source_file,
                line_start=first.line_number,
                line_end=last.line_number,
                raw_excerpt="\n".join(observation.raw_line for observation in property_observations),
            )

        return SecurityIR(
            device=DeviceInfo(
                vendor=cls.vendor,
                version=version,
                hostname=hostname,
            ),
            normalized_properties=normalized_properties,
            provenance=provenance,
            unknown_patterns=unknown_patterns,
        )


def detect_fortigate(configuration_text: str) -> bool:
    """Convenience detector for callers that do not need a parser instance."""

    return FortiGateParser.detect(configuration_text)


def parse_fortigate_config(
    configuration_text: str,
    *,
    source_file: str = "fortigate_config.txt",
) -> SecurityIR:
    """Convenience entry point for the focused FortiOS parser."""

    return FortiGateParser.parse(configuration_text, source_file=source_file)
