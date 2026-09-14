import re
from dataclasses import dataclass
from typing import Any

from ..domain.security_ir import DeviceInfo, SecurityIR, SourceLocation, UnknownPattern


@dataclass(frozen=True)
class _Observation:
    value: bool
    line_number: int
    raw_line: str


class CiscoParser:
    """Parse the small Cisco IOS/IOS-XE pattern set used by the demo."""

    vendor = "cisco_iosxe"

    _VERSION_RE = re.compile(r"^version\s+(?P<version>.+?)\s*$", re.IGNORECASE)
    _HOSTNAME_RE = re.compile(r"^hostname\s+(?P<hostname>\S+)\s*$", re.IGNORECASE)
    _VTY_RE = re.compile(r"^line\s+vty\b", re.IGNORECASE)
    _TRANSPORT_RE = re.compile(r"^transport\s+input\s+(?P<protocols>.+?)\s*$", re.IGNORECASE)
    _LOGGING_ENABLED_RE = re.compile(r"^logging\s+buffered(?:\s+.+)?$", re.IGNORECASE)
    _LOGGING_DISABLED_RE = re.compile(r"^no\s+logging\s+buffered(?:\s+.+)?$", re.IGNORECASE)
    _PASSWORD_ENABLED_RE = re.compile(r"^service\s+password-encryption\s*$", re.IGNORECASE)
    _PASSWORD_DISABLED_RE = re.compile(r"^no\s+service\s+password-encryption\s*$", re.IGNORECASE)
    _NTP_ENABLED_RE = re.compile(r"^ntp\s+server\s+\S+", re.IGNORECASE)
    _NTP_DISABLED_RE = re.compile(r"^no\s+ntp\s+server\s+\S+", re.IGNORECASE)

    @classmethod
    def detect(cls, configuration_text: str) -> bool:
        """Return true for the focused Cisco IOS/IOS-XE demo input shape."""

        if not isinstance(configuration_text, str) or not configuration_text.strip():
            return False

        lines = configuration_text.splitlines()
        return any(
            cls._VERSION_RE.match(line.strip())
            or cls._HOSTNAME_RE.match(line.strip())
            or cls._VTY_RE.match(line.strip())
            or cls._PASSWORD_ENABLED_RE.match(line.strip())
            or cls._PASSWORD_DISABLED_RE.match(line.strip())
            for line in lines
        )

    @classmethod
    def parse(
        cls,
        configuration_text: str,
        *,
        source_file: str = "cisco_config.txt",
    ) -> SecurityIR:
        """Convert supported Cisco text into Security IR with line provenance."""

        if not isinstance(configuration_text, str):
            raise TypeError("configuration_text must be a string")
        if not source_file.strip():
            raise ValueError("source_file cannot be empty")
        if not cls.detect(configuration_text):
            raise ValueError("configuration is not recognized as supported Cisco IOS/IOS-XE demo input")

        lines = configuration_text.splitlines()
        version: str | None = None
        hostname: str | None = None
        in_vty_block = False
        observations: dict[str, list[_Observation]] = {}
        unknown_patterns: list[UnknownPattern] = []

        def add_observation(property_name: str, value: bool, line_number: int, raw_line: str) -> None:
            observations.setdefault(property_name, []).append(
                _Observation(value=value, line_number=line_number, raw_line=raw_line)
            )

        def add_unknown(raw_line: str, line_number: int, reason: str) -> None:
            unknown_patterns.append(
                UnknownPattern(
                    pattern_id=f"cisco-unknown-{line_number}",
                    raw_pattern=raw_line,
                    source_file=source_file,
                    line_start=line_number,
                    line_end=line_number,
                    reason=reason,
                    context="Focused Cisco IOS/IOS-XE MVP parser",
                )
            )

        for line_number, raw_line in enumerate(lines, start=1):
            stripped_line = raw_line.strip()

            version_match = cls._VERSION_RE.match(stripped_line)
            if version_match:
                version = version_match.group("version")

            hostname_match = cls._HOSTNAME_RE.match(stripped_line)
            if hostname_match:
                hostname = hostname_match.group("hostname")

            if cls._VTY_RE.match(stripped_line):
                in_vty_block = True
                continue

            if stripped_line == "!":
                in_vty_block = False
                continue

            if in_vty_block:
                transport_match = cls._TRANSPORT_RE.match(stripped_line)
                if transport_match:
                    protocols = transport_match.group("protocols").lower().split()
                    if set(protocols).issubset({"ssh", "telnet"}) and protocols:
                        add_observation(
                            "management.ssh_enabled",
                            "ssh" in protocols,
                            line_number,
                            raw_line,
                        )
                        add_observation(
                            "management.telnet_enabled",
                            "telnet" in protocols,
                            line_number,
                            raw_line,
                        )
                    else:
                        add_unknown(
                            raw_line,
                            line_number,
                            "The VTY transport directive is outside the focused SSH/Telnet pattern set.",
                        )
                    continue

            if cls._LOGGING_ENABLED_RE.match(stripped_line):
                add_observation("logging.enabled", True, line_number, raw_line)
            elif cls._LOGGING_DISABLED_RE.match(stripped_line):
                add_observation("logging.enabled", False, line_number, raw_line)
            elif stripped_line.lower().startswith("logging") or stripped_line.lower().startswith("no logging"):
                add_unknown(
                    raw_line,
                    line_number,
                    "The logging directive is outside the focused buffered-logging pattern set.",
                )

            if cls._PASSWORD_ENABLED_RE.match(stripped_line):
                add_observation("password_protection.enabled", True, line_number, raw_line)
            elif cls._PASSWORD_DISABLED_RE.match(stripped_line):
                add_observation("password_protection.enabled", False, line_number, raw_line)

            if cls._NTP_ENABLED_RE.match(stripped_line):
                add_observation("time_sync.ntp_enabled", True, line_number, raw_line)
            elif cls._NTP_DISABLED_RE.match(stripped_line):
                add_observation("time_sync.ntp_enabled", False, line_number, raw_line)
            elif stripped_line.lower().startswith("ntp") or stripped_line.lower().startswith("no ntp"):
                add_unknown(
                    raw_line,
                    line_number,
                    "The NTP directive is outside the focused NTP-server pattern set.",
                )

        normalized_properties: dict[str, Any] = {}
        provenance: dict[str, SourceLocation] = {}

        for property_name, property_observations in observations.items():
            values = {observation.value for observation in property_observations}
            first = property_observations[0]
            last = property_observations[-1]
            normalized_properties[property_name] = next(iter(values)) if len(values) == 1 else None
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


def detect_cisco(configuration_text: str) -> bool:
    """Convenience detector for callers that do not need a parser instance."""

    return CiscoParser.detect(configuration_text)


def parse_cisco_config(
    configuration_text: str,
    *,
    source_file: str = "cisco_config.txt",
) -> SecurityIR:
    """Convenience entry point for the focused Cisco parser."""

    return CiscoParser.parse(configuration_text, source_file=source_file)
