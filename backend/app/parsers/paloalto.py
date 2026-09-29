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


class PaloAltoParser:
    """Parse a focused PAN-OS ``set``-statement configuration export."""

    vendor = "paloalto_panos"

    _PANOS_MARKERS = (
        ("set", "deviceconfig", "system", "hostname"),
        ("set", "deviceconfig", "system", "ntp-servers"),
        ("set", "mgt-config", "password-complexity"),
        ("set", "network", "profiles", "interface-management-profile"),
        ("set", "shared", "log-settings"),
    )
    _SUPPORTED_ACCESS_PROTOCOLS = {"ssh", "telnet"}
    _COMMENT_MODEL_RE = re.compile(
        r"^#\s*(?:Chassis(?: type)?|Model|Device Model|PID|Hardware)[:=\s]\s*(?P<model>\S+)\s*$",
        re.IGNORECASE,
    )
    _COMMENT_SERIAL_RE = re.compile(
        r"^#\s*(?:(?:System )?Serial(?: Number)?|SN)[:=\s]\s*(?P<serial>\S+)\s*$",
        re.IGNORECASE,
    )
    _COMMENT_VERSION_RE = re.compile(
        r"^#\s*(?:(?:PAN-OS|Software)\s+)?Version[:=\s]\s*(?P<version>\S+)\s*$",
        re.IGNORECASE,
    )
    _COMMENT_PLATFORM_RE = re.compile(
        r"^#\s*Platform[:=\s]\s*(?P<platform>\S+)\s*$",
        re.IGNORECASE,
    )
    _COMMENT_HOSTNAME_RE = re.compile(
        r"^#\s*Hostname[:=\s]\s*(?P<hostname>\S+)\s*$",
        re.IGNORECASE,
    )

    @classmethod
    def detect(cls, configuration_text: str) -> bool:
        """Return true for the focused bare PAN-OS ``set`` input shape."""

        if not isinstance(configuration_text, str) or not configuration_text.strip():
            return False

        for raw_line in configuration_text.splitlines():
            stripped = raw_line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            try:
                tokens = shlex.split(stripped)
            except ValueError:
                continue
            if any(tuple(tokens[: len(marker)]) == marker for marker in cls._PANOS_MARKERS):
                return True
        return False

    @classmethod
    def parse(
        cls,
        configuration_text: str,
        *,
        source_file: str = "paloalto_config.txt",
    ) -> SecurityIR:
        """Convert supported PAN-OS set statements into Security IR."""

        if not isinstance(configuration_text, str):
            raise TypeError("configuration_text must be a string")
        if not source_file.strip():
            raise ValueError("source_file cannot be empty")
        if not cls.detect(configuration_text):
            raise ValueError("configuration is not recognized as supported Palo Alto PAN-OS demo input")

        version: str | None = None
        hostname: str | None = None
        device_model: str | None = None
        serial_number: str | None = None
        platform: str | None = None
        metadata_provenance: dict[str, SourceLocation] = {}
        unknown_patterns: list[UnknownPattern] = []
        observations: dict[str, list[_Observation]] = {}
        ambiguous_properties: set[str] = set()
        profile_observations: dict[str, dict[str, list[_Observation]]] = {}
        assigned_profiles: list[tuple[str, int, str]] = []

        def add_observation(property_name: str, value: bool, line_number: int, raw_line: str) -> None:
            if property_name == "password_protection.enabled":
                observations.setdefault("credentials.username_exclusion_enabled", []).append(
                    _Observation(value=value, line_number=line_number, raw_line=raw_line)
                )
            observations.setdefault(property_name, []).append(
                _Observation(value=value, line_number=line_number, raw_line=raw_line)
            )

        def add_unknown(raw_line: str, line_number: int, reason: str) -> None:
            unknown_patterns.append(
                UnknownPattern(
                    pattern_id=f"paloalto-unknown-{line_number}",
                    raw_pattern=raw_line,
                    source_file=source_file,
                    line_start=line_number,
                    line_end=line_number,
                    reason=reason,
                    context="Focused Palo Alto PAN-OS MVP parser",
                )
            )

        for line_number, raw_line in enumerate(configuration_text.splitlines(), start=1):
            stripped_line = raw_line.strip()
            if not stripped_line:
                continue

            if stripped_line.startswith("#"):
                model_match = cls._COMMENT_MODEL_RE.match(stripped_line)
                if model_match:
                    device_model = model_match.group("model")
                    metadata_provenance["device_model"] = SourceLocation(
                        source_file=source_file, line_start=line_number, line_end=line_number, raw_excerpt=raw_line
                    )
                    continue

                serial_match = cls._COMMENT_SERIAL_RE.match(stripped_line)
                if serial_match:
                    serial_number = serial_match.group("serial")
                    metadata_provenance["serial_number"] = SourceLocation(
                        source_file=source_file, line_start=line_number, line_end=line_number, raw_excerpt=raw_line
                    )
                    continue

                version_match = cls._COMMENT_VERSION_RE.match(stripped_line)
                if version_match:
                    version = version_match.group("version")
                    metadata_provenance["software_version"] = SourceLocation(
                        source_file=source_file, line_start=line_number, line_end=line_number, raw_excerpt=raw_line
                    )
                    continue

                platform_match = cls._COMMENT_PLATFORM_RE.match(stripped_line)
                if platform_match:
                    platform = platform_match.group("platform")
                    metadata_provenance["platform"] = SourceLocation(
                        source_file=source_file, line_start=line_number, line_end=line_number, raw_excerpt=raw_line
                    )
                    continue

                hostname_match = cls._COMMENT_HOSTNAME_RE.match(stripped_line)
                if hostname_match:
                    hostname = hostname_match.group("hostname")
                    metadata_provenance["hostname"] = SourceLocation(
                        source_file=source_file, line_start=line_number, line_end=line_number, raw_excerpt=raw_line
                    )
                    continue

                continue

            try:
                tokens = shlex.split(stripped_line)
            except ValueError:
                if stripped_line.startswith(("set deviceconfig", "set network", "set shared", "set mgt-config")):
                    add_unknown(raw_line, line_number, "The PAN-OS set statement is malformed.")
                continue

            if not tokens or tokens[0].lower() != "set":
                if tokens and tokens[0].lower() in {"delete", "edit"}:
                    add_unknown(
                        raw_line,
                        line_number,
                        "This PAN-OS statement is outside the focused set-statement parser.",
                    )
                continue

            lowered = [token.lower() for token in tokens]

            if lowered[:4] == ["set", "deviceconfig", "system", "hostname"]:
                if len(tokens) == 5 and tokens[4].strip():
                    hostname = tokens[4]
                    metadata_provenance["hostname"] = SourceLocation(source_file=source_file, line_start=line_number, line_end=line_number, raw_excerpt=raw_line)
                else:
                    add_unknown(raw_line, line_number, "The PAN-OS hostname statement is malformed or ambiguous.")
                continue

            if lowered[:4] in (["set", "deviceconfig", "system", "model"], ["set", "deviceconfig", "system", "device-model"]):
                if len(tokens) == 5 and tokens[4].strip():
                    device_model = tokens[4]
                    metadata_provenance["device_model"] = SourceLocation(
                        source_file=source_file, line_start=line_number, line_end=line_number, raw_excerpt=raw_line
                    )
                else:
                    add_unknown(raw_line, line_number, "The PAN-OS model statement is malformed or ambiguous.")
                continue

            if lowered[:4] in (["set", "deviceconfig", "system", "serial"], ["set", "deviceconfig", "system", "serial-number"]):
                if len(tokens) == 5 and tokens[4].strip():
                    serial_number = tokens[4]
                    metadata_provenance["serial_number"] = SourceLocation(
                        source_file=source_file, line_start=line_number, line_end=line_number, raw_excerpt=raw_line
                    )
                else:
                    add_unknown(raw_line, line_number, "The PAN-OS serial statement is malformed or ambiguous.")
                continue

            if lowered[:4] in (["set", "deviceconfig", "system", "version"], ["set", "deviceconfig", "system", "sw-version"]):
                if len(tokens) == 5 and tokens[4].strip():
                    version = tokens[4]
                    metadata_provenance["software_version"] = SourceLocation(
                        source_file=source_file, line_start=line_number, line_end=line_number, raw_excerpt=raw_line
                    )
                else:
                    add_unknown(raw_line, line_number, "The PAN-OS version statement is malformed or ambiguous.")
                continue

            if lowered[:4] == ["set", "deviceconfig", "system", "platform"]:
                if len(tokens) == 5 and tokens[4].strip():
                    platform = tokens[4]
                    metadata_provenance["platform"] = SourceLocation(
                        source_file=source_file, line_start=line_number, line_end=line_number, raw_excerpt=raw_line
                    )
                else:
                    add_unknown(raw_line, line_number, "The PAN-OS platform statement is malformed or ambiguous.")
                continue

            if lowered[:4] == ["set", "network", "profiles", "interface-management-profile"]:
                if len(tokens) == 7 and lowered[5] in cls._SUPPORTED_ACCESS_PROTOCOLS and lowered[6] in {"yes", "no"}:
                    profile_name = tokens[4]
                    profile_observations.setdefault(profile_name, {}).setdefault(lowered[5], []).append(
                        _Observation(lowered[6] == "yes", line_number, raw_line)
                    )
                else:
                    add_unknown(raw_line, line_number, "The PAN-OS interface management profile statement is unsupported or ambiguous.")
                continue

            if lowered[:3] == ["set", "network", "interface"] and "interface-management-profile" in lowered:
                profile_index = lowered.index("interface-management-profile")
                if profile_index == len(tokens) - 2 and profile_index >= 2 and tokens[profile_index + 1].strip():
                    assigned_profiles.append((tokens[profile_index + 1], line_number, raw_line))
                else:
                    add_unknown(raw_line, line_number, "The PAN-OS interface management profile assignment is unsupported or ambiguous.")
                continue

            if lowered[:5] == ["set", "shared", "log-settings", "system", "match-list"]:
                if len(tokens) == 8 and lowered[6] == "send-to-panorama" and lowered[7] in {"yes", "no"}:
                    add_observation("logging.enabled", lowered[7] == "yes", line_number, raw_line)
                else:
                    add_unknown(raw_line, line_number, "The PAN-OS system log-setting statement is outside the focused mapping.")
                continue

            if lowered[:3] == ["set", "mgt-config", "password-complexity"]:
                if len(tokens) == 5 and lowered[3] == "block-username-inclusion" and lowered[4] in {"yes", "no"}:
                    add_observation("password_protection.enabled", lowered[4] == "yes", line_number, raw_line)
                else:
                    add_unknown(raw_line, line_number, "The PAN-OS password-complexity statement is outside the focused mapping.")
                continue

            if lowered[:6] == [
                "set",
                "deviceconfig",
                "system",
                "ntp-servers",
                "primary-ntp-server",
                "ntp-server-address",
            ]:
                if len(tokens) == 7 and tokens[6].strip():
                    add_observation("time_sync.ntp_enabled", True, line_number, raw_line)
                else:
                    add_unknown(raw_line, line_number, "The PAN-OS primary NTP server statement is malformed or ambiguous.")
                continue

            if tuple(lowered[:3]) in {
                ("set", "deviceconfig", "system"),
                ("set", "mgt-config", "password-complexity"),
                ("set", "shared", "log-settings"),
            }:
                add_unknown(raw_line, line_number, "The PAN-OS statement is outside the focused MVP mapping.")

        for property_name in ("management.ssh_enabled", "management.telnet_enabled"):
            protocol = property_name.rsplit(".", maxsplit=1)[-1].removesuffix("_enabled")
            relevant: list[_Observation] = []
            profile_is_ambiguous = False
            for profile_name, _, _ in assigned_profiles:
                profile_values = profile_observations.get(profile_name, {}).get(protocol, [])
                if not profile_values:
                    profile_is_ambiguous = True
                    continue
                relevant.extend(profile_values)
                if len({observation.value for observation in profile_values}) > 1:
                    profile_is_ambiguous = True

            if relevant:
                observations[property_name] = relevant
                if profile_is_ambiguous:
                    ambiguous_properties.add(property_name)

        normalized_properties: dict[str, Any] = {}
        provenance: dict[str, SourceLocation] = {}

        for property_name, property_observations in observations.items():
            first = property_observations[0]
            last = property_observations[-1]
            values = {observation.value for observation in property_observations}
            normalized_properties[property_name] = (
                None
                if property_name in ambiguous_properties or len(values) != 1
                else next(iter(values))
            )
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
                device_model=device_model,
                serial_number=serial_number,
                platform=platform,
                metadata_provenance=metadata_provenance,
            ),
            normalized_properties=normalized_properties,
            provenance=provenance,
            unknown_patterns=unknown_patterns,
        )


def detect_paloalto(configuration_text: str) -> bool:
    """Convenience detector for callers that do not need a parser instance."""

    return PaloAltoParser.detect(configuration_text)


def parse_paloalto_config(
    configuration_text: str,
    *,
    source_file: str = "paloalto_config.txt",
) -> SecurityIR:
    """Convenience entry point for the focused PAN-OS parser."""

    return PaloAltoParser.parse(configuration_text, source_file=source_file)
