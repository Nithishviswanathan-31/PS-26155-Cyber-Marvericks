import re

from ..domain.security_ir import DeviceInfo, SecurityIR, SourceLocation, UnknownPattern


class AstraNetParser:
    """Parse the intentionally tiny, fictional AstraNet demo format.

    AstraNet is synthetic demonstration data, not a real network operating
    system.  The ``guard-channel`` directive is deliberately left unmapped so
    the compliance pipeline can safely demonstrate UNKNOWN behavior.
    """

    vendor = "astranet"

    _MARKER_RE = re.compile(
        r"^#\s*FICTIONAL\s*/\s*SYNTHETIC\s+DEMONSTRATION\s+DATA\b",
        re.IGNORECASE,
    )
    _DEVICE_RE = re.compile(r"^astranet-device\s+(?P<hostname>\S+)\s*$", re.IGNORECASE)
    _UNKNOWN_PATTERN_RE = re.compile(r"^guard-channel\s+\S+(?:\s+.*)?$", re.IGNORECASE)

    @classmethod
    def detect(cls, configuration_text: str) -> bool:
        """Return true only for the focused synthetic AstraNet input shape."""

        if not isinstance(configuration_text, str) or not configuration_text.strip():
            return False

        has_marker = any(cls._MARKER_RE.match(line.strip()) for line in configuration_text.splitlines())
        has_device = any(cls._DEVICE_RE.match(line.strip()) for line in configuration_text.splitlines())
        has_unknown_pattern = any(
            cls._UNKNOWN_PATTERN_RE.match(line.strip()) for line in configuration_text.splitlines()
        )
        return has_marker and has_device and has_unknown_pattern

    @classmethod
    def parse(
        cls,
        configuration_text: str,
        *,
        source_file: str = "astranet_config.txt",
    ) -> SecurityIR:
        """Convert synthetic AstraNet text into Security IR.

        No normalized security property is emitted for ``guard-channel``.
        Its raw line is retained as an UNKNOWN pattern with exact provenance.
        """

        if not isinstance(configuration_text, str):
            raise TypeError("configuration_text must be a string")
        if not source_file.strip():
            raise ValueError("source_file cannot be empty")
        if not cls.detect(configuration_text):
            raise ValueError("configuration is not recognized as supported synthetic AstraNet demo input")

        hostname: str | None = None
        unknown_patterns: list[UnknownPattern] = []

        for line_number, raw_line in enumerate(configuration_text.splitlines(), start=1):
            stripped_line = raw_line.strip()
            device_match = cls._DEVICE_RE.match(stripped_line)
            if device_match:
                hostname = device_match.group("hostname")
                continue

            if cls._UNKNOWN_PATTERN_RE.match(stripped_line):
                location = SourceLocation(
                    source_file=source_file,
                    line_start=line_number,
                    line_end=line_number,
                    raw_excerpt=raw_line,
                )
                unknown_patterns.append(
                    UnknownPattern(
                        pattern_id=f"astranet-unknown-{line_number}",
                        raw_pattern=raw_line,
                        source_file=source_file,
                        line_start=line_number,
                        line_end=line_number,
                        location=location,
                        reason="Unrecognized fictional configuration structure has no approved semantic mapping.",
                        context="Fictional AstraNet OS synthetic demonstration; mapping is intentionally absent in P0.10-A.",
                    )
                )

        return SecurityIR(
            device=DeviceInfo(vendor=cls.vendor, hostname=hostname),
            normalized_properties={},
            provenance={},
            unknown_patterns=unknown_patterns,
        )


def detect_astranet(configuration_text: str) -> bool:
    """Convenience detector for callers that do not need a parser instance."""

    return AstraNetParser.detect(configuration_text)


def parse_astranet_config(
    configuration_text: str,
    *,
    source_file: str = "astranet_config.txt",
) -> SecurityIR:
    """Convenience entry point for the synthetic AstraNet parser."""

    return AstraNetParser.parse(configuration_text, source_file=source_file)
