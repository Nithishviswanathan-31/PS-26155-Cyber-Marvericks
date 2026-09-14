from typing import Protocol

from ..domain.mapping import CandidateMappingSuggestion
from ..domain.security_ir import UnknownPattern


class SuggestionUnavailable(ValueError):
    """Raised when the controlled adapter has no safe candidate for a pattern."""


class MappingSuggestionService(Protocol):
    """Interface a future real AI provider can implement."""

    def suggest(
        self,
        pattern: UnknownPattern,
        *,
        vendor: str,
    ) -> CandidateMappingSuggestion:
        ...


class LocalDemoSuggestionService:
    """Deterministic local adapter for the single synthetic AstraNet pattern."""

    _SUPPORTED_VENDOR = "astranet"
    _SUPPORTED_PATTERN = "guard-channel lattice-secure"

    def suggest(
        self,
        pattern: UnknownPattern,
        *,
        vendor: str,
    ) -> CandidateMappingSuggestion:
        if vendor != self._SUPPORTED_VENDOR or pattern.raw_pattern.strip().lower() != self._SUPPORTED_PATTERN:
            raise SuggestionUnavailable(
                "No controlled demo candidate is available for this unknown pattern."
            )

        # This is a candidate interpretation for review, not a compliance fact.
        return CandidateMappingSuggestion(
            pattern_id=pattern.pattern_id,
            confidence=0.94,
            semantic_mapping={
                "management.ssh_enabled": True,
                "management.telnet_enabled": False,
            },
            reasoning=(
                "Candidate interpretation of the unfamiliar synthetic configuration "
                "pattern; human approval is required before it can be stored."
            ),
            requires_human_approval=True,
        )


def get_demo_suggestion_service() -> MappingSuggestionService:
    """Return the controlled adapter through the future-provider interface."""

    return LocalDemoSuggestionService()
