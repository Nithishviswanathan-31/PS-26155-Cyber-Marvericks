from datetime import datetime, timezone
from typing import Protocol
from uuid import uuid4

from ..domain.interpretation import AIProposal
from ..domain.mapping import CandidateMappingSuggestion, pattern_signature, normalized_context
from ..domain.security_ir import UnknownPattern
from .ai_suggestion_service import SuggestionUnavailable, get_demo_suggestion_service


class InterpretationUnavailable(ValueError):
    """Raised when no safe offline interpretation exists."""


class InterpretationProvider(Protocol):
    provider_id: str
    provider_version: str

    def interpret(self, pattern: UnknownPattern, *, vendor: str, analysis_id: str) -> AIProposal:
        ...


class DemoInterpretationProvider:
    """Deterministic local provider for the synthetic AstraNet demonstration."""

    provider_id = "DEMO_INTERPRETATION_PROVIDER"
    provider_version = "1"

    def interpret(self, pattern: UnknownPattern, *, vendor: str, analysis_id: str) -> AIProposal:
        try:
            candidate: CandidateMappingSuggestion = get_demo_suggestion_service().suggest(pattern, vendor=vendor)
        except SuggestionUnavailable as exc:
            raise InterpretationUnavailable(str(exc)) from exc
        now = datetime.now(timezone.utc)
        mapping = dict(candidate.semantic_mapping)
        primary_property = sorted(mapping)[0]
        return AIProposal(
            proposal_id=f"proposal-{uuid4().hex[:12]}",
            analysis_id=analysis_id,
            pattern_id=pattern.pattern_id,
            vendor=vendor,
            pattern_signature=pattern_signature(vendor, pattern.raw_pattern),
            source_context=(pattern.context or pattern.location.raw_excerpt if pattern.location else pattern.raw_pattern).strip(),
            candidate_property=primary_property,
            candidate_value=mapping[primary_property],
            candidate_mapping=mapping,
            confidence=candidate.confidence,
            explanation=candidate.reasoning,
            interpreter_id=self.provider_id,
            interpreter_version=self.provider_version,
            created_at=now,
            updated_at=now,
        )


def get_interpretation_provider() -> InterpretationProvider:
    """Offline default; external model adapters can implement this protocol later."""

    return DemoInterpretationProvider()
