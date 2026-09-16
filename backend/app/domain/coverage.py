"""Count independent requirements using stored relationships, never the live YAML."""
from collections import Counter
from collections.abc import Iterable

from .schemas import ControlResultSummary


def coverage_counts(results: Iterable[ControlResultSummary]) -> Counter:
    return Counter(result.result.value for result in results if result.diagnostic_of is None)
