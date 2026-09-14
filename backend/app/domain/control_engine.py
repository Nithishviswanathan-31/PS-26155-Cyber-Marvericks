from collections.abc import Iterable
from typing import Any

from .enums import ComplianceResult
from .schemas import (
    ControlDefinition,
    ControlEvaluationResult,
    ControlEvidence,
)
from .security_ir import SecurityIR


class DeterministicControlEngine:
    """Evaluate YAML controls against Security IR without AI or vendor logic."""

    def evaluate(
        self,
        security_ir: SecurityIR,
        control: ControlDefinition,
    ) -> ControlEvaluationResult:
        evaluation_type = control.evaluation.type.strip().lower()

        if evaluation_type in {"not_applicable", "na"}:
            return ControlEvaluationResult(
                control_id=control.control_id,
                control_name=control.name,
                result=ComplianceResult.NOT_APPLICABLE,
                expected=None,
                actual=None,
                evidence=[],
                explanation="The control explicitly declares itself not applicable.",
                remediation=dict(control.remediation),
            )

        conditions = control.evaluation.conditions
        if not conditions:
            return self._unknown_result(
                control,
                expected=None,
                actual=None,
                evidence=[],
                explanation="The control has no evaluable conditions.",
            )

        evidence: list[ControlEvidence] = []
        condition_results: list[ComplianceResult] = []
        actual_values: dict[str, Any] = {}
        expected_values: dict[str, Any] = {}

        for condition in conditions:
            expected_values[condition.path] = condition.expected
            trace = security_ir.trace_property(condition.path)

            if trace is None:
                actual_values[condition.path] = None
                condition_results.append(ComplianceResult.UNKNOWN)
                evidence.append(
                    ControlEvidence.from_trace(
                        property_name=condition.path,
                        expected=condition.expected,
                        actual=None,
                        result=ComplianceResult.UNKNOWN,
                        provenance=None,
                        explanation="The required normalized property is missing from the Security IR.",
                    )
                )
                continue

            actual_values[condition.path] = trace.value

            if (
                trace.provenance is None
                and trace.mapping_provenance is None
                and trace.simulation_provenance is None
            ):
                condition_results.append(ComplianceResult.UNKNOWN)
                evidence.append(
                    ControlEvidence.from_trace(
                        property_name=condition.path,
                        expected=condition.expected,
                        actual=trace.value,
                        result=ComplianceResult.UNKNOWN,
                        provenance=None,
                        explanation="The property exists, but source provenance is unavailable.",
                    )
                )
                continue

            if trace.value is None:
                condition_results.append(ComplianceResult.UNKNOWN)
                evidence.append(
                    ControlEvidence.from_trace(
                        property_name=condition.path,
                        expected=condition.expected,
                        actual=None,
                        result=ComplianceResult.UNKNOWN,
                        provenance=trace.provenance,
                        explanation="The normalized property is explicitly ambiguous or unknown.",
                    )
                )
                continue

            if condition.operator.strip().lower() != "equals":
                condition_results.append(ComplianceResult.UNKNOWN)
                evidence.append(
                    ControlEvidence.from_trace(
                        property_name=condition.path,
                        expected=condition.expected,
                        actual=trace.value,
                        result=ComplianceResult.UNKNOWN,
                        provenance=trace.provenance,
                        explanation=(
                            f"The operator '{condition.operator}' is not supported by the deterministic engine."
                        ),
                    )
                )
                continue

            condition_result = (
                ComplianceResult.PASS
                if trace.value == condition.expected
                else ComplianceResult.FAIL
            )
            condition_results.append(condition_result)
            evidence.append(
                ControlEvidence.from_trace(
                    property_name=condition.path,
                    expected=condition.expected,
                    actual=trace.value,
                    result=condition_result,
                    provenance=trace.provenance,
                    explanation=self._condition_explanation(
                        condition.path,
                        condition.expected,
                        trace.value,
                        condition_result,
                    ),
                )
            )

        result = self._combine_results(evaluation_type, condition_results)
        if result is ComplianceResult.PASS:
            explanation = "All required deterministic conditions are satisfied."
        elif result is ComplianceResult.FAIL:
            explanation = "One or more required deterministic conditions are violated."
        else:
            explanation = "The deterministic engine could not establish a supported result from the available evidence."

        is_single_condition = len(conditions) == 1
        expected: Any = conditions[0].expected if is_single_condition else expected_values
        actual: Any = actual_values[conditions[0].path] if is_single_condition else actual_values

        return ControlEvaluationResult(
            control_id=control.control_id,
            control_name=control.name,
            result=result,
            expected=expected,
            actual=actual,
            evidence=evidence,
            explanation=explanation,
            remediation=dict(control.remediation),
        )

    def evaluate_all(
        self,
        security_ir: SecurityIR,
        controls: Iterable[ControlDefinition],
    ) -> list[ControlEvaluationResult]:
        """Evaluate controls in the supplied order for stable demo output."""

        return [self.evaluate(security_ir, control) for control in controls]

    @staticmethod
    def _combine_results(
        evaluation_type: str,
        condition_results: list[ComplianceResult],
    ) -> ComplianceResult:
        if evaluation_type == "equals" and len(condition_results) != 1:
            return ComplianceResult.UNKNOWN
        if evaluation_type not in {"equals", "all"}:
            return ComplianceResult.UNKNOWN
        if any(result is ComplianceResult.UNKNOWN for result in condition_results):
            return ComplianceResult.UNKNOWN
        if all(result is ComplianceResult.PASS for result in condition_results):
            return ComplianceResult.PASS
        return ComplianceResult.FAIL

    @staticmethod
    def _condition_explanation(
        property_name: str,
        expected: Any,
        actual: Any,
        result: ComplianceResult,
    ) -> str:
        if result is ComplianceResult.PASS:
            return f"{property_name} matched the expected value {expected!r}."
        return f"{property_name} was {actual!r}, but the expected value is {expected!r}."

    @staticmethod
    def _unknown_result(
        control: ControlDefinition,
        *,
        expected: Any,
        actual: Any,
        evidence: list[ControlEvidence],
        explanation: str,
    ) -> ControlEvaluationResult:
        return ControlEvaluationResult(
            control_id=control.control_id,
            control_name=control.name,
            result=ComplianceResult.UNKNOWN,
            expected=expected,
            actual=actual,
            evidence=evidence,
            explanation=explanation,
            remediation=dict(control.remediation),
        )


ControlEngine = DeterministicControlEngine
