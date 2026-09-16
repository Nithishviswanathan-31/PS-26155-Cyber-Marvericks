from ..domain.mapping import MappingStatus, MappingVersion, validate_semantic_mapping, pattern_signature, normalized_context
from ..domain.security_ir import MappingProvenance, RecognizedPattern, SecurityIR


class MappingApplicationError(ValueError):
    """Raised when an approved mapping cannot be safely applied."""


class MappingApplicationService:
    """Apply one active approved mapping to a deep-copied Security IR."""

    def apply(
        self,
        security_ir: SecurityIR,
        mapping: MappingVersion,
        *,
        pattern_id: str | None = None,
    ) -> SecurityIR:
        if mapping.status is not MappingStatus.APPROVED or not mapping.active:
            raise MappingApplicationError("Only ACTIVE + APPROVED mappings can be applied.")
        if mapping.approved_mapping is None or not mapping.approved_mapping:
            raise MappingApplicationError("The approved mapping has no semantic properties.")
        try:
            validate_semantic_mapping(mapping.approved_mapping)
        except (TypeError, ValueError) as exc:
            raise MappingApplicationError("The approved mapping failed validation.") from exc

        target_pattern_id = pattern_id or mapping.pattern_id
        pattern = next(
            (item for item in security_ir.unknown_patterns if item.pattern_id == target_pattern_id),
            None,
        )
        if pattern is None:
            raise MappingApplicationError("The mapping pattern is not present in the Security IR.")
        identity = mapping.identity
        if type(mapping.version) is not int or mapping.version < 1:
            raise MappingApplicationError("Invalid approved mapping version.")
        if mapping.vendor != security_ir.device.vendor:
            raise MappingApplicationError("Approved mapping vendor does not match the target.")
        if mapping.pattern_signature != pattern_signature(security_ir.device.vendor, pattern.raw_pattern):
            raise MappingApplicationError("Approved mapping signature does not match the target.")
        if identity is None:
            raise MappingApplicationError("Legacy mapping has no verified context; explicit re-approval is required.")
        if not normalized_context(pattern) or identity.context != normalized_context(pattern):
            raise MappingApplicationError("Approved mapping context does not match the target.")
        if pattern_signature(mapping.vendor, identity.source_pattern) != mapping.pattern_signature:
            raise MappingApplicationError("Approved source pattern does not match its signature.")
        if len(identity.target_properties) != len(set(identity.target_properties)) or set(identity.target_properties) != set(mapping.approved_mapping):
            raise MappingApplicationError("Approved mapping target properties do not match its identity.")
        if any(item.pattern_id == target_pattern_id for item in security_ir.recognized_patterns):
            raise MappingApplicationError("The pattern is already recognized in this Security IR.")

        enriched = security_ir.model_copy(deep=True)
        for property_name, value in mapping.approved_mapping.items():
            if property_name in enriched.normalized_properties:
                raise MappingApplicationError(
                    f"Refusing to overwrite existing normalized property '{property_name}'."
                )
            enriched.normalized_properties[property_name] = value
            enriched.mapping_provenance[property_name] = MappingProvenance(
                mapping_id=mapping.mapping_id,
                mapping_version=mapping.version,
                original_pattern=pattern.raw_pattern,
                original_location=pattern.location,
            )

        enriched.recognized_patterns.append(
            RecognizedPattern(
                pattern_id=target_pattern_id,
                raw_pattern=pattern.raw_pattern,
                mapping_id=mapping.mapping_id,
                mapping_version=mapping.version,
                source_location=pattern.location,
            )
        )
        return enriched


def apply_mapping_to_copy(
    security_ir: SecurityIR,
    mapping: MappingVersion,
    *,
    pattern_id: str | None = None,
) -> SecurityIR:
    """Functional convenience wrapper for the copy-based application service."""

    return MappingApplicationService().apply(security_ir, mapping, pattern_id=pattern_id)
