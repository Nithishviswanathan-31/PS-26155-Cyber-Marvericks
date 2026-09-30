import type { SemanticMapping } from "./mappings";

export const SUPPORTED_MAPPING_PROPERTIES = [
  "management.ssh_enabled",
  "management.telnet_enabled",
  "logging.enabled",
  "password_protection.enabled",
  "time_sync.ntp_enabled",
] as const;

export type SupportedMappingProperty = (typeof SUPPORTED_MAPPING_PROPERTIES)[number];

export function isSupportedMappingProperty(property: string): property is SupportedMappingProperty {
  return (SUPPORTED_MAPPING_PROPERTIES as readonly string[]).includes(property);
}

export function canUserReview(role?: string | null): boolean {
  return role === "ADMIN" || role === "REVIEWER";
}

export type ProposalActionLabel = "Approve Mapping" | "Correct & Approve" | "Reject";

export function getProposalActions(
  status?: string | null,
  role?: string | null
): ProposalActionLabel[] {
  if (!canUserReview(role)) {
    return [];
  }
  const s = (status || "").toUpperCase();
  if (s === "NEEDS_REVIEW" || s === "PROPOSED") {
    return ["Approve Mapping", "Correct & Approve", "Reject"];
  }
  return [];
}

export function validateSemanticMapping(mapping: unknown): {
  valid: boolean;
  error?: string;
  mapping?: SemanticMapping;
} {
  if (typeof mapping !== "object" || mapping === null || Array.isArray(mapping)) {
    return { valid: false, error: "Mapping must be a valid JSON object." };
  }
  const entries = Object.entries(mapping);
  if (entries.length === 0) {
    return { valid: false, error: "Mapping must define at least one security property." };
  }
  const result: SemanticMapping = {};
  for (const [key, value] of entries) {
    if (!isSupportedMappingProperty(key)) {
      return {
        valid: false,
        error: `Property '${key}' is not supported. Supported properties: ${SUPPORTED_MAPPING_PROPERTIES.join(", ")}`,
      };
    }
    if (typeof value !== "boolean") {
      return {
        valid: false,
        error: `Property '${key}' must have a boolean value (true or false).`,
      };
    }
    result[key] = value;
  }
  return { valid: true, mapping: result };
}
