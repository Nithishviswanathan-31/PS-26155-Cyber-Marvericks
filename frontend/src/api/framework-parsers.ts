export type ComplianceResult =
  | "PASS"
  | "FAIL"
  | "PARTIAL"
  | "NOT_APPLICABLE"
  | "UNKNOWN";

export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonObject | JsonValue[];
export interface JsonObject {
  [key: string]: JsonValue;
}

export type ControlSeverity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export interface FrameworkMappingSummary {
  framework_name: string;
  framework_version?: string | null;
  reference_id: string;
  title?: string | null;
  description?: string | null;
  mapping_status?: "VERIFIED" | "PROTOTYPE" | "INTERNAL";
}

export interface ControlResultSummary {
  diagnostic_of?: string | null;
  control_id: string;
  control_name: string;
  result: ComplianceResult;
  expected: JsonValue;
  actual: JsonValue;
  explanation: string;
  severity?: ControlSeverity | null;
  category?: string | null;
  framework_mappings?: FrameworkMappingSummary[];
}

export const isComplianceResult = (v: unknown): v is ComplianceResult =>
  typeof v === "string" && ["PASS", "FAIL", "PARTIAL", "NOT_APPLICABLE", "UNKNOWN"].includes(v);

export const isSeverity = (v: unknown): v is ControlSeverity =>
  typeof v === "string" && ["LOW", "MEDIUM", "HIGH", "CRITICAL"].includes(v);

export const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

export const requiredString = (record: Record<string, unknown>, key: string): string | null => {
  const value = record[key];
  return typeof value === "string" && value.trim().length > 0 ? value : null;
};

export const optionalString = (record: Record<string, unknown>, key: string): string | null => {
  const value = record[key];
  return typeof value === "string" && value.trim().length > 0 ? value : null;
};

export const isJsonValue = (value: unknown): value is JsonValue => {
  if (value === null || typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
    return true;
  }
  if (Array.isArray(value)) {
    return value.every(isJsonValue);
  }
  if (isRecord(value)) {
    return Object.values(value).every(isJsonValue);
  }
  return false;
};

export const parseFrameworkMappings = (value: unknown): FrameworkMappingSummary[] => {
  if (!Array.isArray(value)) return [];
  const mappings: FrameworkMappingSummary[] = [];
  for (const item of value) {
    if (!isRecord(item)) continue;
    const name = requiredString(item, "framework_name");
    const ref = requiredString(item, "reference_id");
    if (!name || !ref) continue;
    mappings.push({
      framework_name: name,
      framework_version: optionalString(item, "framework_version"),
      reference_id: ref,
      title: optionalString(item, "title"),
      description: optionalString(item, "description"),
      mapping_status: (item.mapping_status === "PROTOTYPE" || item.mapping_status === "INTERNAL")
        ? item.mapping_status
        : "VERIFIED",
    });
  }
  return mappings;
};

export const parseResults = (value: unknown): ControlResultSummary[] | null => {
  if (!Array.isArray(value)) return null;
  const results: ControlResultSummary[] = [];
  for (const item of value) {
    if (!isRecord(item)) return null;
    const controlId = requiredString(item, "control_id");
    const controlName = requiredString(item, "control_name");
    const explanation = requiredString(item, "explanation");
    if (
      controlId === null ||
      controlName === null ||
      explanation === null ||
      !isComplianceResult(item.result) ||
      !isJsonValue(item.expected) ||
      !isJsonValue(item.actual)
    ) {
      return null;
    }
    results.push({
      control_id: controlId,
      control_name: controlName,
      diagnostic_of: optionalString(item, "diagnostic_of"),
      result: item.result,
      expected: item.expected,
      actual: item.actual,
      explanation,
      severity: isSeverity(item.severity) ? item.severity : null,
      category: optionalString(item, "category"),
      framework_mappings: parseFrameworkMappings(item.framework_mappings),
    });
  }
  return results;
};
