import { authFetch as fetch } from "./http";
export {
  type ControlSeverity,
  type FrameworkMappingSummary,
  isSeverity,
  parseFrameworkMappings,
  parseResults,
} from "./framework-parsers";
import {
  type ControlSeverity,
  type FrameworkMappingSummary,
  parseResults,
} from "./framework-parsers";
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

export interface AnalysisDevice {
  hostname: string | null;
  version: string | null;
  device_model: string | null;
  serial_number: string | null;
  device_id: string | null;
  platform: string | null;
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

export interface EvidenceRecord {
  property: string;
  expected: JsonValue;
  actual: JsonValue;
  result: ComplianceResult;
  source_file: string | null;
  line_start: number | null;
  line_end: number | null;
  raw_excerpt: string | null;
  explanation: string;
  control_id: string | null;
  control_name: string | null;
  vendor: string | null;
  configuration_version: string | null;
  condition_result: ComplianceResult | null;
  control_explanation: string | null;
  evidence_source: string | null;
  mapping_id: string | null;
  mapping_version: number | null;
  original_pattern: string | null;
  original_source_file: string | null;
  original_line_start: number | null;
  original_line_end: number | null;
  original_raw_excerpt: string | null;
  simulation_id: string | null;
  remediation_id: string | null;
  original_analysis_id: string | null;
  before_value: JsonValue;
  after_value: JsonValue;
}

export interface UnknownPatternSummary {
  pattern_id: string;
  raw_pattern: string;
  status: string;
  source_file: string | null;
  line_start: number | null;
  line_end: number | null;
  reason: string | null;
  context: string | null;
}

export interface AnalysisResponse {
  configuration?: { configuration_id: string; device_id: string; content_sha256: string; parser_status: string } | null;
  analysis_id: string;
  filename: string;
  vendor: string;
  device: AnalysisDevice;
  results: ControlResultSummary[];
  evidence: EvidenceRecord[];
  unknown_patterns: UnknownPatternSummary[];
  recognized_patterns: RecognizedPatternSummary[];
  parent_analysis_id: string | null;
  reanalyzed: boolean;
  mapping_id: string | null;
  mapping_version: number | null;
  reanalyzed_at: string | null;
  message: string | null;
}

export interface BatchItem {
  batch_item_id: string;
  source_filename: string;
  configuration_id: string | null;
  device_id: string | null;
  analysis_id: string | null;
  content_sha256: string | null;
  processing_status: "QUEUED" | "PROCESSING" | "COMPLETED" | "FAILED" | "DUPLICATE";
  error_code: string | null;
  error_message: string | null;
  duplicate_of_configuration_id: string | null;
  compliance_status: "PASS" | "FAIL" | "UNKNOWN" | "MIXED" | null;
  vendor?: string | null;
  platform?: string | null;
  hostname?: string | null;
  device_model?: string | null;
  serial_number?: string | null;
  pass_count?: number;
  fail_count?: number;
  unknown_count?: number;
  not_applicable_count?: number;
}

export interface BatchSummary {
  total: number;
  processed: number;
  successful: number;
  failed: number;
  duplicates: number;
  pass_analyses: number;
  fail_analyses: number;
  unknown_analyses: number;
  vendors_detected?: string[];
  devices_analyzed?: string[];
  pass_count?: number;
  fail_count?: number;
  unknown_count?: number;
  not_applicable_count?: number;
}

export interface BatchAnalysis {
  batch_id: string;
  status: string;
  total_items: number;
  processed_items: number;
  successful_items: number;
  failed_items: number;
  duplicate_items: number;
  summary: BatchSummary;
  created_at?: string;
  updated_at?: string;
}

export interface RecognizedPatternSummary {
  pattern_id: string;
  state: string;
  original_status: string;
  raw_pattern: string;
  mapping_id: string;
  mapping_version: number;
  source_location: {
    source_file: string;
    line_start: number | null;
    line_end: number | null;
    raw_excerpt: string | null;
  } | null;
}

export class AnalysisApiError extends Error {
  status: number | null;
  code: string | null;

  constructor(message: string, status: number | null = null, code: string | null = null) {
    super(message);
    this.name = "AnalysisApiError";
    this.status = status;
    this.code = code;
  }
}

export const API_BASE_URL = (import.meta.env.VITE_API_URL ?? "http://127.0.0.1:8000").replace(/\/$/, "");

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const isJsonValue = (value: unknown): value is JsonValue => {
  if (value === null || typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
    return true;
  }
  if (Array.isArray(value)) {
    return value.every(isJsonValue);
  }
  return isRecord(value) && Object.values(value).every(isJsonValue);
};

const isComplianceResult = (value: unknown): value is ComplianceResult =>
  value === "PASS" ||
  value === "FAIL" ||
  value === "PARTIAL" ||
  value === "NOT_APPLICABLE" ||
  value === "UNKNOWN";

const requiredString = (record: Record<string, unknown>, key: string): string | null =>
  typeof record[key] === "string" ? record[key] : null;

const optionalString = (record: Record<string, unknown>, key: string): string | null =>
  record[key] === null || record[key] === undefined || typeof record[key] === "string"
    ? (record[key] as string | null | undefined) ?? null
    : null;

const optionalNumber = (record: Record<string, unknown>, key: string): number | null =>
  record[key] === null || record[key] === undefined || typeof record[key] === "number"
    ? (record[key] as number | null | undefined) ?? null
    : null;

const parseDevice = (value: unknown): AnalysisDevice | null => {
  if (!isRecord(value)) return null;
  const hostname = optionalString(value, "hostname");
  const version = optionalString(value, "version");
  const deviceModel = optionalString(value, "device_model");
  const serialNumber = optionalString(value, "serial_number");
  const deviceId = optionalString(value, "device_id");
  const platform = optionalString(value, "platform");
  if (
    (value.hostname !== null && value.hostname !== undefined && hostname === null) ||
    (value.version !== null && value.version !== undefined && version === null) ||
    (value.device_model !== null && value.device_model !== undefined && deviceModel === null) ||
    (value.serial_number !== null && value.serial_number !== undefined && serialNumber === null) ||
    (value.device_id !== null && value.device_id !== undefined && deviceId === null)
    || (value.platform !== null && value.platform !== undefined && platform === null)
  ) {
    return null;
  }
  return {
    hostname,
    version,
    device_model: deviceModel,
    serial_number: serialNumber,
    device_id: deviceId,
    platform,
  };
};



const parseEvidence = (value: unknown): EvidenceRecord[] | null => {
  if (!Array.isArray(value)) return null;
  const evidence: EvidenceRecord[] = [];
  for (const item of value) {
    if (!isRecord(item)) return null;
    const property = requiredString(item, "property");
    const explanation = requiredString(item, "explanation");
    if (
      property === null ||
      explanation === null ||
      !isComplianceResult(item.result) ||
      !isJsonValue(item.expected) ||
      !isJsonValue(item.actual)
    ) {
      return null;
    }
    const conditionResult = item.condition_result;
    if (conditionResult !== null && conditionResult !== undefined && !isComplianceResult(conditionResult)) {
      return null;
    }
    evidence.push({
      property,
      expected: item.expected,
      actual: item.actual,
      result: item.result,
      source_file: optionalString(item, "source_file"),
      line_start: optionalNumber(item, "line_start"),
      line_end: optionalNumber(item, "line_end"),
      raw_excerpt: optionalString(item, "raw_excerpt"),
      explanation,
      control_id: optionalString(item, "control_id"),
      control_name: optionalString(item, "control_name"),
      vendor: optionalString(item, "vendor"),
      configuration_version: optionalString(item, "configuration_version"),
      condition_result: (conditionResult as ComplianceResult | null | undefined) ?? null,
      control_explanation: optionalString(item, "control_explanation"),
      evidence_source: optionalString(item, "evidence_source"),
      mapping_id: optionalString(item, "mapping_id"),
      mapping_version: optionalNumber(item, "mapping_version"),
      original_pattern: optionalString(item, "original_pattern"),
      original_source_file: optionalString(item, "original_source_file"),
      original_line_start: optionalNumber(item, "original_line_start"),
      original_line_end: optionalNumber(item, "original_line_end"),
      original_raw_excerpt: optionalString(item, "original_raw_excerpt"),
      simulation_id: optionalString(item, "simulation_id"),
      remediation_id: optionalString(item, "remediation_id"),
      original_analysis_id: optionalString(item, "original_analysis_id"),
      before_value: isJsonValue(item.before_value) ? item.before_value : null,
      after_value: isJsonValue(item.after_value) ? item.after_value : null,
    });
  }
  return evidence;
};

const parseUnknownPatterns = (value: unknown): UnknownPatternSummary[] | null => {
  if (!Array.isArray(value)) return null;
  const patterns: UnknownPatternSummary[] = [];
  for (const item of value) {
    if (!isRecord(item)) return null;
    const patternId = requiredString(item, "pattern_id");
    const rawPattern = requiredString(item, "raw_pattern");
    const status = requiredString(item, "status");
    if (patternId === null || rawPattern === null || status === null) return null;
    patterns.push({
      pattern_id: patternId,
      raw_pattern: rawPattern,
      status,
      source_file: optionalString(item, "source_file"),
      line_start: optionalNumber(item, "line_start"),
      line_end: optionalNumber(item, "line_end"),
      reason: optionalString(item, "reason"),
      context: optionalString(item, "context"),
    });
  }
  return patterns;
};

const parseRecognizedPatterns = (value: unknown): RecognizedPatternSummary[] | null => {
  if (!Array.isArray(value)) return null;
  const patterns: RecognizedPatternSummary[] = [];
  for (const item of value) {
    if (!isRecord(item)) return null;
    const patternId = requiredString(item, "pattern_id");
    const state = requiredString(item, "state");
    const originalStatus = requiredString(item, "original_status");
    const rawPattern = requiredString(item, "raw_pattern");
    const mappingId = requiredString(item, "mapping_id");
    const mappingVersion = optionalNumber(item, "mapping_version");
    if (patternId === null || state === null || originalStatus === null || rawPattern === null || mappingId === null || mappingVersion === null) return null;
    let sourceLocation: RecognizedPatternSummary["source_location"] = null;
    if (item.source_location !== null && item.source_location !== undefined) {
      if (!isRecord(item.source_location)) return null;
      const sourceFile = requiredString(item.source_location, "source_file");
      if (sourceFile === null) return null;
      sourceLocation = {
        source_file: sourceFile,
        line_start: optionalNumber(item.source_location, "line_start"),
        line_end: optionalNumber(item.source_location, "line_end"),
        raw_excerpt: optionalString(item.source_location, "raw_excerpt"),
      };
    }
    patterns.push({ pattern_id: patternId, state, original_status: originalStatus, raw_pattern: rawPattern, mapping_id: mappingId, mapping_version: mappingVersion, source_location: sourceLocation });
  }
  return patterns;
};

export const parseAnalysisResponse = (value: unknown): AnalysisResponse => {
  if (!isRecord(value)) throw new AnalysisApiError("The server returned an invalid analysis response.");
  const analysisId = requiredString(value, "analysis_id");
  const filename = requiredString(value, "filename");
  const vendor = requiredString(value, "vendor");
  const device = parseDevice(value.device);
  const results = parseResults(value.results);
  const evidence = parseEvidence(value.evidence);
  const unknownPatterns = parseUnknownPatterns(value.unknown_patterns);
  const recognizedPatterns = parseRecognizedPatterns(value.recognized_patterns ?? []);
  const reanalyzed = value.reanalyzed === undefined ? false : value.reanalyzed;
  const parentAnalysisId = optionalString(value, "parent_analysis_id");
  const mappingId = optionalString(value, "mapping_id");
  const mappingVersion = optionalNumber(value, "mapping_version");
  const reanalyzedAt = optionalString(value, "reanalyzed_at");
  const message = optionalString(value, "message");
  let configuration: AnalysisResponse["configuration"] = null;
  if (value.configuration !== undefined && value.configuration !== null) {
    const item = value.configuration;
    if (!isRecord(item) || typeof item.configuration_id !== "string" || typeof item.device_id !== "string" || typeof item.content_sha256 !== "string" || typeof item.parser_status !== "string") {
      throw new AnalysisApiError("The server returned invalid configuration context.");
    }
    configuration = { configuration_id: item.configuration_id, device_id: item.device_id, content_sha256: item.content_sha256, parser_status: item.parser_status };
  }
  if (
    analysisId === null ||
    filename === null ||
    vendor === null ||
    device === null ||
    results === null ||
    evidence === null ||
    unknownPatterns === null ||
    recognizedPatterns === null ||
    typeof reanalyzed !== "boolean"
  ) {
    throw new AnalysisApiError("The server returned an incomplete analysis response.");
  }
  return {
    analysis_id: analysisId,
    configuration,
    filename,
    vendor,
    device,
    results,
    evidence,
    unknown_patterns: unknownPatterns,
    recognized_patterns: recognizedPatterns,
    parent_analysis_id: parentAnalysisId,
    reanalyzed,
    mapping_id: mappingId,
    mapping_version: mappingVersion,
    reanalyzed_at: reanalyzedAt,
    message,
  };
};

export async function analyzeConfiguration(file: File): Promise<AnalysisResponse> {
  const formData = new FormData();
  formData.append("file", file);

  let response: Response;
  try {
    response = await fetch(`${API_BASE_URL}/api/analyze`, {
      method: "POST",
      body: formData,
    });
  } catch {
    throw new AnalysisApiError("The analysis service could not be reached.");
  }

  let payload: unknown = null;
  try {
    payload = await response.json();
  } catch {
    payload = null;
  }

  if (!response.ok) {
    const detail = isRecord(payload) && typeof payload.detail === "string" ? payload.detail : null;
    const code = isRecord(payload) && typeof payload.error_code === "string" ? payload.error_code : null;
    throw new AnalysisApiError(detail ?? "The server rejected the configuration.", response.status, code);
  }

  return parseAnalysisResponse(payload);
}

export async function analyzeBatch(files: File[]): Promise<{ batch: BatchAnalysis; items: BatchItem[] }> {
  const formData = new FormData();
  files.forEach((file) => formData.append("files", file));
  let response: Response;
  try {
    response = await fetch(`${API_BASE_URL}/api/batches/analyze`, { method: "POST", body: formData });
  } catch {
    throw new AnalysisApiError("The batch analysis service could not be reached.");
  }
  const payload: unknown = await response.json().catch(() => null);
  if (!response.ok || !isRecord(payload)) {
    const detail = isRecord(payload) && typeof payload.detail === "string" ? payload.detail : "The server rejected the batch.";
    throw new AnalysisApiError(detail, response.status, isRecord(payload) && typeof payload.error_code === "string" ? payload.error_code : null);
  }
  const batch = payload as unknown as BatchAnalysis;
  if (typeof batch.batch_id !== "string" || typeof batch.status !== "string" || typeof batch.summary !== "object" || batch.summary === null) {
    throw new AnalysisApiError("The server returned an invalid batch response.");
  }
  const itemsResponse = await fetch(`${API_BASE_URL}/api/batches/${batch.batch_id}/items`);
  const itemsPayload: unknown = await itemsResponse.json().catch(() => null);
  if (!itemsResponse.ok || !Array.isArray(itemsPayload)) throw new AnalysisApiError("The batch items could not be loaded.", itemsResponse.status);
  return { batch, items: itemsPayload as BatchItem[] };
}

export async function getAnalysis(analysisId: string): Promise<AnalysisResponse> {
  const response = await fetch(`${API_BASE_URL}/api/analyze/${encodeURIComponent(analysisId)}`);
  const payload: unknown = await response.json().catch(() => null);
  if (!response.ok) {
    const detail = isRecord(payload) && typeof payload.detail === "string" ? payload.detail : "The analysis could not be loaded.";
    throw new AnalysisApiError(detail, response.status);
  }
  return parseAnalysisResponse(payload);
}
