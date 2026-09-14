import { API_BASE_URL } from "./analyze";

export type MappingStatus = "SUGGESTED" | "APPROVED" | "REJECTED" | "INACTIVE";
export type SemanticMapping = Record<string, boolean>;

export interface CandidateMappingSuggestion {
  pattern_id: string;
  status: "SUGGESTED";
  confidence: number;
  semantic_mapping: SemanticMapping;
  reasoning: string;
  requires_human_approval: true;
}

export interface MappingVersion {
  mapping_id: string;
  pattern_id: string;
  vendor: string;
  pattern_signature: string;
  proposed_mapping: SemanticMapping;
  approved_mapping: SemanticMapping | null;
  status: MappingStatus;
  version: number;
  reviewer_id: string | null;
  action: string;
  created_at: string;
  updated_at: string;
  active: boolean;
}

export interface MappingDecisionResponse {
  pattern_id: string;
  pattern_status: "UNKNOWN";
  mapping: MappingVersion;
  compliance_impact: "UNCHANGED";
  message: string;
}

export class MappingApiError extends Error {
  status: number | null;
  code: string | null;

  constructor(message: string, status: number | null = null, code: string | null = null) {
    super(message);
    this.name = "MappingApiError";
    this.status = status;
    this.code = code;
  }
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const requestMapping = async <T>(path: string, init?: RequestInit): Promise<T> => {
  let response: Response;
  try {
    response = await fetch(`${API_BASE_URL}${path}`, init);
  } catch {
    throw new MappingApiError("The mapping service could not be reached.");
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
    throw new MappingApiError(detail ?? "The mapping request was rejected.", response.status, code);
  }
  if (!isRecord(payload)) throw new MappingApiError("The server returned an invalid mapping response.");
  return payload as T;
};

const jsonRequest = (body: object): RequestInit => ({
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify(body),
});

export async function suggestMapping(patternId: string): Promise<CandidateMappingSuggestion> {
  return requestMapping<CandidateMappingSuggestion>(
    `/api/mappings/${encodeURIComponent(patternId)}/suggest`,
    { method: "POST" },
  );
}

export async function approveMapping(
  patternId: string,
  semanticMapping: SemanticMapping,
  reviewerId: string,
): Promise<MappingDecisionResponse> {
  return requestMapping<MappingDecisionResponse>(
    `/api/mappings/${encodeURIComponent(patternId)}/approve`,
    jsonRequest({ reviewer_id: reviewerId, semantic_mapping: semanticMapping }),
  );
}

export async function correctAndApproveMapping(
  patternId: string,
  semanticMapping: SemanticMapping,
  reviewerId: string,
): Promise<MappingDecisionResponse> {
  return requestMapping<MappingDecisionResponse>(
    `/api/mappings/${encodeURIComponent(patternId)}/correct`,
    jsonRequest({ reviewer_id: reviewerId, semantic_mapping: semanticMapping }),
  );
}

export async function rejectMapping(
  patternId: string,
  reviewerId: string,
  reason?: string,
): Promise<MappingDecisionResponse> {
  return requestMapping<MappingDecisionResponse>(
    `/api/mappings/${encodeURIComponent(patternId)}/reject`,
    jsonRequest({ reviewer_id: reviewerId, reason }),
  );
}
