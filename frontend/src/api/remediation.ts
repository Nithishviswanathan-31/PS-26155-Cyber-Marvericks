import {
  API_BASE_URL,
  type ComplianceResult,
  type ControlResultSummary,
  type EvidenceRecord,
  type JsonValue,
} from "./analyze";

export interface RemediationDefinition {
  remediation_id: string;
  control_id: string;
  vendor: string;
  title: string;
  description: string;
  commands: string[];
  target_properties: string[];
  expected_state: Record<string, boolean>;
  risk_level: "LOW" | "MEDIUM" | "HIGH";
  simulation_only: true;
}

export interface RemediationResponse {
  analysis_id: string;
  simulation_only: true;
  remediations: RemediationDefinition[];
}

export interface SimulatedChange {
  property: string;
  before_value: JsonValue;
  after_value: JsonValue;
  change_source: "SIMULATED_REMEDIATION";
}

export interface SimulationResponse {
  simulation_id: string;
  parent_analysis_id: string;
  remediation_id: string;
  control_id: string;
  before_result: ComplianceResult;
  after_result: ComplianceResult;
  simulated_changes: SimulatedChange[];
  simulation_only: true;
  created_at: string;
  results: ControlResultSummary[];
  evidence: EvidenceRecord[];
  message: string;
}

export class RemediationApiError extends Error {
  status: number | null;
  code: string | null;

  constructor(message: string, status: number | null = null, code: string | null = null) {
    super(message);
    this.name = "RemediationApiError";
    this.status = status;
    this.code = code;
  }
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const request = async <T>(path: string, init?: RequestInit): Promise<T> => {
  let response: Response;
  try {
    response = await fetch(`${API_BASE_URL}${path}`, init);
  } catch {
    throw new RemediationApiError("The remediation service could not be reached.");
  }
  let payload: unknown = null;
  try {
    payload = await response.json();
  } catch {
    payload = null;
  }
  if (!response.ok) {
    const detail = isRecord(payload) && typeof payload.detail === "string" ? payload.detail : "The remediation request was rejected.";
    const code = isRecord(payload) && typeof payload.error_code === "string" ? payload.error_code : null;
    throw new RemediationApiError(detail, response.status, code);
  }
  return payload as T;
};

export async function getRemediations(analysisId: string): Promise<RemediationResponse> {
  return request<RemediationResponse>(`/api/remediation/${encodeURIComponent(analysisId)}`);
}

export async function simulateRemediation(analysisId: string, remediationId: string): Promise<SimulationResponse> {
  return request<SimulationResponse>(`/api/remediation/${encodeURIComponent(analysisId)}/simulate`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ remediation_id: remediationId }),
  });
}
