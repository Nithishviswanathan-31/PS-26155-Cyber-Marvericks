import {
  API_BASE_URL,
  AnalysisApiError,
  parseAnalysisResponse,
  type AnalysisResponse,
} from "./analyze";

export async function reanalyzeConfiguration(analysisId: string): Promise<AnalysisResponse> {
  let response: Response;
  try {
    response = await fetch(`${API_BASE_URL}/api/analyze/${encodeURIComponent(analysisId)}/reanalyze`, {
      method: "POST",
    });
  } catch {
    throw new AnalysisApiError("The re-analysis service could not be reached.");
  }

  let payload: unknown = null;
  try {
    payload = await response.json();
  } catch {
    payload = null;
  }
  if (!response.ok) {
    const detail = typeof payload === "object" && payload !== null && !Array.isArray(payload) && "detail" in payload && typeof payload.detail === "string"
      ? payload.detail
      : "The re-analysis request was rejected.";
    const code = typeof payload === "object" && payload !== null && !Array.isArray(payload) && "error_code" in payload && typeof payload.error_code === "string"
      ? payload.error_code : null;
    throw new AnalysisApiError(detail, response.status, code);
  }
  return parseAnalysisResponse(payload);
}
