import { API_BASE_URL } from "./analyze";

export class ReportApiError extends Error {
  status: number | null;
  code: string | null;

  constructor(message: string, status: number | null = null, code: string | null = null) {
    super(message);
    this.name = "ReportApiError";
    this.status = status;
    this.code = code;
  }
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

export async function generatePdfReport(analysisId: string): Promise<Blob> {
  let response: Response;
  try {
    response = await fetch(`${API_BASE_URL}/api/reports/${encodeURIComponent(analysisId)}/pdf`);
  } catch {
    throw new ReportApiError("The report service could not be reached.");
  }

  if (!response.ok) {
    let payload: unknown = null;
    try {
      payload = await response.json();
    } catch {
      payload = null;
    }
    const detail = isRecord(payload) && typeof payload.detail === "string"
      ? payload.detail
      : "The PDF report could not be generated.";
    const code = isRecord(payload) && typeof payload.error_code === "string" ? payload.error_code : null;
    throw new ReportApiError(detail, response.status, code);
  }

  const contentType = response.headers.get("content-type") ?? "";
  if (!contentType.toLowerCase().includes("application/pdf")) {
    throw new ReportApiError("The report response was not a PDF.", response.status);
  }
  return response.blob();
}

export function downloadPdf(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}
