import { authFetch as fetch } from "./http";
import { API_BASE_URL } from "./analyze";

export interface FrameworkInfo {
  framework_id: string;
  display_name: string;
  version: string;
  description: string;
  verification_status: "SUPPORTED" | "PROTOTYPE";
  authoritative_url?: string | null;
}

export class FrameworkApiError extends Error {
  status: number | null;
  code: string | null;

  constructor(message: string, status: number | null = null, code: string | null = null) {
    super(message);
    this.name = "FrameworkApiError";
    this.status = status;
    this.code = code;
  }
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

export async function getFrameworks(): Promise<FrameworkInfo[]> {
  let response: Response;
  try {
    response = await fetch(`${API_BASE_URL}/api/frameworks`);
  } catch {
    throw new FrameworkApiError("The framework registry service could not be reached.");
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
      : "Failed to load compliance frameworks.";
    const code = isRecord(payload) && typeof payload.error_code === "string" ? payload.error_code : null;
    throw new FrameworkApiError(detail, response.status, code);
  }

  const data = (await response.json()) as unknown;
  if (!Array.isArray(data)) {
    throw new FrameworkApiError("Malformed response from framework registry.");
  }

  return data.map((item: Record<string, unknown>) => ({
    framework_id: String(item.framework_id || ""),
    display_name: String(item.display_name || ""),
    version: String(item.version || ""),
    description: String(item.description || ""),
    verification_status: (item.verification_status === "PROTOTYPE" ? "PROTOTYPE" : "SUPPORTED") as "SUPPORTED" | "PROTOTYPE",
    authoritative_url: typeof item.authoritative_url === "string" ? item.authoritative_url : null,
  }));
}
