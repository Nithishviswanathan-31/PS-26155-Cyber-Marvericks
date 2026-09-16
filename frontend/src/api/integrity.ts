import { authJson } from "./http";

export type IntegrityStatus = "VALID" | "INVALID" | "NOT_FOUND" | "NOT_VERIFIED";
export interface IntegrityResult {
  status: IntegrityStatus;
  artifact_type?: string;
  artifact_id?: string;
  content_hash?: string;
  integrity_record_id?: string;
  record_count?: number;
  verified_at?: string;
  reason?: string;
}

export const verifyChain = () => authJson<IntegrityResult>("/api/integrity/chain");
export const verifyArtifact = (type: string, id: string) => authJson<IntegrityResult>(`/api/integrity/${encodeURIComponent(type)}/${encodeURIComponent(id)}/verify`, { method: "POST" });
