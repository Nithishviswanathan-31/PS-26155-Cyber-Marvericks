import { useCallback, useEffect, useState } from "react";
import { Alert, Box, Button, Card, CardContent, Chip, CircularProgress, Stack, TextField, Typography } from "@mui/material";
import { type IntegrityResult, verifyArtifact, verifyChain } from "../api/integrity";

const tone = (status?: string) => status === "VALID" ? "success" : status === "INVALID" ? "error" : "default";

export function AnalysisIntegrityStatus({ analysisId }: { analysisId: string }) {
  const [result, setResult] = useState<IntegrityResult | null>(null);
  const [busy, setBusy] = useState(false);
  const verify = async () => {
    setBusy(true);
    try { setResult(await verifyArtifact("ANALYSIS", analysisId)); } finally { setBusy(false); }
  };
  useEffect(() => { void verify(); }, [analysisId]);
  return <Stack direction="row" spacing={1} alignItems="center" sx={{ mt: 1.5 }}>
    <Chip size="small" color={tone(result?.status)} label={`Integrity: ${result?.status ?? "NOT VERIFIED"}`} />
    <Button size="small" disabled={busy} onClick={() => void verify()}>{busy ? "Verifying…" : "Verify"}</Button>
  </Stack>;
}

export default function IntegrityPage() {
  const [chain, setChain] = useState<IntegrityResult | null>(null);
  const [artifactType, setArtifactType] = useState("ANALYSIS");
  const [artifactId, setArtifactId] = useState("");
  const [artifact, setArtifact] = useState<IntegrityResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const loadChain = useCallback(async () => {
    setLoading(true); setError(null);
    try { setChain(await verifyChain()); } catch { setError("Integrity verification could not be completed."); }
    finally { setLoading(false); }
  }, []);
  useEffect(() => { void loadChain(); }, [loadChain]);
  const checkArtifact = async () => {
    if (!artifactId.trim()) return;
    setError(null);
    try { setArtifact(await verifyArtifact(artifactType, artifactId.trim())); } catch { setError("Artifact verification could not be completed."); }
  };
  if (loading) return <Box sx={{ p: 4, textAlign: "center" }}><CircularProgress /></Box>;
  return <Stack spacing={2}>
    <Box><Typography variant="overline" color="secondary.main">AUDIT INTEGRITY</Typography><Typography variant="h4">Evidence Integrity Ledger</Typography><Typography color="text.secondary">Local tamper-evident hash chain. It verifies stored audit snapshots; it is not a public blockchain.</Typography></Box>
    {error ? <Alert severity="error">{error}</Alert> : null}
    <Card><CardContent><Stack direction={{ xs: "column", sm: "row" }} justifyContent="space-between" alignItems={{ sm: "center" }} spacing={1}><Box><Typography variant="subtitle2">Audit chain</Typography><Typography variant="body2" color="text.secondary">{chain?.record_count ?? 0} ledger records</Typography></Box><Chip label={chain?.status ?? "NOT VERIFIED"} color={tone(chain?.status)} /><Button onClick={() => void loadChain()}>Verify chain</Button></Stack>{chain?.verified_at ? <Typography variant="caption" color="text.secondary">Verified {new Date(chain.verified_at).toLocaleString()}</Typography> : null}</CardContent></Card>
    <Card><CardContent><Stack spacing={1.5}><Typography variant="subtitle2">Verify an audit artifact</Typography><Stack direction={{ xs: "column", sm: "row" }} spacing={1}><TextField select SelectProps={{ native: true }} label="Artifact type" value={artifactType} onChange={event => setArtifactType(event.target.value)}><option>ANALYSIS</option><option>CONFIGURATION</option><option>EVIDENCE</option><option>MAPPING_VERSION</option><option>AI_PROPOSAL</option><option>REMEDIATION_SIMULATION</option><option>REPORT</option></TextField><TextField fullWidth label="Artifact ID" value={artifactId} onChange={event => setArtifactId(event.target.value)} /><Button variant="contained" disabled={!artifactId.trim()} onClick={() => void checkArtifact()}>Verify</Button></Stack>{artifact ? <Alert severity={artifact.status === "VALID" ? "success" : artifact.status === "INVALID" ? "error" : "info"}>Integrity: {artifact.status}{artifact.reason ? ` — ${artifact.reason}` : ""}{artifact.content_hash ? <Typography component="span" variant="caption"> Hash: {artifact.content_hash.slice(0, 16)}…</Typography> : null}</Alert> : null}</Stack></CardContent></Card>
  </Stack>;
}
