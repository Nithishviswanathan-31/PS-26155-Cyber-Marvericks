import { authFetch as fetch } from "../api/http";
import {
  ArrowForward,
  Assessment,
  CloudUpload,
  Layers,
  Security,
} from "@mui/icons-material";
import {
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  Grid,
  Stack,
  Typography,
  CircularProgress,
} from "@mui/material";
import { useEffect, useState } from "react";

import { API_BASE_URL, type AnalysisResponse } from "../api/analyze";

interface DashboardSummary {
  total_analyses?: number;
  total_devices?: number;
  overall_compliance_rate?: number;
  active_rules?: number;
  recent_analyses?: Array<{
    analysis_id?: string;
    filename?: string;
    vendor?: string;
    compliance_status?: string;
  }>;
  [key: string]: unknown;
}

interface DashboardPageProps {
  analyses: AnalysisResponse[];
  onAnalyze: (tab: "single" | "bulk") => void;
  onInspectAnalysis?: (analysisId: string) => void;
}

export default function DashboardPage({ analyses, onAnalyze, onInspectAnalysis }: DashboardPageProps) {
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const load = () => { setLoading(true); setError(null); fetch(`${API_BASE_URL}/api/dashboard/summary`).then((r) => r.ok ? r.json() : Promise.reject()).then(setSummary).catch(() => setError("Persisted dashboard metrics could not be loaded.")).finally(() => setLoading(false)); };
  useEffect(load, [analyses.length]);
  const metric = (key: string) => Number(summary?.[key] ?? 0);

  return (
    <Stack spacing={3}>
      <Box>
        <Typography variant="overline" color="secondary.main" letterSpacing={1.5}>
          OPERATIONS OVERVIEW
        </Typography>
        <Typography variant="h4" sx={{ mt: 1 }}>
          AI-Driven Multi-Vendor Network Security Compliance Auditor
        </Typography>
        <Typography color="text.secondary" sx={{ mt: 1, maxWidth: 720 }}>
          Upload a supported network configuration and follow the complete path from source text to deterministic results.
        </Typography>
      </Box>

      <Grid container spacing={2}>
        <Grid size={{ xs: 12, sm: 4 }}>
          <Card sx={{ height: "100%" }}>
            <CardContent>
              <Stack direction="row" justifyContent="space-between" alignItems="flex-start">
                <Box>
                  <Typography color="text.secondary" variant="body2">
                    Persisted analyses
                  </Typography>
                  <Typography variant="h3" sx={{ mt: 1 }}>
                    {loading ? <CircularProgress size={30} /> : metric("total_analyses")}
                  </Typography>
                </Box>
                <Assessment color="primary" />
              </Stack>
            </CardContent>
          </Card>
        </Grid>
        <Grid size={{ xs: 12, sm: 4 }}>
          <Card sx={{ height: "100%" }}>
            <CardContent>
              <Stack direction="row" justifyContent="space-between" alignItems="flex-start">
                <Box>
                  <Typography color="text.secondary" variant="body2">
                    Independent findings
                  </Typography>
                  <Typography variant="h5" sx={{ mt: 1 }}>
                    {loading ? "Loading…" : `${metric("pass_findings")} pass · ${metric("fail_findings")} fail · ${metric("unknown_findings")} unknown`}
                  </Typography>
                </Box>
                <Security color="secondary" />
              </Stack>
            </CardContent>
          </Card>
        </Grid>
        <Grid size={{ xs: 12, sm: 4 }}>
          <Card sx={{ height: "100%", bgcolor: "rgba(37,208,177,0.08)" }}>
            <CardContent>
              <Typography color="text.secondary" variant="body2">
                Current demo scope
              </Typography>
              <Stack direction="row" spacing={1} alignItems="center" sx={{ mt: 1 }}>
                <Chip label="Cisco · FortiGate · Palo Alto · AstraNet" color="secondary" size="small" />
              </Stack>
              <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
                File-based prototype · deterministic results · simulation only
              </Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {error && <Card><CardContent><Typography color="error.main">{error}</Typography><Button sx={{ mt: 1 }} onClick={load}>Retry</Button></CardContent></Card>}
      {!loading && !error && <Card variant="outlined"><CardContent><Stack direction="row" justifyContent="space-between"><Typography variant="subtitle1" fontWeight={700}>Persisted audit inventory</Typography><Button size="small" onClick={load}>Refresh</Button></Stack><Grid container spacing={1.5} sx={{ mt: 1 }}>{[["Devices","total_devices"],["Configurations","total_configurations"],["Batches","batch_analyses"],["Active knowledge","active_knowledge_entries"]].map(([label,key])=><Grid key={key} size={{xs:6,sm:3}}><Typography variant="caption" color="text.secondary">{label}</Typography><Typography variant="h6">{metric(key)}</Typography></Grid>)}</Grid><Typography variant="caption" color="text.secondary">Stored root-control findings only; CTRL-005 and CTRL-006 are diagnostic rows and do not inflate independent coverage.</Typography></CardContent></Card>}

      <Card variant="outlined">
        <CardContent>
          <Typography variant="subtitle1" fontWeight={700}>
            Demonstration paths
          </Typography>
          <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap sx={{ mt: 1.25 }}>
            <Chip label="Cisco → Non-Compliant" size="small" variant="outlined" />
            <Chip label="FortiGate → Compliant" size="small" variant="outlined" />
            <Chip label="Palo Alto → Mixed" size="small" variant="outlined" />
            <Chip label="AstraNet → Unknown → Learning" size="small" variant="outlined" />
          </Stack>
        </CardContent>
      </Card>

      <Card sx={{ border: "1px solid rgba(110,168,254,0.25)" }}>
        <CardContent sx={{ p: { xs: 2.5, md: 3.5 } }}>
          <Typography variant="h6" fontWeight={700} gutterBottom>
            Start an audit
          </Typography>
          <Typography color="text.secondary" sx={{ mb: 2 }}>
            Upload a prepared demo configuration to generate a deterministic compliance report, traceable evidence, and an exportable PDF.
          </Typography>
          <Stack direction={{ xs: "column", sm: "row" }} spacing={2}>
            <Button
              variant="contained"
              startIcon={<CloudUpload />}
              endIcon={<ArrowForward />}
              onClick={() => onAnalyze("single")}
            >
              Single Device Audit
            </Button>
            <Button
              variant="outlined"
              startIcon={<Layers />}
              endIcon={<ArrowForward />}
              onClick={() => onAnalyze("bulk")}
            >
              Bulk Fleet Audit
            </Button>
          </Stack>
        </CardContent>
      </Card>

      {summary?.recent_analyses && summary.recent_analyses.length > 0 && (() => {
        const lastAnalysis = summary.recent_analyses[0];
        return (
          <Card>
            <CardContent>
              <Stack direction="row" justifyContent="space-between" alignItems="center">
                <Typography variant="subtitle1" fontWeight={700}>
                  Last analysis
                </Typography>
                {onInspectAnalysis && lastAnalysis.analysis_id && (
                  <Button
                    size="small"
                    variant="outlined"
                    onClick={() => onInspectAnalysis(lastAnalysis.analysis_id!)}
                  >
                    Inspect Analysis
                  </Button>
                )}
              </Stack>
              <Stack direction={{ xs: "column", sm: "row" }} spacing={1} sx={{ mt: 1 }}>
                <Chip label={lastAnalysis.filename ?? "analysis"} size="small" />
                {lastAnalysis.vendor && <Chip label={lastAnalysis.vendor} size="small" variant="outlined" />}
                {lastAnalysis.analysis_id && <Chip label={lastAnalysis.analysis_id} size="small" variant="outlined" />}
              </Stack>
            </CardContent>
          </Card>
        );
      })()}

      {!loading && !error && metric("total_analyses") === 0 && (
        <Typography color="text.secondary">
          No analyses yet. Upload a configuration to begin.
        </Typography>
      )}
    </Stack>
  );
}
