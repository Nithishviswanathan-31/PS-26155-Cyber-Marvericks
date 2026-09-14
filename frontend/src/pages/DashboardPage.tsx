import {
  ArrowForward,
  Assessment,
  CloudUpload,
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
} from "@mui/material";

import type { AnalysisResponse } from "../api/analyze";

interface DashboardPageProps {
  analyses: AnalysisResponse[];
  onAnalyze: () => void;
}

export default function DashboardPage({ analyses, onAnalyze }: DashboardPageProps) {
  const lastAnalysis = analyses.at(-1);
  const passCount = lastAnalysis?.results.filter((item) => item.result === "PASS").length ?? 0;
  const failCount = lastAnalysis?.results.filter((item) => item.result === "FAIL").length ?? 0;

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
                    Session analyses
                  </Typography>
                  <Typography variant="h3" sx={{ mt: 1 }}>
                    {analyses.length}
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
                    Last result
                  </Typography>
                  <Typography variant="h5" sx={{ mt: 1 }}>
                    {lastAnalysis ? `${passCount} pass · ${failCount} fail` : "No analysis yet"}
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

      <Card variant="outlined">
        <CardContent>
          <Typography variant="subtitle1" fontWeight={700}>
            Demonstration paths
          </Typography>
          <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap sx={{ mt: 1.25 }}>
            <Chip label="Compliance Findings" size="small" variant="outlined" />
            <Chip label="Adaptive Learning" size="small" variant="outlined" />
            <Chip label="Remediation Simulation" size="small" variant="outlined" />
            <Chip label="Evidence-first PDF" size="small" variant="outlined" />
          </Stack>
        </CardContent>
      </Card>

      <Card sx={{ border: "1px solid rgba(110,168,254,0.25)" }}>
        <CardContent sx={{ p: { xs: 2.5, md: 3.5 } }}>
          <Stack direction={{ xs: "column", md: "row" }} spacing={3} alignItems={{ md: "center" }}>
            <Box sx={{ flexGrow: 1 }}>
              <Stack direction="row" spacing={1.5} alignItems="center">
                <CloudUpload color="primary" />
                <Typography variant="h6" fontWeight={700}>
                  Start a configuration analysis
                </Typography>
              </Stack>
              <Typography color="text.secondary" sx={{ mt: 1 }}>
                Upload a prepared demo configuration to generate Security IR, deterministic controls, and traceable evidence.
              </Typography>
            </Box>
            <Button variant="contained" endIcon={<ArrowForward />} onClick={onAnalyze}>
              Analyze Configuration
            </Button>
          </Stack>
        </CardContent>
      </Card>

      {lastAnalysis && (
        <Card>
          <CardContent>
            <Typography variant="subtitle1" fontWeight={700}>
              Last analysis
            </Typography>
            <Stack direction={{ xs: "column", sm: "row" }} spacing={1} sx={{ mt: 1 }}>
              <Chip label={lastAnalysis.filename} size="small" />
              <Chip label={lastAnalysis.vendor} size="small" variant="outlined" />
              <Chip label={lastAnalysis.analysis_id} size="small" variant="outlined" />
            </Stack>
          </CardContent>
        </Card>
      )}

      {!lastAnalysis && (
        <Typography color="text.secondary">
          No analyses yet. Upload a configuration to begin.
        </Typography>
      )}
    </Stack>
  );
}
