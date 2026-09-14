import { useMemo, useRef, useState } from "react";

import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  Dialog,
  DialogContent,
  DialogTitle,
  Divider,
  Grid,
  IconButton,
  FormControlLabel,
  LinearProgress,
  Paper,
  Stack,
  Switch,
  TextField,
  Step,
  StepLabel,
  Stepper,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
  Typography,
} from "@mui/material";

import { Close, Description, Download, UploadFile } from "@mui/icons-material";

import {
  analyzeConfiguration,
  type AnalysisResponse,
  type ComplianceResult,
  type ControlResultSummary,
  type EvidenceRecord,
  AnalysisApiError,
} from "../api/analyze";

import {
  approveMapping,
  correctAndApproveMapping,
  MappingApiError,
  rejectMapping,
  suggestMapping,
  type CandidateMappingSuggestion,
  type MappingDecisionResponse,
  type SemanticMapping,
} from "../api/mappings";

import { reanalyzeConfiguration } from "../api/reanalysis";

import {
  getRemediations,
  RemediationApiError,
  simulateRemediation,
  type RemediationDefinition,
  type SimulationResponse,
} from "../api/remediation";

import {
  downloadPdf,
  generatePdfReport,
  ReportApiError,
} from "../api/reports";

type WorkflowState =
  | "IDLE"
  | "FILE_SELECTED"
  | "UPLOADING"
  | "SUCCESS"
  | "ERROR";

interface AnalyzeConfigurationPageProps {
  onAnalysisCompleted: (analysis: AnalysisResponse) => void;
}

const MAX_FILE_BYTES = 1 * 1024 * 1024;

const ALLOWED_EXTENSIONS = [".conf", ".cfg", ".txt"];

const formatBytes = (bytes: number): string => {
  if (bytes < 1024) return `${bytes} B`;
  return `${(bytes / 1024).toFixed(1)} KB`;
};

const formatValue = (value: unknown): string => {
  if (value === null || value === undefined) return "Not available";
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
};

const statusColor = (
  result: ComplianceResult
): "success" | "error" | "warning" | "info" | "default" => {
  if (result === "PASS") return "success";
  if (result === "FAIL") return "error";
  if (result === "UNKNOWN") return "warning";
  if (result === "PARTIAL") return "info";
  return "default";
};

const vendorLabel = (vendor: string): string => {
  if (vendor === "cisco_iosxe") return "Cisco IOS/IOS-XE";
  if (vendor === "fortigate_fortios") return "FortiGate/FortiOS";
  if (vendor === "paloalto_panos") return "Palo Alto/PAN-OS";
  if (vendor === "astranet") return "AstraNet (Synthetic)";
  return vendor;
};

const reanalyzingLabel = (busy: boolean): string =>
  busy ? "Re-analyzing…" : "Re-analyze";

const ASTRANET_TIMELINE = [
  "Detected",
  "UNKNOWN",
  "Suggestion Generated",
  "Human Approved",
  "Mapping Activated",
  "Re-analysis Requested",
  "Recognized",
  "Compliance Evaluated",
  "Evidence Generated",
];

const validateFile = (file: File): string | null => {
  const extension = file.name
    .slice(file.name.lastIndexOf("."))
    .toLowerCase();

  if (!ALLOWED_EXTENSIONS.includes(extension)) {
    return "Unsupported file type. Select a .conf, .cfg, or .txt configuration file.";
  }

  if (file.size === 0) {
    return "The selected file is empty.";
  }

  if (file.size > MAX_FILE_BYTES) {
    return "The selected file exceeds the 1 MB demo limit.";
  }

  return null;
};

export default function AnalyzeConfigurationPage({
  onAnalysisCompleted,
}: AnalyzeConfigurationPageProps) {
  const inputRef = useRef<HTMLInputElement>(null);

  const [workflowState, setWorkflowState] =
    useState<WorkflowState>("IDLE");

  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [analysis, setAnalysis] = useState<AnalysisResponse | null>(null);

  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const [selectedResult, setSelectedResult] =
    useState<ControlResultSummary | null>(null);

  const [isDragging, setIsDragging] = useState(false);

  const [candidate, setCandidate] =
    useState<CandidateMappingSuggestion | null>(null);

  const [reviewMapping, setReviewMapping] =
    useState<SemanticMapping>({});

  const [mappingDecision, setMappingDecision] =
    useState<MappingDecisionResponse | null>(null);

  const [mappingBusy, setMappingBusy] = useState(false);
  const [mappingError, setMappingError] = useState<string | null>(null);

  const [reviewerId, setReviewerId] = useState("demo-reviewer");

  const [reanalysis, setReanalysis] =
    useState<AnalysisResponse | null>(null);

  const [reanalysisBusy, setReanalysisBusy] = useState(false);
  const [reanalysisError, setReanalysisError] =
    useState<string | null>(null);

  const [remediations, setRemediations] =
    useState<RemediationDefinition[]>([]);

  const [remediationBusy, setRemediationBusy] = useState(false);
  const [remediationError, setRemediationError] =
    useState<string | null>(null);

  const [simulation, setSimulation] =
    useState<SimulationResponse | null>(null);

  const [simulationBusy, setSimulationBusy] = useState(false);

  const [reportBusy, setReportBusy] = useState(false);
  const [reportError, setReportError] = useState<string | null>(null);

  const isAstraNet = analysis?.vendor === "astranet";

  /*
   * IMPORTANT:
   * Keep the original analysis immutable.
   * When re-analysis exists, use it only as the currently displayed result.
   */
  const displayedAnalysis = reanalysis ?? analysis;

  const timelineStep = reanalysis
    ? ASTRANET_TIMELINE.length
    : reanalysisBusy
      ? 5
      : mappingDecision?.mapping.status === "APPROVED" &&
          mappingDecision.mapping.active
        ? 4
        : candidate
          ? 2
          : analysis
            ? 1
            : 0;

  /*
   * Evidence must follow whichever analysis is currently being displayed.
   * Before re-analysis: original analysis evidence.
   * After re-analysis: child/re-analysis evidence.
   */
  const selectedEvidence = useMemo<EvidenceRecord[]>(() => {
    if (!selectedResult || !displayedAnalysis) return [];

    return displayedAnalysis.evidence.filter(
      (item) => item.control_id === selectedResult.control_id
    );
  }, [displayedAnalysis, selectedResult]);

  const selectFile = (file: File | undefined) => {
    if (!file) return;

    const validationError = validateFile(file);

    if (validationError) {
      setSelectedFile(null);
      setAnalysis(null);
      setErrorMessage(validationError);
      setWorkflowState("ERROR");
      return;
    }

    setSelectedFile(file);
    setAnalysis(null);
    setCandidate(null);
    setReviewMapping({});
    setMappingDecision(null);
    setMappingError(null);
    setReanalysis(null);
    setReanalysisError(null);
    setRemediations([]);
    setRemediationError(null);
    setSimulation(null);
    setReportError(null);
    setSelectedResult(null);
    setErrorMessage(null);
    setWorkflowState("FILE_SELECTED");
  };

  const handleAnalyze = async () => {
    if (!selectedFile || workflowState === "UPLOADING") return;

    setWorkflowState("UPLOADING");
    setErrorMessage(null);

    try {
      const result = await analyzeConfiguration(selectedFile);

      setAnalysis(result);
      setCandidate(null);
      setReviewMapping({});
      setMappingDecision(null);
      setMappingError(null);
      setReanalysis(null);
      setReanalysisError(null);
      setSimulation(null);
      setReportError(null);
      setSelectedResult(null);
      setWorkflowState("SUCCESS");

      onAnalysisCompleted(result);

      setRemediationBusy(true);

      try {
        const remediationResponse = await getRemediations(
          result.analysis_id
        );

        setRemediations(remediationResponse.remediations);
      } catch (error: unknown) {
        setRemediationError(
          error instanceof RemediationApiError
            ? error.message
            : "Remediation recommendations could not be loaded."
        );
      } finally {
        setRemediationBusy(false);
      }
    } catch (error: unknown) {
      const message =
        error instanceof AnalysisApiError
          ? error.message
          : "The configuration could not be analyzed.";

      setErrorMessage(message);
      setWorkflowState("ERROR");
    }
  };

  const removeFile = () => {
    setSelectedFile(null);
    setAnalysis(null);
    setCandidate(null);
    setReviewMapping({});
    setMappingDecision(null);
    setMappingError(null);
    setReanalysis(null);
    setReanalysisError(null);
    setRemediations([]);
    setRemediationError(null);
    setSimulation(null);
    setReportError(null);
    setSelectedResult(null);
    setErrorMessage(null);
    setWorkflowState("IDLE");

    if (inputRef.current) {
      inputRef.current.value = "";
    }
  };

  const handleSuggest = async (patternId: string) => {
    setMappingBusy(true);
    setMappingError(null);

    try {
      const suggestion = await suggestMapping(patternId);

      setCandidate(suggestion);
      setReviewMapping({
        ...suggestion.semantic_mapping,
      });
    } catch (error: unknown) {
      setMappingError(
        error instanceof MappingApiError
          ? error.message
          : "The candidate suggestion could not be generated."
      );
    } finally {
      setMappingBusy(false);
    }
  };

  const handleMappingDecision = async (
    action: "approve" | "correct" | "reject"
  ) => {
    if (
      !candidate ||
      !analysis?.unknown_patterns[0] ||
      !reviewerId.trim() ||
      mappingBusy
    ) {
      return;
    }

    const patternId = analysis.unknown_patterns[0].pattern_id;

    setMappingBusy(true);
    setMappingError(null);

    try {
      const decision =
        action === "approve"
          ? await approveMapping(
              patternId,
              reviewMapping,
              reviewerId.trim()
            )
          : action === "correct"
            ? await correctAndApproveMapping(
                patternId,
                reviewMapping,
                reviewerId.trim()
              )
            : await rejectMapping(
                patternId,
                reviewerId.trim(),
                "Rejected during human review."
              );

      setMappingDecision(decision);
    } catch (error: unknown) {
      setMappingError(
        error instanceof MappingApiError
          ? error.message
          : "The mapping decision could not be stored."
      );
    } finally {
      setMappingBusy(false);
    }
  };

  const handleReanalyze = async () => {
    if (
      !analysis ||
      !mappingDecision ||
      mappingDecision.mapping.status !== "APPROVED" ||
      !mappingDecision.mapping.active ||
      reanalysisBusy
    ) {
      return;
    }

    setReanalysisBusy(true);
    setReanalysisError(null);

    try {
      const result = await reanalyzeConfiguration(
        analysis.analysis_id
      );

      /*
       * Store the child analysis separately.
       * Never mutate the original analysis.
       */
      setReanalysis(result);

      /*
       * Clear any previously selected original control.
       * The user can now select a control from the re-analysis table.
       */
      setSelectedResult(null);
    } catch (error: unknown) {
      setReanalysisError(
        error instanceof AnalysisApiError
          ? error.message
          : "The explicit re-analysis could not be completed."
      );
    } finally {
      setReanalysisBusy(false);
    }
  };

  const handleSimulate = async (
    remediation: RemediationDefinition
  ) => {
    if (!analysis || simulationBusy) return;

    setSimulationBusy(true);
    setRemediationError(null);

    try {
      setSimulation(
        await simulateRemediation(
          analysis.analysis_id,
          remediation.remediation_id
        )
      );
    } catch (error: unknown) {
      setRemediationError(
        error instanceof RemediationApiError
          ? error.message
          : "The remediation simulation could not be completed."
      );
    } finally {
      setSimulationBusy(false);
    }
  };

  const handleGenerateReport = async (
    analysisId: string,
    suggestedName: string
  ) => {
    if (reportBusy) return;

    setReportBusy(true);
    setReportError(null);

    try {
      const pdf = await generatePdfReport(analysisId);

      const baseName = suggestedName
        .replace(/\.[^.]+$/, "")
        .replace(/[^a-zA-Z0-9_-]+/g, "-");

      downloadPdf(
        pdf,
        `ps26155-${baseName || "analysis"}-report.pdf`
      );
    } catch (error: unknown) {
      setReportError(
        error instanceof ReportApiError
          ? error.message
          : "The PDF report could not be generated."
      );
    } finally {
      setReportBusy(false);
    }
  };

  return (
    <Stack spacing={3}>
      <Box>
        <Typography
          variant="overline"
          color="secondary.main"
          letterSpacing={1.5}
        >
          CONFIGURATION ANALYSIS
        </Typography>

        <Typography variant="h4" sx={{ mt: 1 }}>
          Upload and analyze
        </Typography>

        <Typography
          color="text.secondary"
          sx={{ mt: 1, maxWidth: 760 }}
        >
          Submit one configuration file. The backend will detect a
          supported vendor, normalize security properties, evaluate
          deterministic controls, and return source evidence.
        </Typography>
      </Box>

      <Alert severity="info" icon={<Description />}>
        <strong>
          Supported in current demo: Cisco IOS/IOS-XE,
          FortiGate/FortiOS, Palo Alto/PAN-OS, and AstraNet
          (synthetic)
        </strong>
        . AstraNet mapping approval and explicit re-analysis are
        demonstrated separately.
      </Alert>

      <Alert severity="warning">
        Demo/Synthetic AstraNet data · No production device
        modification · AI suggestions require human approval ·
        Compliance results are deterministic.
      </Alert>

      <Card>
        <CardContent sx={{ p: { xs: 2, md: 3 } }}>
          <Stack spacing={2.5}>
            <Box
              onDragOver={(event) => {
                event.preventDefault();
                setIsDragging(true);
              }}
              onDragLeave={() => setIsDragging(false)}
              onDrop={(event) => {
                event.preventDefault();
                setIsDragging(false);
                selectFile(event.dataTransfer.files[0]);
              }}
              sx={{
                border: "1px dashed",
                borderColor: isDragging
                  ? "secondary.main"
                  : "rgba(110,168,254,0.45)",
                bgcolor: isDragging
                  ? "rgba(37,208,177,0.08)"
                  : "rgba(110,168,254,0.04)",
                borderRadius: 3,
                p: { xs: 3, md: 5 },
                textAlign: "center",
                transition: "all 160ms ease",
              }}
            >
              <UploadFile
                sx={{
                  fontSize: 42,
                  color: "primary.main",
                }}
              />

              <Typography variant="h6" sx={{ mt: 1 }}>
                Drop a supported configuration here
              </Typography>

              <Typography
                color="text.secondary"
                sx={{ mt: 0.75 }}
              >
                or select a prepared `.conf`, `.cfg`, or `.txt`
                file
              </Typography>

              <Button
                variant="outlined"
                sx={{ mt: 2 }}
                onClick={() => inputRef.current?.click()}
              >
                Browse files
              </Button>

              <input
                ref={inputRef}
                hidden
                type="file"
                accept=".conf,.cfg,.txt,text/plain"
                onChange={(event) =>
                  selectFile(event.target.files?.[0])
                }
              />
            </Box>

            {selectedFile && (
              <Paper variant="outlined" sx={{ p: 2 }}>
                <Stack
                  direction={{ xs: "column", sm: "row" }}
                  spacing={1.5}
                  alignItems={{ sm: "center" }}
                >
                  <Box sx={{ flexGrow: 1 }}>
                    <Typography fontWeight={700}>
                      {selectedFile.name}
                    </Typography>

                    <Typography
                      variant="body2"
                      color="text.secondary"
                    >
                      {formatBytes(selectedFile.size)} · ready
                      for analysis
                    </Typography>
                  </Box>

                  <Button
                    size="small"
                    onClick={() => inputRef.current?.click()}
                  >
                    Replace
                  </Button>

                  <Button
                    size="small"
                    color="inherit"
                    onClick={removeFile}
                  >
                    Remove
                  </Button>
                </Stack>
              </Paper>
            )}

            {workflowState === "UPLOADING" && (
              <Box>
                <Stack
                  direction="row"
                  justifyContent="space-between"
                  sx={{ mb: 0.75 }}
                >
                  <Typography
                    variant="body2"
                    color="text.secondary"
                  >
                    Uploading and analyzing configuration…
                  </Typography>

                  <Typography
                    variant="body2"
                    color="secondary.main"
                  >
                    Processing
                  </Typography>
                </Stack>

                <LinearProgress />
              </Box>
            )}

            {errorMessage && (
              <Alert severity="error">{errorMessage}</Alert>
            )}

            <Stack direction="row" justifyContent="flex-end">
              <Button
                variant="contained"
                size="large"
                disabled={
                  !selectedFile ||
                  workflowState === "UPLOADING"
                }
                onClick={handleAnalyze}
              >
                {workflowState === "UPLOADING"
                  ? "Analyzing…"
                  : "Analyze Configuration"}
              </Button>
            </Stack>
          </Stack>
        </CardContent>
      </Card>

      {analysis && (
        <Stack spacing={2.5}>
          {isAstraNet && (
            <Card
              sx={{
                border:
                  "1px solid rgba(255,183,77,0.42)",
              }}
            >
              <CardContent>
                <Typography
                  variant="overline"
                  color="secondary.main"
                  letterSpacing={1.2}
                >
                  ASTRA NET DEMO TIMELINE
                </Typography>

                <Stepper
                  activeStep={timelineStep}
                  alternativeLabel
                  sx={{ mt: 2, overflowX: "auto" }}
                >
                  {ASTRANET_TIMELINE.map((step) => (
                    <Step key={step}>
                      <StepLabel>{step}</StepLabel>
                    </Step>
                  ))}
                </Stepper>
              </CardContent>
            </Card>
          )}

          <Card
            sx={{
              border:
                "1px solid rgba(37,208,177,0.3)",
            }}
          >
            <CardContent>
              <Stack
                direction={{ xs: "column", md: "row" }}
                spacing={2}
                justifyContent="space-between"
              >
                <Box>
                  <Typography
                    variant="overline"
                    color="secondary.main"
                    letterSpacing={1.2}
                  >
                    ORIGINAL ANALYSIS
                  </Typography>

                  <Typography
                    variant="h5"
                    sx={{ mt: 0.75 }}
                  >
                    {analysis.filename}
                  </Typography>
                </Box>

                <Chip
                  label={vendorLabel(analysis.vendor)}
                  color="secondary"
                />
              </Stack>

              <Grid container spacing={2} sx={{ mt: 1 }}>
                <Grid size={{ xs: 12, sm: 4 }}>
                  <Typography
                    variant="caption"
                    color="text.secondary"
                  >
                    Vendor
                  </Typography>

                  <Typography sx={{ mt: 0.5 }}>
                    {vendorLabel(analysis.vendor)}
                  </Typography>
                </Grid>

                <Grid size={{ xs: 12, sm: 4 }}>
                  <Typography
                    variant="caption"
                    color="text.secondary"
                  >
                    Hostname
                  </Typography>

                  <Typography sx={{ mt: 0.5 }}>
                    {analysis.device.hostname ??
                      "Not available"}
                  </Typography>
                </Grid>

                <Grid size={{ xs: 12, sm: 4 }}>
                  <Typography
                    variant="caption"
                    color="text.secondary"
                  >
                    Version
                  </Typography>

                  <Typography sx={{ mt: 0.5 }}>
                    {analysis.device.version ??
                      "Not available"}
                  </Typography>
                </Grid>
              </Grid>

              <Divider sx={{ my: 2 }} />

              <Typography
                variant="caption"
                color="text.secondary"
              >
                Analysis ID
              </Typography>

              <Typography
                variant="body2"
                sx={{
                  mt: 0.5,
                  fontFamily: "monospace",
                  wordBreak: "break-all",
                }}
              >
                {analysis.analysis_id}
              </Typography>

              <Button
                variant="outlined"
                startIcon={<Download />}
                onClick={() =>
                  handleGenerateReport(
                    analysis.analysis_id,
                    analysis.filename
                  )
                }
                disabled={reportBusy}
                sx={{ mt: 2 }}
              >
                {reportBusy
                  ? "Generating report…"
                  : "Generate PDF Report"}
              </Button>
            </CardContent>
          </Card>

          {analysis.unknown_patterns.length > 0 && (
            <Card
              sx={{
                border:
                  "1px solid rgba(255,183,77,0.42)",
              }}
            >
              <CardContent>
                <Stack spacing={2}>
                  <Box>
                    <Typography
                      variant="overline"
                      color="warning.main"
                      letterSpacing={1.2}
                    >
                      UNKNOWN PATTERN
                    </Typography>

                    <Typography
                      variant="h6"
                      fontWeight={700}
                      sx={{ mt: 0.5 }}
                    >
                      Unrecognized configuration structure
                    </Typography>

                    <Typography
                      variant="body2"
                      color="text.secondary"
                      sx={{ mt: 0.5 }}
                    >
                      This configuration structure has not been
                      assigned an approved normalized security
                      meaning.
                    </Typography>
                  </Box>

                  {analysis.unknown_patterns.map(
                    (pattern) => (
                      <Paper
                        key={pattern.pattern_id}
                        variant="outlined"
                        sx={{
                          p: 2,
                          bgcolor:
                            "rgba(255,183,77,0.04)",
                        }}
                      >
                        <Stack spacing={1.25}>
                          <Stack
                            direction={{
                              xs: "column",
                              sm: "row",
                            }}
                            spacing={1}
                            alignItems={{
                              sm: "center",
                            }}
                          >
                            <Chip
                              label="UNKNOWN"
                              color="warning"
                              size="small"
                            />

                            <Typography
                              variant="body2"
                              sx={{
                                fontFamily:
                                  "monospace",
                              }}
                            >
                              {pattern.pattern_id}
                            </Typography>
                          </Stack>

                          <Box
                            component="pre"
                            sx={{
                              mt: 0,
                              mb: 0,
                              p: 1.5,
                              overflowX: "auto",
                              borderRadius: 1.5,
                              bgcolor: "#06111f",
                              color: "#b7d8ff",
                              fontFamily: "monospace",
                              fontSize: "0.85rem",
                            }}
                          >
                            {pattern.raw_pattern}
                          </Box>

                          <Typography variant="body2">
                            <strong>Source:</strong>{" "}
                            {pattern.source_file ??
                              "Not available"}{" "}
                            · <strong>Line:</strong>{" "}
                            {pattern.line_start ??
                              "Not available"}
                          </Typography>

                          {pattern.reason && (
                            <Typography
                              variant="body2"
                              color="text.secondary"
                            >
                              <strong>Reason:</strong>{" "}
                              {pattern.reason}
                            </Typography>
                          )}

                          {!mappingDecision &&
                            !candidate && (
                              <Button
                                variant="outlined"
                                onClick={() =>
                                  handleSuggest(
                                    pattern.pattern_id
                                  )
                                }
                                disabled={mappingBusy}
                              >
                                {mappingBusy
                                  ? "Generating candidate…"
                                  : "Generate candidate mapping"}
                              </Button>
                            )}
                        </Stack>
                      </Paper>
                    )
                  )}

                  {candidate && !mappingDecision && (
                    <Paper
                      variant="outlined"
                      sx={{
                        p: 2,
                        bgcolor:
                          "rgba(110,168,254,0.05)",
                      }}
                    >
                      <Stack spacing={2}>
                        <Box>
                          <Typography
                            variant="overline"
                            color="secondary.main"
                            letterSpacing={1.2}
                          >
                            AI SUGGESTION
                          </Typography>

                          <Typography
                            variant="subtitle1"
                            fontWeight={700}
                          >
                            HUMAN APPROVAL REQUIRED
                          </Typography>

                          <Typography
                            variant="body2"
                            color="text.secondary"
                            sx={{ mt: 0.5 }}
                          >
                            Candidate interpretation only.
                            Human approval is required; this
                            does not change compliance.
                          </Typography>
                        </Box>

                        <Typography variant="body2">
                          <strong>Confidence:</strong>{" "}
                          {(candidate.confidence * 100).toFixed(
                            0
                          )}
                          % demo suggestion value
                        </Typography>

                        <Typography variant="body2">
                          <strong>Reasoning:</strong>{" "}
                          {candidate.reasoning}
                        </Typography>

                        <Stack spacing={0.5}>
                          {Object.entries(
                            reviewMapping
                          ).map(
                            ([property, value]) => (
                              <FormControlLabel
                                key={property}
                                control={
                                  <Switch
                                    checked={value}
                                    onChange={(event) =>
                                      setReviewMapping(
                                        (current) => ({
                                          ...current,
                                          [property]:
                                            event.target
                                              .checked,
                                        })
                                      )
                                    }
                                  />
                                }
                                label={
                                  <Typography
                                    sx={{
                                      fontFamily:
                                        "monospace",
                                    }}
                                  >
                                    {property} ={" "}
                                    {String(value)}
                                  </Typography>
                                }
                              />
                            )
                          )}
                        </Stack>

                        <TextField
                          label="Reviewer identity"
                          value={reviewerId}
                          onChange={(event) =>
                            setReviewerId(
                              event.target.value
                            )
                          }
                          size="small"
                          helperText="Demo reviewer identity; approval is explicit."
                        />

                        <Stack
                          direction={{
                            xs: "column",
                            sm: "row",
                          }}
                          spacing={1}
                        >
                          <Button
                            variant="contained"
                            onClick={() =>
                              handleMappingDecision(
                                "approve"
                              )
                            }
                            disabled={
                              mappingBusy ||
                              !reviewerId.trim()
                            }
                          >
                            {mappingBusy
                              ? "Approving…"
                              : "Approve"}
                          </Button>

                          <Button
                            variant="outlined"
                            onClick={() =>
                              handleMappingDecision(
                                "correct"
                              )
                            }
                            disabled={
                              mappingBusy ||
                              !reviewerId.trim()
                            }
                          >
                            {mappingBusy
                              ? "Saving…"
                              : "Correct + approve"}
                          </Button>

                          <Button
                            color="error"
                            onClick={() =>
                              handleMappingDecision(
                                "reject"
                              )
                            }
                            disabled={
                              mappingBusy ||
                              !reviewerId.trim()
                            }
                          >
                            {mappingBusy
                              ? "Saving…"
                              : "Reject"}
                          </Button>
                        </Stack>
                      </Stack>
                    </Paper>
                  )}

                  {mappingDecision && (
                    <Alert
                      severity={
                        mappingDecision.mapping.status ===
                        "APPROVED"
                          ? "success"
                          : "warning"
                      }
                    >
                      <Stack spacing={1.25}>
                        <Typography variant="body2">
                          <strong>
                            APPROVED MAPPING v
                            {mappingDecision.mapping.version}
                          </strong>{" "}
                          · {mappingDecision.mapping.status} ·{" "}
                          {mappingDecision.mapping.active
                            ? "ACTIVE"
                            : "INACTIVE"}{" "}
                          · Human action by{" "}
                          {mappingDecision.mapping.reviewer_id ??
                            "unknown"}
                          .
                        </Typography>

                        <Typography variant="body2">
                          Compliance remains unchanged and
                          the pattern remains UNKNOWN until
                          explicit re-analysis.
                        </Typography>

                        {mappingDecision.mapping.status ===
                          "APPROVED" &&
                          mappingDecision.mapping.active &&
                          !reanalysis && (
                            <Button
                              variant="contained"
                              onClick={handleReanalyze}
                              disabled={reanalysisBusy}
                              sx={{
                                alignSelf:
                                  "flex-start",
                              }}
                            >
                              {reanalyzingLabel(
                                reanalysisBusy
                              )}
                            </Button>
                          )}
                      </Stack>
                    </Alert>
                  )}

                  {mappingError && (
                    <Alert severity="error">
                      {mappingError}
                    </Alert>
                  )}

                  {reanalysisError && (
                    <Alert severity="error">
                      {reanalysisError}
                    </Alert>
                  )}
                </Stack>
              </CardContent>
            </Card>
          )}

          {reanalysis && (
            <Card
              sx={{
                border:
                  "1px solid rgba(37,208,177,0.45)",
              }}
            >
              <CardContent>
                <Stack spacing={2}>
                  <Box>
                    <Typography
                      variant="overline"
                      color="secondary.main"
                      letterSpacing={1.2}
                    >
                      RE-ANALYSIS COMPLETE
                    </Typography>

                    <Typography
                      variant="h6"
                      sx={{ mt: 0.5 }}
                    >
                      {reanalysis.message ??
                        "Explicit re-analysis completed."}
                    </Typography>
                  </Box>

                  <Grid container spacing={2}>
                    <Grid size={{ xs: 12, sm: 4 }}>
                      <Typography
                        variant="caption"
                        color="text.secondary"
                      >
                        Parent analysis
                      </Typography>

                      <Typography
                        variant="body2"
                        sx={{
                          mt: 0.5,
                          fontFamily: "monospace",
                          wordBreak: "break-all",
                        }}
                      >
                        {reanalysis.parent_analysis_id ??
                          "Not available"}
                      </Typography>
                    </Grid>

                    <Grid size={{ xs: 12, sm: 4 }}>
                      <Typography
                        variant="caption"
                        color="text.secondary"
                      >
                        Mapping
                      </Typography>

                      <Typography sx={{ mt: 0.5 }}>
                        v
                        {reanalysis.mapping_version ??
                          "?"}{" "}
                        · ACTIVE
                      </Typography>
                    </Grid>

                    <Grid size={{ xs: 12, sm: 4 }}>
                      <Typography
                        variant="caption"
                        color="text.secondary"
                      >
                        Pattern state
                      </Typography>

                      <Typography sx={{ mt: 0.5 }}>
                        RECOGNIZED VIA APPROVED MAPPING
                      </Typography>
                    </Grid>
                  </Grid>

                  <Divider />

                  <Typography
                    variant="overline"
                    color="secondary.main"
                    letterSpacing={1.2}
                  >
                    DETERMINISTIC RESULT
                  </Typography>

                  <Stack
                    direction="row"
                    spacing={1}
                    flexWrap="wrap"
                    useFlexGap
                  >
                    {reanalysis.results.map((result) => (
                      <Chip
                        key={result.control_id}
                        label={`${result.control_id}: ${result.result}`}
                        color={statusColor(
                          result.result
                        )}
                      />
                    ))}
                  </Stack>

                  <Typography
                    variant="overline"
                    color="secondary.main"
                    letterSpacing={1.2}
                  >
                    EVIDENCE
                  </Typography>

                  {reanalysis.evidence.map(
                    (item, index) => (
                      <Paper
                        key={`${item.property}-${index}`}
                        variant="outlined"
                        sx={{ p: 1.5 }}
                      >
                        <Typography
                          variant="body2"
                          sx={{
                            fontFamily: "monospace",
                          }}
                        >
                          {item.property} ={" "}
                          {formatValue(item.actual)} ·{" "}
                          {item.result}
                        </Typography>

                        <Typography
                          variant="caption"
                          color="text.secondary"
                        >
                          {item.evidence_source ===
                          "APPROVED_MAPPING"
                            ? `Approved mapping ${
                                item.mapping_id ?? ""
                              } v${
                                item.mapping_version ??
                                "?"
                              }`
                            : "Configuration evidence"}{" "}
                          · original pattern:{" "}
                          {item.original_pattern ??
                            "Not available"}
                        </Typography>
                      </Paper>
                    )
                  )}

                  <Button
                    variant="outlined"
                    startIcon={<Download />}
                    onClick={() =>
                      handleGenerateReport(
                        reanalysis.analysis_id,
                        `${reanalysis.filename}-reanalyzed`
                      )
                    }
                    disabled={reportBusy}
                    sx={{ alignSelf: "flex-start" }}
                  >
                    {reportBusy
                      ? "Generating report…"
                      : "Generate Re-analysis Report"}
                  </Button>
                </Stack>
              </CardContent>
            </Card>
          )}

          {analysis.results.some(
            (result) => result.result === "FAIL"
          ) && (
            <Card
              id="remediation-card"
              sx={{
                border:
                  "1px solid rgba(255,112,112,0.42)",
              }}
            >
              <CardContent>
                <Stack spacing={2}>
                  <Box>
                    <Typography
                      variant="overline"
                      color="error.main"
                      letterSpacing={1.2}
                    >
                      REMEDIATION
                    </Typography>

                    <Typography
                      variant="h6"
                      sx={{ mt: 0.5 }}
                    >
                      Safe remediation simulation
                    </Typography>

                    <Typography
                      variant="body2"
                      color="text.secondary"
                      sx={{ mt: 0.5 }}
                    >
                      Recommendations are deterministic and
                      limited to supported demo findings.
                      Commands are displayed as guidance only;
                      they are never executed.
                    </Typography>
                  </Box>

                  <Alert severity="warning">
                    <strong>SIMULATION ONLY</strong> · No
                    production device will be changed.
                  </Alert>

                  {remediationBusy && (
                    <LinearProgress />
                  )}

                  {remediationError && (
                    <Alert severity="error">
                      {remediationError}
                    </Alert>
                  )}

                  {!remediationBusy &&
                    remediations.length === 0 &&
                    !remediationError && (
                      <Typography
                        variant="body2"
                        color="text.secondary"
                      >
                        No supported remediation is available
                        for the failed controls in this analysis.
                      </Typography>
                    )}

                  {remediations.map((remediation) => (
                    <Paper
                      key={remediation.remediation_id}
                      variant="outlined"
                      sx={{
                        p: 2,
                        bgcolor:
                          "rgba(255,112,112,0.04)",
                      }}
                    >
                      <Stack spacing={1.25}>
                        <Stack
                          direction={{
                            xs: "column",
                            sm: "row",
                          }}
                          spacing={1}
                          alignItems={{
                            sm: "center",
                          }}
                        >
                          <Typography
                            variant="subtitle1"
                            fontWeight={700}
                          >
                            {remediation.control_id} ·{" "}
                            {remediation.title}
                          </Typography>

                          <Chip
                            label={`Risk: ${remediation.risk_level}`}
                            size="small"
                            color="warning"
                          />
                        </Stack>

                        <Typography variant="body2">
                          {remediation.description}
                        </Typography>

                        <Typography
                          variant="caption"
                          color="text.secondary"
                        >
                          Target properties:{" "}
                          {remediation.target_properties.join(
                            ", "
                          )}
                        </Typography>

                        <Box
                          component="pre"
                          sx={{
                            mt: 0,
                            mb: 0,
                            p: 1.5,
                            overflowX: "auto",
                            borderRadius: 1.5,
                            bgcolor: "#06111f",
                            color: "#b7d8ff",
                            fontFamily: "monospace",
                            fontSize: "0.8rem",
                          }}
                        >
                          {remediation.commands.join("\n")}
                        </Box>

                        <Button
                          variant="contained"
                          onClick={() =>
                            handleSimulate(remediation)
                          }
                          disabled={simulationBusy}
                          sx={{
                            alignSelf:
                              "flex-start",
                          }}
                        >
                          {simulationBusy
                            ? "Simulating…"
                            : "Simulate Remediation"}
                        </Button>
                      </Stack>
                    </Paper>
                  ))}

                  {simulation && (
                    <Paper
                      variant="outlined"
                      sx={{
                        p: 2,
                        bgcolor:
                          "rgba(37,208,177,0.05)",
                        borderColor:
                          "rgba(37,208,177,0.42)",
                      }}
                    >
                      <Stack spacing={1.5}>
                        <Typography
                          variant="overline"
                          color="secondary.main"
                          letterSpacing={1.2}
                        >
                          SIMULATION RESULT
                        </Typography>

                        <Typography variant="h6">
                          Before:{" "}
                          {simulation.before_result} ·
                          After:{" "}
                          {simulation.after_result}
                        </Typography>

                        <Typography
                          variant="body2"
                          color="text.secondary"
                        >
                          {simulation.message}
                        </Typography>

                        <Divider />

                        <Typography
                          variant="subtitle2"
                          fontWeight={700}
                        >
                          SIMULATED CONFIGURATION
                        </Typography>

                        {simulation.simulated_changes.map(
                          (change) => (
                            <Typography
                              key={change.property}
                              variant="body2"
                              sx={{
                                fontFamily:
                                  "monospace",
                              }}
                            >
                              {change.property}:{" "}
                              {formatValue(
                                change.before_value
                              )}{" "}
                              →{" "}
                              {formatValue(
                                change.after_value
                              )}
                            </Typography>
                          )
                        )}

                        <Typography
                          variant="subtitle2"
                          fontWeight={700}
                        >
                          EVIDENCE
                        </Typography>

                        {simulation.evidence
                          .filter(
                            (item) =>
                              item.control_id ===
                              simulation.control_id
                          )
                          .map((item, index) => (
                            <Typography
                              key={`${item.property}-${index}`}
                              variant="body2"
                              color="text.secondary"
                            >
                              {item.property}:{" "}
                              {item.result} ·{" "}
                              {item.evidence_source ??
                                "SIMULATED_REMEDIATION"}{" "}
                              · original source{" "}
                              {item.original_source_file ??
                                "Not available"}
                            </Typography>
                          ))}

                        <Button
                          variant="outlined"
                          startIcon={<Download />}
                          onClick={() =>
                            handleGenerateReport(
                              analysis.analysis_id,
                              `${analysis.filename}-simulation`
                            )
                          }
                          disabled={reportBusy}
                          sx={{
                            alignSelf:
                              "flex-start",
                          }}
                        >
                          {reportBusy
                            ? "Generating report…"
                            : "Generate Report"}
                        </Button>
                      </Stack>
                    </Paper>
                  )}
                </Stack>
              </CardContent>
            </Card>
          )}

          <Card>
            <CardContent sx={{ p: 0 }}>
              <Box
                sx={{
                  p: { xs: 2, md: 2.5 },
                }}
              >
                <Typography
                  variant="h6"
                  fontWeight={700}
                >
                  Control results
                  {reanalysis ? " — Re-analysis" : ""}
                </Typography>

                <Typography
                  variant="body2"
                  color="text.secondary"
                  sx={{ mt: 0.5 }}
                >
                  {reanalysis
                    ? `Showing re-analysis results using approved mapping v${
                        reanalysis.mapping_version ??
                        mappingDecision?.mapping.version ??
                        "?"
                      }. Select a control to inspect its evidence.`
                    : "Select a control to inspect its source evidence."}
                </Typography>
              </Box>

              <Box sx={{ overflowX: "auto" }}>
                <Table>
                  <TableHead>
                    <TableRow>
                      <TableCell>Control ID</TableCell>
                      <TableCell>Control name</TableCell>
                      <TableCell>Result</TableCell>
                      <TableCell>Expected</TableCell>
                      <TableCell>Actual</TableCell>
                      <TableCell>Action</TableCell>
                    </TableRow>
                  </TableHead>

                  <TableBody>
                    {displayedAnalysis?.results.map(
                      (result) => (
                        <TableRow
                          key={result.control_id}
                          hover
                          tabIndex={0}
                          onClick={() =>
                            setSelectedResult(result)
                          }
                          onKeyDown={(event) => {
                            if (
                              event.key === "Enter" ||
                              event.key === " "
                            ) {
                              setSelectedResult(
                                result
                              );
                            }
                          }}
                          sx={{
                            cursor: "pointer",
                          }}
                        >
                          <TableCell
                            sx={{
                              fontFamily: "monospace",
                            }}
                          >
                            {result.control_id}
                          </TableCell>

                          <TableCell>
                            {result.control_name}
                          </TableCell>

                          <TableCell>
                            <Chip
                              label={result.result}
                              color={statusColor(
                                result.result
                              )}
                              size="small"
                            />
                          </TableCell>

                          <TableCell>
                            {formatValue(
                              result.expected
                            )}
                          </TableCell>

                          <TableCell>
                            {formatValue(
                              result.actual
                            )}
                          </TableCell>

                          <TableCell>
                            {result.result === "FAIL" &&
                              remediations.some(
                                (item) =>
                                  item.control_id ===
                                  result.control_id
                              ) && (
                                <Button
                                  size="small"
                                  onClick={(event) => {
                                    event.stopPropagation();

                                    document
                                      .getElementById(
                                        "remediation-card"
                                      )
                                      ?.scrollIntoView({
                                        behavior:
                                          "smooth",
                                      });
                                  }}
                                >
                                  View remediation
                                </Button>
                              )}
                          </TableCell>
                        </TableRow>
                      )
                    )}
                  </TableBody>
                </Table>
              </Box>
            </CardContent>
          </Card>

          {reportError && (
            <Alert severity="error">
              {reportError}
            </Alert>
          )}
        </Stack>
      )}

      <Dialog
        open={Boolean(selectedResult)}
        onClose={() => setSelectedResult(null)}
        fullWidth
        maxWidth="md"
      >
        {selectedResult && (
          <>
            <DialogTitle sx={{ pr: 6 }}>
              <Stack spacing={0.75}>
                <Typography
                  variant="overline"
                  color="secondary.main"
                >
                  Evidence detail
                </Typography>

                <Typography variant="h6">
                  {selectedResult.control_id} ·{" "}
                  {selectedResult.control_name}
                </Typography>

                <Chip
                  label={selectedResult.result}
                  color={statusColor(
                    selectedResult.result
                  )}
                  size="small"
                  sx={{
                    alignSelf: "flex-start",
                  }}
                />
              </Stack>

              <IconButton
                aria-label="Close evidence"
                onClick={() =>
                  setSelectedResult(null)
                }
                sx={{
                  position: "absolute",
                  right: 12,
                  top: 12,
                }}
              >
                <Close />
              </IconButton>
            </DialogTitle>

            <DialogContent dividers>
              <Stack spacing={2.5}>
                <Alert
                  severity={
                    selectedResult.result ===
                    "UNKNOWN"
                      ? "warning"
                      : selectedResult.result ===
                          "FAIL"
                        ? "error"
                        : "info"
                  }
                >
                  {selectedResult.explanation}
                </Alert>

                {selectedEvidence.map(
                  (item, index) => (
                    <Paper
                      key={`${item.property}-${index}`}
                      variant="outlined"
                      sx={{ p: 2 }}
                    >
                      <Stack spacing={1.5}>
                        <Typography
                          variant="subtitle1"
                          fontWeight={700}
                        >
                          {item.property}
                        </Typography>

                        <Grid container spacing={2}>
                          <Grid size={{ xs: 12, sm: 6 }}>
                            <Typography
                              variant="caption"
                              color="text.secondary"
                            >
                              Expected
                            </Typography>

                            <Typography
                              sx={{ mt: 0.5 }}
                            >
                              {formatValue(
                                item.expected
                              )}
                            </Typography>
                          </Grid>

                          <Grid size={{ xs: 12, sm: 6 }}>
                            <Typography
                              variant="caption"
                              color="text.secondary"
                            >
                              Actual
                            </Typography>

                            <Typography
                              sx={{ mt: 0.5 }}
                            >
                              {formatValue(
                                item.actual
                              )}
                            </Typography>
                          </Grid>

                          <Grid size={{ xs: 12, sm: 6 }}>
                            <Typography
                              variant="caption"
                              color="text.secondary"
                            >
                              Source file
                            </Typography>

                            <Typography
                              sx={{ mt: 0.5 }}
                            >
                              {item.source_file ??
                                "Not available"}
                            </Typography>
                          </Grid>

                          <Grid size={{ xs: 12, sm: 6 }}>
                            <Typography
                              variant="caption"
                              color="text.secondary"
                            >
                              Source line
                            </Typography>

                            <Typography
                              sx={{ mt: 0.5 }}
                            >
                              {item.line_start
                                ? `${item.line_start}${
                                    item.line_end &&
                                    item.line_end !==
                                      item.line_start
                                      ? `–${item.line_end}`
                                      : ""
                                  }`
                                : "Not available"}
                            </Typography>
                          </Grid>
                        </Grid>

                        <Box>
                          <Typography
                            variant="caption"
                            color="text.secondary"
                          >
                            Raw configuration
                          </Typography>

                          <Box
                            component="pre"
                            sx={{
                              mt: 0.75,
                              mb: 0,
                              p: 1.5,
                              overflowX: "auto",
                              borderRadius: 1.5,
                              bgcolor: "#06111f",
                              color: "#b7d8ff",
                              fontFamily: "monospace",
                              fontSize: "0.85rem",
                            }}
                          >
                            {item.raw_excerpt ??
                              "Not available"}
                          </Box>
                        </Box>

                        <Typography
                          variant="body2"
                          color="text.secondary"
                        >
                          {item.explanation}
                        </Typography>
                      </Stack>
                    </Paper>
                  )
                )}

                {selectedEvidence.length === 0 && (
                  <Alert severity="warning">
                    No detailed evidence was returned for
                    this control.
                  </Alert>
                )}
              </Stack>
            </DialogContent>
          </>
        )}
      </Dialog>
    </Stack>
  );
}