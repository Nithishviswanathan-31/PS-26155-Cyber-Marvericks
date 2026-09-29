import { useMemo, useRef, useState } from "react";
import { useAuth } from "../auth/AuthProvider";

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
  Tab,
  Tabs,
  TextField,
  Tooltip,
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

import {
  Close,
  Description,
  Download,
  Layers,
  PictureAsPdf,
  UploadFile,
  Visibility,
} from "@mui/icons-material";

import {
  analyzeConfiguration,
  analyzeBatch,
  getAnalysis,
  type BatchAnalysis,
  type BatchItem,
  type AnalysisResponse,
  type ComplianceResult,
  type ControlResultSummary,
  type EvidenceRecord,
  AnalysisApiError,
} from "../api/analyze";

import {
  approveMapping,
  correctAndApproveMapping,
  deactivateKnowledge,
  getPatternKnowledge,
  MappingApiError,
  rejectMapping,
  suggestMapping,
  type CandidateMappingSuggestion,
  type MappingDecisionResponse,
  type KnowledgeClassification,
  type SemanticMapping,
} from "../api/mappings";

import { reanalyzeConfiguration } from "../api/reanalysis";

import {
  getRemediations,
  RemediationApiError,
  simulateRemediation,
  reanalyzeSimulation,
  type RemediationDefinition,
  type SimulationResponse,
} from "../api/remediation";

import {
  downloadPdf,
  generatePdfReport,
  ReportApiError,
} from "../api/reports";
import { AnalysisIntegrityStatus } from "./IntegrityPage";

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
  const { user } = useAuth();
  const canAudit = user.role !== "REVIEWER";
  const canReview = user.role !== "AUDITOR";
  const [storedAnalysisId, setStoredAnalysisId] = useState("");
  const inputRef = useRef<HTMLInputElement>(null);
  const batchInputRef = useRef<HTMLInputElement>(null);

  const [workflowState, setWorkflowState] =
    useState<WorkflowState>("IDLE");

  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [ingestionTab, setIngestionTab] = useState<"single" | "bulk">("single");
  const [downloadingReportId, setDownloadingReportId] = useState<string | null>(null);
  const [inspectedBatchItemId, setInspectedBatchItemId] = useState<string | null>(null);
  const [batchDragOver, setBatchDragOver] = useState(false);
  const [batchFiles, setBatchFiles] = useState<File[]>([]);
  const [batch, setBatch] = useState<BatchAnalysis | null>(null);
  const [batchItems, setBatchItems] = useState<BatchItem[]>([]);
  const [batchBusy, setBatchBusy] = useState(false);
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
  const [knowledge, setKnowledge] = useState<KnowledgeClassification | null>(null);

  const [mappingBusy, setMappingBusy] = useState(false);
  const [mappingError, setMappingError] = useState<string | null>(null);

  const [reviewerId, setReviewerId] = useState(user.offline ? "demo-reviewer" : user.user_id);

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
  const [simulationReanalysis, setSimulationReanalysis] = useState<AnalysisResponse | null>(null);

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
      setSimulationReanalysis(null);
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

  const handleBatchAnalyze = async () => {
    if (!batchFiles.length || batchBusy) return;
    setBatchBusy(true);
    setErrorMessage(null);
    try {
      const result = await analyzeBatch(batchFiles);
      setBatch(result.batch);
      setBatchItems(result.items);
    } catch (error: unknown) {
      setErrorMessage(error instanceof AnalysisApiError ? error.message : "The batch could not be analyzed.");
    } finally {
      setBatchBusy(false);
    }
  };

  const addBatchFiles = (newFiles: File[]) => {
    const validFiles: File[] = [];
    const errors: string[] = [];

    for (const f of newFiles) {
      const valErr = validateFile(f);
      if (valErr) {
        errors.push(`${f.name}: ${valErr}`);
      } else {
        validFiles.push(f);
      }
    }

    if (errors.length > 0) {
      setErrorMessage(errors.join(" | "));
    } else {
      setErrorMessage(null);
    }

    setBatchFiles((prev) => {
      const existingKeys = new Set(prev.map((f) => `${f.name}:${f.size}`));
      const filtered = validFiles.filter((f) => !existingKeys.has(`${f.name}:${f.size}`));
      const combined = [...prev, ...filtered];
      if (combined.length > 25) {
        setErrorMessage("A batch may contain at most 25 files. Excess files were omitted.");
        return combined.slice(0, 25);
      }
      return combined;
    });
  };

  const removeBatchFile = (index: number) => {
    setBatchFiles((prev) => prev.filter((_, i) => i !== index));
  };

  const clearBatchFiles = () => {
    setBatchFiles([]);
    if (batchInputRef.current) {
      batchInputRef.current.value = "";
    }
  };

  const openBatchAnalysis = async (analysisId: string, batchItemId?: string) => {
    try {
      const result = await getAnalysis(analysisId);
      setAnalysis(result);
      setInspectedBatchItemId(batchItemId ?? null);
      setCandidate(null);
      setKnowledge(null);
      setMappingDecision(null);
      setReviewMapping({});
      setSimulation(null);
      setSimulationReanalysis(null);
      setRemediations([]);
      setMappingError(null);
      setReanalysis(null);
      setSelectedResult(null);
      onAnalysisCompleted(result);

      setRemediationBusy(true);
      try {
        const remediationResponse = await getRemediations(result.analysis_id);
        setRemediations(remediationResponse.remediations);
      } catch (err: unknown) {
        setRemediationError(
          err instanceof RemediationApiError
            ? err.message
            : "Remediation recommendations could not be loaded."
        );
      } finally {
        setRemediationBusy(false);
      }
    } catch (error: unknown) {
      setErrorMessage(error instanceof AnalysisApiError ? error.message : "The analysis could not be loaded.");
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

      const retrievedKnowledge = await getPatternKnowledge(patternId);

      setCandidate(suggestion);
      setKnowledge(retrievedKnowledge);
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
              reviewerId.trim(),
              candidate.proposal_id
            )
          : action === "correct"
            ? await correctAndApproveMapping(
              patternId,
              reviewMapping,
              reviewerId.trim(),
              candidate.proposal_id
              )
            : await rejectMapping(
              patternId,
              reviewerId.trim(),
              "Rejected during human review.",
              candidate.proposal_id
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

  const handleDeactivateKnowledge = async () => {
    if (!mappingDecision?.mapping.mapping_id || !reviewerId.trim() || mappingBusy) return;
    setMappingBusy(true);
    setMappingError(null);
    try {
      await deactivateKnowledge(mappingDecision.mapping.mapping_id, reviewerId.trim());
      setMappingDecision((current) => current ? { ...current, mapping: { ...current.mapping, active: false, status: "INACTIVE" } } : current);
    } catch (error: unknown) {
      setMappingError(error instanceof MappingApiError ? error.message : "Knowledge could not be deactivated.");
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

  const handleSimulationReanalysis = async () => {
    if (!simulation || simulationBusy) return;
    setSimulationBusy(true);
    setRemediationError(null);
    try {
      setSimulationReanalysis(await reanalyzeSimulation(simulation.simulation_id));
    } catch (error: unknown) {
      setRemediationError(error instanceof RemediationApiError ? error.message : "The simulation could not be re-analyzed.");
    } finally {
      setSimulationBusy(false);
    }
  };

  const handleGenerateReport = async (
    analysisId: string,
    suggestedName: string,
    batchItemId?: string
  ) => {
    if (reportBusy) return;

    setReportBusy(true);
    if (batchItemId) setDownloadingReportId(batchItemId);
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
      setDownloadingReportId(null);
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

      {canAudit && (
        <Card variant="outlined" sx={{ overflow: "hidden" }}>
          <Box sx={{ borderBottom: 1, borderColor: "divider", bgcolor: "rgba(255,255,255,0.02)" }}>
            <Tabs
              value={ingestionTab}
              onChange={(_, value) => {
                setIngestionTab(value);
                setErrorMessage(null);
              }}
              textColor="primary"
              indicatorColor="primary"
              sx={{ px: 2, pt: 1 }}
            >
              <Tab
                value="single"
                icon={<Description fontSize="small" />}
                iconPosition="start"
                label={selectedFile ? `Single Device Audit (${selectedFile.name})` : "Single Device Audit"}
              />
              <Tab
                value="bulk"
                icon={<Layers fontSize="small" />}
                iconPosition="start"
                label={
                  batchFiles.length > 0
                    ? `Bulk Fleet Ingestion (${batchFiles.length})`
                    : "Bulk Fleet Ingestion"
                }
              />
            </Tabs>
          </Box>

          <CardContent sx={{ p: { xs: 2, md: 3 } }}>
            {ingestionTab === "single" ? (
              <Stack spacing={2.5}>
                <Stack direction={{ xs: "column", sm: "row" }} spacing={2}>
                  <TextField
                    size="small"
                    label="Open Stored Analysis by ID"
                    placeholder="Enter existing analysis UUID (e.g. from seed or prior run)"
                    value={storedAnalysisId}
                    onChange={(event) => setStoredAnalysisId(event.target.value)}
                    fullWidth
                  />
                  <Button
                    variant="outlined"
                    disabled={!storedAnalysisId.trim()}
                    onClick={() => void openBatchAnalysis(storedAnalysisId.trim())}
                  >
                    Open
                  </Button>
                </Stack>

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
                    or select a prepared `.conf`, `.cfg`, or `.txt` file
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
                          {formatBytes(selectedFile.size)} · ready for analysis
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
            ) : (
              <Stack spacing={3}>
                <Box>
                  <Typography variant="h6" fontWeight={700}>
                    Multi-Device Fleet Ingestion & Audit
                  </Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
                    Select or drag-and-drop up to 25 configuration files across Cisco IOS/IOS-XE, FortiGate/FortiOS, Palo Alto/PAN-OS, and AstraNet. Each configuration is parsed, mapped to Security IR, independently evaluated deterministically against CIS Controls v8, NIST SP 800-53 r5, DISA STIG, and ISO/IEC 27001:2022, and recorded in the integrity ledger.
                  </Typography>
                </Box>

                <Box
                  onDragOver={(event) => {
                    event.preventDefault();
                    setBatchDragOver(true);
                  }}
                  onDragLeave={() => setBatchDragOver(false)}
                  onDrop={(event) => {
                    event.preventDefault();
                    setBatchDragOver(false);
                    addBatchFiles(Array.from(event.dataTransfer.files));
                  }}
                  sx={{
                    border: "2px dashed",
                    borderColor: batchDragOver
                      ? "secondary.main"
                      : "rgba(110,168,254,0.45)",
                    bgcolor: batchDragOver
                      ? "rgba(37,208,177,0.08)"
                      : "rgba(110,168,254,0.04)",
                    borderRadius: 3,
                    p: { xs: 3, md: 4 },
                    textAlign: "center",
                    transition: "all 160ms ease",
                  }}
                >
                  <UploadFile sx={{ fontSize: 44, color: "primary.main" }} />
                  <Typography variant="h6" sx={{ mt: 1 }}>
                    Drop fleet configuration files here
                  </Typography>
                  <Typography color="text.secondary" variant="body2" sx={{ mt: 0.5 }}>
                    Supports multiple <code>.conf</code>, <code>.cfg</code>, and <code>.txt</code> files (up to 25 files, 1 MB max each)
                  </Typography>
                  <Button
                    variant="outlined"
                    sx={{ mt: 2 }}
                    onClick={() => batchInputRef.current?.click()}
                  >
                    Select Fleet Files
                  </Button>
                  <input
                    ref={batchInputRef}
                    hidden
                    multiple
                    type="file"
                    accept=".conf,.cfg,.txt,text/plain"
                    onChange={(event) =>
                      addBatchFiles(Array.from(event.target.files ?? []))
                    }
                  />
                </Box>

                {batchFiles.length > 0 && (
                  <Paper variant="outlined" sx={{ p: 2, bgcolor: "background.paper" }}>
                    <Stack spacing={1.5}>
                      <Stack direction="row" justifyContent="space-between" alignItems="center">
                        <Typography variant="subtitle2" fontWeight={700}>
                          Staged Fleet Configurations ({batchFiles.length} / 25)
                        </Typography>
                        <Button size="small" color="inherit" onClick={clearBatchFiles}>
                          Clear All
                        </Button>
                      </Stack>
                      <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
                        {batchFiles.map((file, idx) => (
                          <Chip
                            key={`${file.name}-${idx}`}
                            icon={<Description fontSize="small" />}
                            label={`${file.name} (${formatBytes(file.size)})`}
                            onDelete={() => removeBatchFile(idx)}
                            variant="outlined"
                            size="small"
                          />
                        ))}
                      </Box>
                      <Divider />
                      <Stack direction="row" justifyContent="flex-end" spacing={1.5} alignItems="center">
                        <Button
                          variant="contained"
                          size="large"
                          disabled={!batchFiles.length || batchBusy}
                          onClick={handleBatchAnalyze}
                        >
                          {batchBusy
                            ? "Analyzing Fleet…"
                            : `Analyze Fleet (${batchFiles.length} Configurations)`}
                        </Button>
                      </Stack>
                    </Stack>
                  </Paper>
                )}

                {batchBusy && (
                  <Box>
                    <Stack direction="row" justifyContent="space-between" sx={{ mb: 0.75 }}>
                      <Typography variant="body2" color="text.secondary">
                        Processing fleet configurations in parallel (Parsing, Security IR, Compliance Engine, Ledger)…
                      </Typography>
                      <Typography variant="body2" color="secondary.main">
                        Batch Ingestion In Progress
                      </Typography>
                    </Stack>
                    <LinearProgress />
                  </Box>
                )}

                {errorMessage && (
                  <Alert severity="error">{errorMessage}</Alert>
                )}

                {batch && (
                  <Stack spacing={2.5} id="batch-summary-card">
                    <Paper
                      variant="outlined"
                      sx={{
                        p: 2.5,
                        borderColor:
                          batch.status === "COMPLETED"
                            ? "success.main"
                            : batch.status === "FAILED"
                              ? "error.main"
                              : "warning.main",
                        bgcolor: "rgba(110,168,254,0.03)",
                      }}
                    >
                      <Stack spacing={2}>
                        <Stack
                          direction={{ xs: "column", sm: "row" }}
                          justifyContent="space-between"
                          alignItems={{ sm: "center" }}
                          spacing={1}
                        >
                          <Box>
                            <Typography variant="overline" color="text.secondary">
                              BATCH INGESTION REPORT
                            </Typography>
                            <Typography variant="h6" fontWeight={700}>
                              Batch ID: <code>{batch.batch_id}</code>
                            </Typography>
                          </Box>
                          <Stack direction="row" spacing={1} alignItems="center">
                            <Chip
                              label={`Status: ${batch.status}`}
                              color={
                                batch.status === "COMPLETED"
                                  ? "success"
                                  : batch.status === "FAILED"
                                    ? "error"
                                    : "warning"
                              }
                              size="medium"
                            />
                            {batch.created_at && (
                              <Typography variant="caption" color="text.secondary">
                                {new Date(batch.created_at).toLocaleTimeString()}
                              </Typography>
                            )}
                          </Stack>
                        </Stack>

                        <Divider />

                        <Grid container spacing={2}>
                          <Grid size={{ xs: 6, sm: 3 }}>
                            <Paper variant="outlined" sx={{ p: 1.5, textAlign: "center" }}>
                              <Typography variant="h5" fontWeight={700}>
                                {batch.total_items}
                              </Typography>
                              <Typography variant="caption" color="text.secondary">
                                Total Files
                              </Typography>
                            </Paper>
                          </Grid>
                          <Grid size={{ xs: 6, sm: 3 }}>
                            <Paper variant="outlined" sx={{ p: 1.5, textAlign: "center" }}>
                              <Typography variant="h5" fontWeight={700} color="success.main">
                                {batch.successful_items}
                              </Typography>
                              <Typography variant="caption" color="text.secondary">
                                Successful
                              </Typography>
                            </Paper>
                          </Grid>
                          <Grid size={{ xs: 6, sm: 3 }}>
                            <Paper variant="outlined" sx={{ p: 1.5, textAlign: "center" }}>
                              <Typography variant="h5" fontWeight={700} color="warning.main">
                                {batch.duplicate_items}
                              </Typography>
                              <Typography variant="caption" color="text.secondary">
                                Duplicates (SHA-256)
                              </Typography>
                            </Paper>
                          </Grid>
                          <Grid size={{ xs: 6, sm: 3 }}>
                            <Paper variant="outlined" sx={{ p: 1.5, textAlign: "center" }}>
                              <Typography
                                variant="h5"
                                fontWeight={700}
                                color={batch.failed_items > 0 ? "error.main" : "text.primary"}
                              >
                                {batch.failed_items}
                              </Typography>
                              <Typography variant="caption" color="text.secondary">
                                Failed
                              </Typography>
                            </Paper>
                          </Grid>
                        </Grid>

                        <Grid container spacing={2}>
                          <Grid size={{ xs: 12, md: 6 }}>
                            <Typography variant="subtitle2" sx={{ mb: 1 }}>
                              Detected Fleet Vendors
                            </Typography>
                            <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
                              {(batch.summary?.vendors_detected ?? []).length > 0 ? (
                                batch.summary?.vendors_detected?.map((v) => (
                                  <Chip
                                    key={v}
                                    label={vendorLabel(v)}
                                    color="primary"
                                    variant="outlined"
                                    size="small"
                                  />
                                ))
                              ) : (
                                <Typography variant="body2" color="text.secondary">
                                  No vendor signatures detected
                                </Typography>
                              )}
                            </Box>
                          </Grid>
                          <Grid size={{ xs: 12, md: 6 }}>
                            <Typography variant="subtitle2" sx={{ mb: 1 }}>
                              Aggregate Control Findings Across Fleet
                            </Typography>
                            <Stack direction="row" spacing={1} flexWrap="wrap">
                              <Chip
                                label={`PASS: ${batch.summary?.pass_count ?? 0}`}
                                color="success"
                                size="small"
                              />
                              <Chip
                                label={`FAIL: ${batch.summary?.fail_count ?? 0}`}
                                color="error"
                                size="small"
                              />
                              <Chip
                                label={`UNKNOWN: ${batch.summary?.unknown_count ?? 0}`}
                                color="warning"
                                size="small"
                              />
                              {(batch.summary?.not_applicable_count ?? 0) > 0 && (
                                <Chip
                                  label={`N/A: ${batch.summary?.not_applicable_count ?? 0}`}
                                  size="small"
                                />
                              )}
                            </Stack>
                          </Grid>
                        </Grid>
                      </Stack>
                    </Paper>

                    {batchItems.length > 0 && (
                      <Paper variant="outlined">
                        <Box sx={{ p: 2, borderBottom: 1, borderColor: "divider" }}>
                          <Typography variant="subtitle1" fontWeight={700}>
                            Per-Device Compliance Breakdown ({batchItems.length} Devices)
                          </Typography>
                          <Typography variant="body2" color="text.secondary">
                            Click <strong>Inspect</strong> to view deep Security IR, framework mappings, evidence provenance, and simulation remediation. Click <strong>PDF</strong> to download an individual device audit report.
                          </Typography>
                        </Box>
                        <Table size="small">
                          <TableHead>
                            <TableRow>
                              <TableCell>Configuration</TableCell>
                              <TableCell>Vendor & Platform</TableCell>
                              <TableCell>Device Identity</TableCell>
                              <TableCell>Status</TableCell>
                              <TableCell>Compliance</TableCell>
                              <TableCell>Findings</TableCell>
                              <TableCell align="right">Actions</TableCell>
                            </TableRow>
                          </TableHead>
                          <TableBody>
                            {batchItems.map((item) => (
                              <TableRow
                                key={item.batch_item_id}
                                sx={{
                                  bgcolor:
                                    inspectedBatchItemId === item.batch_item_id
                                      ? "rgba(37,208,177,0.08)"
                                      : undefined,
                                }}
                              >
                                <TableCell>
                                  <Typography variant="body2" fontWeight={600}>
                                    {item.source_filename}
                                  </Typography>
                                  {item.content_sha256 && (
                                    <Tooltip title={`Full SHA-256: ${item.content_sha256}`}>
                                      <Typography
                                        variant="caption"
                                        color="text.secondary"
                                        sx={{ fontFamily: "monospace", cursor: "help" }}
                                      >
                                        SHA-256: {item.content_sha256.substring(0, 10)}…
                                      </Typography>
                                    </Tooltip>
                                  )}
                                </TableCell>
                                <TableCell>
                                  <Stack spacing={0.5} alignItems="flex-start">
                                    <Chip
                                      label={item.vendor ? vendorLabel(item.vendor) : "Unknown"}
                                      size="small"
                                      variant="outlined"
                                    />
                                    {item.platform && (
                                      <Typography variant="caption" color="text.secondary">
                                        Platform: {item.platform}
                                      </Typography>
                                    )}
                                  </Stack>
                                </TableCell>
                                <TableCell>
                                  <Stack spacing={0.25}>
                                    <Typography variant="body2" fontWeight={600}>
                                      {item.hostname || "Not present in configuration"}
                                    </Typography>
                                    <Typography variant="caption" color="text.secondary">
                                      Model: {item.device_model || "Not present"} · SN: {item.serial_number || "Not present"}
                                    </Typography>
                                  </Stack>
                                </TableCell>
                                <TableCell>
                                  <Chip
                                    label={item.processing_status}
                                    size="small"
                                    color={
                                      item.processing_status === "COMPLETED"
                                        ? "success"
                                        : item.processing_status === "DUPLICATE"
                                          ? "warning"
                                          : item.processing_status === "FAILED"
                                            ? "error"
                                            : "default"
                                    }
                                  />
                                  {item.error_message && (
                                    <Typography variant="caption" color="error" display="block">
                                      {item.error_message}
                                    </Typography>
                                  )}
                                </TableCell>
                                <TableCell>
                                  {item.compliance_status ? (
                                    <Chip
                                      label={item.compliance_status}
                                      size="small"
                                      color={
                                        item.compliance_status === "PASS"
                                          ? "success"
                                          : item.compliance_status === "FAIL"
                                            ? "error"
                                            : item.compliance_status === "UNKNOWN"
                                              ? "warning"
                                              : "info"
                                      }
                                    />
                                  ) : (
                                    <Typography variant="caption" color="text.secondary">
                                      —
                                    </Typography>
                                  )}
                                </TableCell>
                                <TableCell>
                                  {item.pass_count !== undefined && item.pass_count !== null ? (
                                    <Stack direction="row" spacing={0.5}>
                                      <Chip
                                        label={`P:${item.pass_count}`}
                                        size="small"
                                        color="success"
                                        variant="outlined"
                                        sx={{ minWidth: 28, height: 20, fontSize: "0.7rem" }}
                                      />
                                      <Chip
                                        label={`F:${item.fail_count ?? 0}`}
                                        size="small"
                                        color="error"
                                        variant="outlined"
                                        sx={{ minWidth: 28, height: 20, fontSize: "0.7rem" }}
                                      />
                                      <Chip
                                        label={`U:${item.unknown_count ?? 0}`}
                                        size="small"
                                        color="warning"
                                        variant="outlined"
                                        sx={{ minWidth: 28, height: 20, fontSize: "0.7rem" }}
                                      />
                                    </Stack>
                                  ) : (
                                    <Typography variant="caption" color="text.secondary">
                                      —
                                    </Typography>
                                  )}
                                </TableCell>
                                <TableCell align="right">
                                  <Stack direction="row" spacing={1} justifyContent="flex-end">
                                    {item.analysis_id && (
                                      <Button
                                        size="small"
                                        variant={
                                          inspectedBatchItemId === item.batch_item_id
                                            ? "contained"
                                            : "outlined"
                                        }
                                        startIcon={<Visibility fontSize="small" />}
                                        onClick={() =>
                                          openBatchAnalysis(item.analysis_id as string, item.batch_item_id)
                                        }
                                      >
                                        Inspect
                                      </Button>
                                    )}
                                    {item.analysis_id && (
                                      <Button
                                        size="small"
                                        variant="outlined"
                                        color="secondary"
                                        startIcon={<PictureAsPdf fontSize="small" />}
                                        disabled={reportBusy}
                                        onClick={() =>
                                          handleGenerateReport(
                                            item.analysis_id as string,
                                            item.source_filename,
                                            item.batch_item_id
                                          )
                                        }
                                      >
                                        {downloadingReportId === item.batch_item_id
                                          ? "Exporting…"
                                          : "PDF"}
                                      </Button>
                                    )}
                                  </Stack>
                                </TableCell>
                              </TableRow>
                            ))}
                          </TableBody>
                        </Table>
                      </Paper>
                    )}
                  </Stack>
                )}
              </Stack>
            )}
          </CardContent>
        </Card>
      )}

      {analysis && (
        <Stack spacing={2.5} id="inspected-analysis-view">
          {inspectedBatchItemId && (
            <Alert
              severity="info"
              action={
                <Button
                  color="inherit"
                  size="small"
                  onClick={() => {
                    setAnalysis(null);
                    setInspectedBatchItemId(null);
                  }}
                >
                  Close Inspection
                </Button>
              }
            >
              Viewing individual device inspection for{" "}
              <strong>
                {displayedAnalysis?.device?.hostname || displayedAnalysis?.filename}
              </strong>{" "}
              from Batch <code>{batch?.batch_id}</code>.
            </Alert>
          )}
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
                    Platform
                  </Typography>

                  <Typography sx={{ mt: 0.5 }}>
                    {analysis.device.platform ?? "Not present in configuration"}
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
                      "Not present in configuration"}
                  </Typography>
                </Grid>

                <Grid size={{ xs: 12, sm: 4 }}>
                  <Typography
                    variant="caption"
                    color="text.secondary"
                  >
                    OS Version
                  </Typography>

                  <Typography sx={{ mt: 0.5 }}>
                    {analysis.device.version ??
                      "Not present in configuration"}
                  </Typography>
                </Grid>

                <Grid size={{ xs: 12, sm: 4 }}>
                  <Typography
                    variant="caption"
                    color="text.secondary"
                  >
                    Model
                  </Typography>

                  <Typography sx={{ mt: 0.5 }}>
                    {analysis.device.device_model ??
                      "Not present in configuration"}
                  </Typography>
                </Grid>

                <Grid size={{ xs: 12, sm: 4 }}>
                  <Typography
                    variant="caption"
                    color="text.secondary"
                  >
                    Serial Number
                  </Typography>

                  <Typography sx={{ mt: 0.5 }}>
                    {analysis.device.serial_number ??
                      "Not present in configuration"}
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
              <AnalysisIntegrityStatus analysisId={analysis.analysis_id} />
              {analysis.configuration && (
                <Typography variant="caption" component="div" sx={{ mt: 1, overflowWrap: "anywhere" }}>
                  Device: {analysis.configuration.device_id}<br />
                  Configuration: {analysis.configuration.configuration_id}<br />
                  Parse status: {analysis.configuration.parser_status}<br />
                  SHA-256: {analysis.configuration.content_sha256}
                </Typography>
              )}

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
                  : "Download Individual Device Audit Report (PDF)"}
              </Button>

              <Typography variant="caption" color="text.secondary" display="block" sx={{ mt: 0.5 }}>
                Comprehensive single PDF per device covering device identification, multi-framework compliance pass/fail with severity, exact evidence provenance, and step-by-step CLI remediation.
              </Typography>
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

                          {canReview && !mappingDecision &&
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
                        p: 2.5,
                        bgcolor:
                          "rgba(110,168,254,0.05)",
                        border: "1px solid rgba(110,168,254,0.3)",
                      }}
                    >
                      <Stack spacing={2}>
                        <Box>
                          <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap sx={{ mb: 1 }}>
                            <Chip label="AI CANDIDATE PROPOSAL" color="secondary" size="small" />
                            <Chip label="AWAITING HUMAN REVIEW" color="warning" size="small" variant="outlined" />
                            <Chip label="DETERMINISTIC EVALUATION UNCHANGED" color="default" size="small" variant="outlined" />
                          </Stack>

                          <Typography
                            variant="overline"
                            color="secondary.main"
                            letterSpacing={1.2}
                          >
                            AI PROPOSAL · BOUNDED INTERPRETATION PROVIDER
                          </Typography>

                          <Typography
                            variant="subtitle1"
                            fontWeight={700}
                          >
                            HUMAN APPROVAL REQUIRED (PS 26155 SAFETY INVARIANT)
                          </Typography>

                          <Alert severity="info" variant="outlined" sx={{ mt: 1, mb: 1 }}>
                            <strong>Core Invariant:</strong> AI proposes → human reviews → approved knowledge is versioned → deterministic engine re-analyzes. AI suggestions NEVER alter compliance evaluations directly. This configuration remains UNKNOWN until an authorized reviewer approves or corrects this mapping.
                          </Alert>
                        </Box>

                        <Typography variant="body2">
                          <strong>Confidence:</strong>{" "}
                          {(candidate.confidence * 100).toFixed(
                            0
                          )}
                          % demo suggestion value
                        </Typography>

                        {knowledge && (
                          <Paper variant="outlined" sx={{ p: 1.25, bgcolor: "background.default" }}>
                            <Typography variant="subtitle2">Adaptive Knowledge Review</Typography>
                            <Typography variant="body2" color="text.secondary">
                              Exact matches: {knowledge.exact_matches.length} · Related knowledge: {knowledge.related_knowledge.length} · Conflicts: {knowledge.conflicts.length}
                            </Typography>
                            {knowledge.exact_matches.map((item) => (
                              <Typography key={`${item.knowledge_id}-${item.version}`} variant="caption" display="block">
                                EXACT · {item.vendor} · v{item.version} · {JSON.stringify(item.approved_mapping)} · reviewer {item.reviewer_id ?? "unknown"}
                              </Typography>
                            ))}
                            {knowledge.conflicts.length > 0 && <Alert severity="warning" sx={{ mt: 1 }}>CONFLICT / REVIEW REQUIRED — no knowledge is applied automatically.</Alert>}
                          </Paper>
                        )}

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
                          slotProps={{ input: { readOnly: !user.offline } }}
                          onChange={(event) =>
                            setReviewerId(
                              event.target.value
                            )
                          }
                          size="small"
                          helperText={user.offline ? "Local demo identity; authentication is disabled." : "Authenticated account. The server records your identity."}
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
                            color="primary"
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
                              : "Approve Mapping"}
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
                              : "Correct & Approve"}
                          </Button>

                          <Button
                            color="error"
                            variant="outlined"
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
                      sx={{ p: 2 }}
                    >
                      <Stack spacing={1.5}>
                        <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap>
                          <Chip
                            label={`APPROVED MAPPING v${mappingDecision.mapping.version}`}
                            color="success"
                            size="small"
                          />
                          <Chip
                            label={mappingDecision.mapping.status}
                            color={mappingDecision.mapping.status === "APPROVED" ? "success" : "warning"}
                            size="small"
                            variant="outlined"
                          />
                          <Chip
                            label={mappingDecision.mapping.active ? "ACTIVE" : "INACTIVE"}
                            size="small"
                            variant="outlined"
                          />
                          <Chip
                            label="STORED IN INTEGRITY LEDGER"
                            color="info"
                            size="small"
                            variant="outlined"
                          />
                        </Stack>

                        <Typography variant="body2">
                          <strong>Human Review Attribution:</strong> Action performed by{" "}
                          <strong>{mappingDecision.mapping.reviewer_id ?? "unknown"}</strong> ·
                          Stored with cryptographic hash chain ledger verification.
                        </Typography>

                        <Typography variant="body2" sx={{ fontStyle: "italic", color: "text.secondary" }}>
                          Under the PS 26155 deterministic contract, creating or approving a mapping does not alter historical analysis in place. The control result remains UNKNOWN until an explicit deterministic re-analysis is executed.
                        </Typography>

                        <Stack direction={{ xs: "column", sm: "row" }} spacing={1} sx={{ pt: 0.5 }}>
                          {mappingDecision.mapping.status === "APPROVED" &&
                            mappingDecision.mapping.active &&
                            !reanalysis && (
                              <Button
                                variant="contained"
                                color="success"
                                onClick={handleReanalyze}
                                disabled={reanalysisBusy}
                              >
                                {reanalyzingLabel(reanalysisBusy)}
                              </Button>
                            )}

                          {mappingDecision.mapping.active && (
                            <Button
                              variant="outlined"
                              color="warning"
                              onClick={handleDeactivateKnowledge}
                              disabled={mappingBusy || !reviewerId.trim()}
                            >
                              Deactivate knowledge
                            </Button>
                          )}
                        </Stack>
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

          {canAudit && analysis.results.some(
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
                          flexWrap="wrap"
                          useFlexGap
                        >
                          <Typography
                            variant="subtitle1"
                            fontWeight={700}
                          >
                            {remediation.control_id} ·{" "}
                            {remediation.title}
                          </Typography>

                          <Chip
                            label={remediation.platform ?? remediation.vendor}
                            size="small"
                            variant="outlined"
                            sx={{ fontWeight: 600, fontSize: "0.75rem" }}
                          />

                          <Chip
                            label={`Risk: ${remediation.risk_level}`}
                            size="small"
                            color="warning"
                          />
                          <Chip label={remediation.safety_classification.replaceAll("_", " ")} size="small" color="info" />
                        </Stack>

                        {remediation.finding && (
                          <Alert severity="error" variant="outlined" sx={{ py: 0.5, px: 1.5, fontSize: "0.85rem" }}>
                            <strong>Finding / Problem:</strong> {remediation.finding}
                          </Alert>
                        )}

                        <Typography variant="body2">
                          {remediation.description}
                        </Typography>

                        {remediation.explanation && (
                          <Typography variant="body2" color="text.secondary">
                            <strong>Rationale:</strong> {remediation.explanation}
                          </Typography>
                        )}

                        {remediation.applicability_notes && (
                          <Typography variant="body2" color="text.secondary" sx={{ fontStyle: "italic", bgcolor: "action.hover", p: 1, borderRadius: 1, borderLeft: "3px solid #f0883e" }}>
                            <strong>Applicability &amp; Constraints:</strong> {remediation.applicability_notes}
                          </Typography>
                        )}

                        <Typography
                          variant="caption"
                          color="text.secondary"
                        >
                          Target properties:{" "}
                          {remediation.target_properties.join(
                            ", "
                          )}
                        </Typography>
                        <Typography variant="caption" color="text.secondary">
                          {remediation.remediation_id} · {remediation.platform ?? remediation.vendor} · {remediation.simulation_capability}
                        </Typography>

                        {remediation.remediation_steps && remediation.remediation_steps.length > 0 && (
                          <Box sx={{ mt: 0.5 }}>
                            <Typography variant="caption" fontWeight={700} color="text.secondary" sx={{ textTransform: "uppercase", letterSpacing: 0.5 }}>
                              Step-by-Step Remediation Guidance
                            </Typography>
                            <Stack spacing={0.5} sx={{ mt: 0.5 }}>
                              {remediation.remediation_steps.map((step, idx) => (
                                <Box
                                  key={idx}
                                  sx={{
                                    p: 0.75,
                                    bgcolor: "#081627",
                                    color: "#c2e0ff",
                                    borderRadius: 1,
                                    fontFamily: "monospace",
                                    fontSize: "0.78rem",
                                    borderLeft: "3px solid #388bfd",
                                  }}
                                >
                                  {step}
                                </Box>
                              ))}
                            </Stack>
                          </Box>
                        )}

                        <Box sx={{ mt: 0.5 }}>
                          <Typography variant="caption" fontWeight={700} color="text.secondary" sx={{ textTransform: "uppercase", letterSpacing: 0.5 }}>
                            CLI Commands Sequence (Guidance Only)
                          </Typography>
                          <Box
                            component="pre"
                            sx={{
                              mt: 0.5,
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
                            mt: 0.5,
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
                          SIMULATION PREVIEW — Before:{" "}
                          {simulation.before_result} ·
                          After:{" "}
                          {simulation.after_result}
                        </Typography>
                        <Alert severity="warning"><strong>SIMULATION ONLY — NO DEVICE WAS MODIFIED</strong>. This preview is not a final compliance result.</Alert>
                        <Typography variant="caption" color="text.secondary">Simulation ID: {simulation.simulation_id} · Actor: {simulation.initiated_by ?? "Not available"} · {new Date(simulation.created_at).toLocaleString()}<br />Configuration fingerprint: {simulation.original_configuration_fingerprint ?? "Not available"}</Typography>

                        <Typography
                          variant="body2"
                          color="text.secondary"
                        >
                          {simulation.message}
                        </Typography>
                        <Button variant="contained" onClick={() => void handleSimulationReanalysis()} disabled={simulationBusy}> {simulationBusy ? "Re-analyzing…" : "Re-analyze simulation"}</Button>
                        {simulationReanalysis && <Alert severity="success"><strong>Deterministic re-analysis result</strong>: {simulationReanalysis.results.find(item => item.control_id === simulation.control_id)?.result ?? "UNKNOWN"}. Evidence is stored with analysis {simulationReanalysis.analysis_id}.</Alert>}

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
                <Alert severity="info" variant="outlined" sx={{ mt: 1.5, fontSize: "0.85rem" }}>
                  <strong>Compliance Authority:</strong> PASS / FAIL / UNKNOWN determinations are made exclusively by the deterministic control engine. Framework references (CIS, NIST, DISA STIG, ISO 27001) are advisory cross-references only.
                </Alert>
              </Box>

              <Box sx={{ overflowX: "auto" }}>
                <Table>
                  <TableHead>
                    <TableRow>
                      <TableCell>Control ID</TableCell>
                      <TableCell>Control name</TableCell>
                      <TableCell>Severity</TableCell>
                      <TableCell>Result</TableCell>
                      <TableCell>Frameworks</TableCell>
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
                            {result.diagnostic_of && (
                              <Typography variant="caption" display="block" color="text.secondary">
                                Diagnostic of {result.diagnostic_of}
                              </Typography>
                            )}
                          </TableCell>

                          <TableCell>
                            {result.severity ? (
                              <Chip
                                label={result.severity}
                                size="small"
                                color={
                                  result.severity === "CRITICAL"
                                    ? "error"
                                    : result.severity === "HIGH"
                                    ? "warning"
                                    : result.severity === "MEDIUM"
                                    ? "info"
                                    : "default"
                                }
                                variant="outlined"
                                sx={{ fontWeight: 600, fontSize: "0.7rem", height: 22 }}
                              />
                            ) : (
                              <Typography variant="body2" color="text.secondary">—</Typography>
                            )}
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
                            {result.framework_mappings && result.framework_mappings.length > 0 ? (
                              <Stack direction="row" spacing={0.5} flexWrap="wrap" useFlexGap sx={{ maxWidth: 220 }}>
                                {result.framework_mappings.map((fm, idx) => (
                                  <Chip
                                    key={`${fm.framework_name}-${fm.reference_id}-${idx}`}
                                    label={`${fm.framework_name} ${fm.reference_id}`}
                                    size="small"
                                    variant={fm.mapping_status === "PROTOTYPE" ? "outlined" : "filled"}
                                    color={fm.mapping_status === "PROTOTYPE" ? "default" : "primary"}
                                    sx={{ fontSize: "0.68rem", height: 20 }}
                                    title={fm.title ? `${fm.title}${fm.mapping_status === "PROTOTYPE" ? " (Prototype/Internal)" : ""}` : undefined}
                                  />
                                ))}
                              </Stack>
                            ) : (
                              <Typography variant="body2" color="text.secondary">—</Typography>
                            )}
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

                <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap>
                  <Chip
                    label={selectedResult.result}
                    color={statusColor(
                      selectedResult.result
                    )}
                    size="small"
                  />
                  {selectedResult.severity && (
                    <Chip
                      label={`Severity: ${selectedResult.severity}`}
                      size="small"
                      variant="outlined"
                      color={
                        selectedResult.severity === "CRITICAL"
                          ? "error"
                          : selectedResult.severity === "HIGH"
                          ? "warning"
                          : selectedResult.severity === "MEDIUM"
                          ? "info"
                          : "default"
                      }
                      sx={{ fontWeight: 600 }}
                    />
                  )}
                  {selectedResult.category && (
                    <Chip
                      label={selectedResult.category}
                      size="small"
                      variant="outlined"
                    />
                  )}
                </Stack>
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

                {selectedResult.framework_mappings && selectedResult.framework_mappings.length > 0 && (
                  <Paper variant="outlined" sx={{ p: 2, bgcolor: "action.hover" }}>
                    <Typography variant="subtitle2" fontWeight={700} gutterBottom>
                      Compliance Framework Cross-References (Advisory)
                    </Typography>
                    <Typography variant="caption" color="text.secondary" display="block" sx={{ mb: 1.5 }}>
                      Advisory cross-references to published security standards. Deterministic engine rules remain the sole compliance evaluation authority.
                    </Typography>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell sx={{ fontWeight: 600 }}>Framework</TableCell>
                          <TableCell sx={{ fontWeight: 600 }}>Version</TableCell>
                          <TableCell sx={{ fontWeight: 600 }}>Reference ID</TableCell>
                          <TableCell sx={{ fontWeight: 600 }}>Status</TableCell>
                          <TableCell sx={{ fontWeight: 600 }}>Title</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {selectedResult.framework_mappings.map((fm, idx) => (
                          <TableRow key={idx}>
                            <TableCell><strong>{fm.framework_name}</strong></TableCell>
                            <TableCell>{fm.framework_version ?? "—"}</TableCell>
                            <TableCell sx={{ fontFamily: "monospace", fontWeight: 600 }}>{fm.reference_id}</TableCell>
                            <TableCell>
                              <Chip
                                label={fm.mapping_status ?? "VERIFIED"}
                                size="small"
                                color={fm.mapping_status === "PROTOTYPE" ? "default" : "info"}
                                variant={fm.mapping_status === "PROTOTYPE" ? "outlined" : "filled"}
                                sx={{ fontSize: "0.65rem", height: 18 }}
                              />
                            </TableCell>
                            <TableCell>{fm.title ?? "—"}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </Paper>
                )}

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
