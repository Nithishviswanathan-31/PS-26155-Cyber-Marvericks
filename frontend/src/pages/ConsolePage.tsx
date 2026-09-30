import { useEffect, useState } from "react";
import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  CircularProgress,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Divider,
  FormControlLabel,
  Paper,
  Snackbar,
  Stack,
  Switch,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
  TextField,
  Tooltip,
  Typography,
} from "@mui/material";
import { CheckCircle, Edit, Cancel, Block } from "@mui/icons-material";
import { consoleGet, type ConsolePage as ConsolePageType } from "../api/console";
import {
  approveMapping,
  correctAndApproveMapping,
  rejectMapping,
  deactivateKnowledge,
  type SemanticMapping,
} from "../api/mappings";
import { useAuth, type SessionUser } from "../auth/AuthProvider";
import {
  canUserReview,
  getProposalActions,
  validateSemanticMapping,
  SUPPORTED_MAPPING_PROPERTIES,
} from "../api/knowledge-review";

interface PendingProposalItem {
  proposal_id: string;
  analysis_id: string;
  pattern_id: string;
  vendor: string;
  pattern_signature: string;
  candidate_property?: string;
  candidate_value?: boolean;
  candidate_mapping?: Record<string, boolean>;
  confidence?: number;
  status: string;
  explanation?: string;
}

interface ActiveKnowledgeItem {
  knowledge_id: string;
  version: number;
  vendor: string;
  target_property: string;
  approved_mapping?: Record<string, boolean>;
  reviewer_id?: string;
  status: string;
  created_at?: string;
}

interface DeactivatedKnowledgeItem {
  knowledge_id: string;
  version: number;
  vendor: string;
  target_property: string;
  reviewer_id?: string;
  status: string;
}

interface KnowledgeQueueData {
  pending_proposals?: PendingProposalItem[];
  active_knowledge?: ActiveKnowledgeItem[];
  deactivated_knowledge?: DeactivatedKnowledgeItem[];
  conflicts?: unknown[];
}

type ActionKind = "approve" | "correct" | "reject" | "deactivate";

interface ActionState {
  kind: ActionKind;
  patternId: string;
  proposalId?: string | null;
  knowledgeId?: string;
  initialMapping: SemanticMapping;
  label: string;
  proposalDetails?: {
    proposalId: string;
    vendor: string;
    confidence?: number;
    explanation?: string;
  };
}

function KnowledgeActionDialog({
  action,
  currentUser,
  onClose,
  onDone,
}: {
  action: ActionState;
  currentUser: SessionUser;
  onClose: () => void;
  onDone: (message: string) => void;
}) {
  const defaultReviewer = currentUser.offline
    ? "local-admin"
    : (currentUser.user_id || currentUser.username || "local-admin");

  const [reviewerId, setReviewerId] = useState(defaultReviewer);
  const [correctedMapping, setCorrectedMapping] = useState<SemanticMapping>({
    ...action.initialMapping,
  });
  const [mappingJson, setMappingJson] = useState(
    JSON.stringify(action.initialMapping, null, 2)
  );
  const [rejectReason, setRejectReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const handlePropertyToggle = (prop: string, checked: boolean) => {
    const updated = { ...correctedMapping, [prop]: checked };
    setCorrectedMapping(updated);
    setMappingJson(JSON.stringify(updated, null, 2));
    setErr(null);
  };

  const handleJsonChange = (raw: string) => {
    setMappingJson(raw);
    try {
      const parsed = JSON.parse(raw) as unknown;
      const validation = validateSemanticMapping(parsed);
      if (validation.valid && validation.mapping) {
        setCorrectedMapping(validation.mapping);
        setErr(null);
      } else {
        setErr(validation.error ?? "Invalid mapping");
      }
    } catch {
      setErr("Invalid JSON format");
    }
  };

  const handleSubmit = async () => {
    setBusy(true);
    setErr(null);

    const activeReviewer = reviewerId.trim() || defaultReviewer;

    try {
      if (action.kind === "approve") {
        await approveMapping(
          action.patternId,
          action.initialMapping,
          activeReviewer,
          action.proposalId
        );
        onDone(`Mapping approved by ${activeReviewer}. Versioned knowledge updated.`);
      } else if (action.kind === "correct") {
        const validation = validateSemanticMapping(correctedMapping);
        if (!validation.valid || !validation.mapping) {
          setErr(validation.error ?? "Please provide a valid semantic mapping.");
          setBusy(false);
          return;
        }
        await correctAndApproveMapping(
          action.patternId,
          validation.mapping,
          activeReviewer,
          action.proposalId
        );
        onDone(`Corrected mapping approved by ${activeReviewer}. New version saved.`);
      } else if (action.kind === "reject") {
        await rejectMapping(
          action.patternId,
          activeReviewer,
          rejectReason.trim() || undefined,
          action.proposalId
        );
        onDone(`Proposal rejected by ${activeReviewer}. Pattern remains UNKNOWN.`);
      } else if (action.kind === "deactivate" && action.knowledgeId) {
        await deactivateKnowledge(action.knowledgeId, activeReviewer);
        onDone(`Knowledge entry ${action.knowledgeId} deactivated.`);
      }
    } catch (e: unknown) {
      setErr(e instanceof Error ? e.message : "The action could not be completed.");
      setBusy(false);
    }
  };

  const isApprove = action.kind === "approve";
  const isCorrect = action.kind === "correct";
  const isReject = action.kind === "reject";
  const isDeactivate = action.kind === "deactivate";

  return (
    <Dialog open maxWidth="sm" fullWidth onClose={onClose}>
      <DialogTitle>
        {isApprove && "Approve AI Candidate Mapping"}
        {isCorrect && "Correct & Approve Candidate Mapping"}
        {isReject && "Reject AI Candidate Mapping"}
        {isDeactivate && "Deactivate Knowledge Entry"}
      </DialogTitle>
      <DialogContent>
        <Stack spacing={2} sx={{ mt: 1 }}>
          {err && <Alert severity="error">{err}</Alert>}

          {action.proposalDetails && (
            <Paper variant="outlined" sx={{ p: 1.5, bgcolor: "action.hover" }}>
              <Typography variant="caption" color="text.secondary" display="block">
                Proposal: <strong>{action.proposalDetails.proposalId}</strong> · Vendor: <strong>{action.proposalDetails.vendor}</strong>
                {action.proposalDetails.confidence !== undefined && (
                  <> · Confidence: <strong>{(action.proposalDetails.confidence * 100).toFixed(0)}%</strong></>
                )}
              </Typography>
              {action.proposalDetails.explanation && (
                <Typography variant="body2" sx={{ mt: 0.5, fontStyle: "italic" }}>
                  "{action.proposalDetails.explanation}"
                </Typography>
              )}
            </Paper>
          )}

          <TextField
            label="Reviewer Identity"
            size="small"
            value={reviewerId}
            onChange={(e) => setReviewerId(e.target.value)}
            disabled={busy}
            helperText="Recorded in the immutable hash-chain ledger for attribution."
            required
            fullWidth
          />

          {isApprove && (
            <Box>
              <Typography variant="subtitle2" sx={{ mb: 0.5 }}>
                Candidate Mapping to Approve:
              </Typography>
              <Box
                component="pre"
                sx={{
                  bgcolor: "background.paper",
                  p: 1.5,
                  borderRadius: 1,
                  border: "1px solid",
                  borderColor: "divider",
                  fontSize: "0.85rem",
                  fontFamily: "monospace",
                  m: 0,
                }}
              >
                {JSON.stringify(action.initialMapping, null, 2)}
              </Box>
            </Box>
          )}

          {isCorrect && (
            <Stack spacing={1.5}>
              <Typography variant="subtitle2">
                Adjust Target Security Properties:
              </Typography>
              <Stack direction="row" flexWrap="wrap" gap={1}>
                {SUPPORTED_MAPPING_PROPERTIES.map((prop) => {
                  const isChecked = correctedMapping[prop] === true;
                  return (
                    <FormControlLabel
                      key={prop}
                      control={
                        <Switch
                          size="small"
                          checked={isChecked}
                          onChange={(e) => handlePropertyToggle(prop, e.target.checked)}
                          disabled={busy}
                        />
                      }
                      label={
                        <Typography variant="caption" sx={{ fontFamily: "monospace" }}>
                          {prop}
                        </Typography>
                      }
                    />
                  );
                })}
              </Stack>

              <TextField
                label="Custom Mapping JSON"
                size="small"
                multiline
                rows={4}
                value={mappingJson}
                onChange={(e) => handleJsonChange(e.target.value)}
                disabled={busy}
                inputProps={{ style: { fontFamily: "monospace", fontSize: "0.82rem" } }}
                helperText="Must be valid JSON object with supported properties and strict booleans."
                fullWidth
              />
            </Stack>
          )}

          {isReject && (
            <TextField
              label="Rejection Rationale"
              size="small"
              multiline
              rows={3}
              value={rejectReason}
              onChange={(e) => setRejectReason(e.target.value)}
              disabled={busy}
              placeholder="e.g. Pattern does not represent an approved cryptographic transport channel."
              helperText="Recorded in the audit ledger alongside the rejection decision."
              fullWidth
            />
          )}

          {isDeactivate && (
            <Alert severity="warning">
              Deactivating this knowledge entry revokes it from future re-analyses. Historical analyses remain immutable.
            </Alert>
          )}

          <Alert severity="info" sx={{ fontSize: "0.8rem" }}>
            <strong>Governance Invariant:</strong>{" "}
            {isReject
              ? "Rejecting records an inactive decision. The pattern remains UNKNOWN and will not match in future re-analyses."
              : "Compliance determinations are produced only by the deterministic control engine during explicit re-analysis. Approval alone does not alter original analysis results."}
          </Alert>
        </Stack>
      </DialogContent>
      <DialogActions sx={{ px: 3, pb: 2 }}>
        <Button onClick={onClose} disabled={busy}>
          Cancel
        </Button>
        <Button
          variant="contained"
          onClick={handleSubmit}
          disabled={busy || !reviewerId.trim()}
          color={isReject || isDeactivate ? "error" : isApprove ? "success" : "primary"}
        >
          {busy && <CircularProgress size={16} sx={{ mr: 1 }} />}
          {action.label}
        </Button>
      </DialogActions>
    </Dialog>
  );
}

export default function ConsolePage({
  title,
  path,
}: {
  title: string;
  path: string;
}) {
  let currentUser: SessionUser = {
    user_id: "local-admin",
    username: "admin",
    display_name: "Local Admin",
    role: "ADMIN",
    offline: true,
  };
  try {
    const auth = useAuth();
    if (auth?.user) currentUser = auth.user;
  } catch {
    // Graceful fallback for non-auth test environments
  }

  const [data, setData] = useState<ConsolePageType | Record<string, unknown> | null>(null);
  const [q, setQ] = useState("");
  const [error, setError] = useState(false);
  const [offset, setOffset] = useState(0);
  const [activeAction, setActiveAction] = useState<ActionState | null>(null);
  const [notification, setNotification] = useState<string | null>(null);

  const load = () => {
    setData(null);
    setError(false);
    consoleGet(
      `${path}${path.includes("?") ? "&" : "?"}offset=${offset}&limit=25${
        q ? `&q=${encodeURIComponent(q)}` : ""
      }`
    )
      .then(setData)
      .catch(() => setError(true));
  };

  useEffect(load, [path, offset, q]);

  if (error) {
    return <Alert severity="error">Unable to load persisted auditor data.</Alert>;
  }
  if (!data) {
    return (
      <Box sx={{ p: 4, textAlign: "center" }}>
        <CircularProgress />
      </Box>
    );
  }

  // Specialized view for Knowledge Review Queue
  if (title === "Knowledge Review Queue" || ("active_knowledge" in data || "pending_proposals" in data)) {
    const kq = data as unknown as KnowledgeQueueData;
    const pending = kq.pending_proposals ?? [];
    const active = kq.active_knowledge ?? [];
    const deactivated = kq.deactivated_knowledge ?? [];
    const isAuthorized = canUserReview(currentUser.role);

    return (
      <Stack spacing={3}>
        {activeAction && (
          <KnowledgeActionDialog
            action={activeAction}
            currentUser={currentUser}
            onClose={() => setActiveAction(null)}
            onDone={(msg) => {
              setActiveAction(null);
              setNotification(msg);
              load();
            }}
          />
        )}

        <Snackbar
          open={Boolean(notification)}
          autoHideDuration={5000}
          onClose={() => setNotification(null)}
          message={notification}
        />

        <Box>
          <Typography variant="overline" color="secondary.main" letterSpacing={1.5}>
            ADAPTIVE AI KNOWLEDGE BASE · HUMAN-IN-THE-LOOP REVIEW
          </Typography>
          <Typography variant="h4" sx={{ mt: 0.5 }}>
            {title}
          </Typography>
          <Typography color="text.secondary" sx={{ mt: 0.5 }}>
            Audit and govern candidate interpretations and versioned knowledge. AI proposes candidate mappings; human reviewers inspect, approve, correct, or reject them. Approved knowledge is versioned and applied only during explicit re-analysis.
          </Typography>
        </Box>

        <Alert severity="info">
          <strong>Core Governance Principle:</strong> AI proposals are candidate interpretations only and never establish compliance directly. Compliance evaluation remains 100% deterministic and evidence-backed.
        </Alert>

        {/* Section 1: Pending AI Interpretation Proposals */}
        <Card variant="outlined">
          <CardContent>
            <Stack spacing={1.5}>
              <Stack direction="row" justifyContent="space-between" alignItems="center">
                <Box>
                  <Typography variant="h6">Pending AI Proposals Awaiting Human Review</Typography>
                  <Typography variant="body2" color="text.secondary">
                    Candidate mappings generated by the controlled interpretation provider requiring reviewer approval.
                  </Typography>
                </Box>
                <Chip
                  label={`${pending.length} Pending`}
                  color={pending.length > 0 ? "warning" : "default"}
                  size="small"
                />
              </Stack>
              <Divider />
              {pending.length === 0 ? (
                <Typography variant="body2" color="text.secondary" sx={{ py: 2 }}>
                  No pending AI proposals awaiting review. All candidate mappings have been resolved or none are queued.
                </Typography>
              ) : (
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell>Proposal ID</TableCell>
                      <TableCell>Vendor</TableCell>
                      <TableCell>Target Candidate Mapping</TableCell>
                      <TableCell>Confidence</TableCell>
                      <TableCell>Status</TableCell>
                      <TableCell align="right" sx={{ minWidth: 320 }}>
                        Actions
                      </TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {pending.map((item) => {
                      const actions = getProposalActions(item.status, currentUser.role);
                      const mapping = item.candidate_mapping ?? (item.candidate_property && item.candidate_value !== undefined ? { [item.candidate_property]: item.candidate_value } : {});

                      return (
                        <TableRow key={item.proposal_id}>
                          <TableCell sx={{ fontFamily: "monospace", fontSize: "0.8rem" }}>
                            {item.proposal_id}
                          </TableCell>
                          <TableCell>
                            <Chip label={item.vendor} size="small" variant="outlined" />
                          </TableCell>
                          <TableCell>
                            <Typography variant="body2" sx={{ fontFamily: "monospace" }}>
                              {JSON.stringify(mapping)}
                            </Typography>
                            {item.explanation && (
                              <Typography variant="caption" color="text.secondary" display="block">
                                {item.explanation}
                              </Typography>
                            )}
                          </TableCell>
                          <TableCell>
                            {item.confidence !== undefined
                              ? `${(item.confidence * 100).toFixed(0)}%`
                              : "—"}
                          </TableCell>
                          <TableCell>
                            <Chip label={item.status} size="small" color="warning" />
                          </TableCell>
                          <TableCell align="right" sx={{ whiteSpace: "nowrap" }}>
                            {actions.length > 0 ? (
                              <Stack direction="row" spacing={1} justifyContent="flex-end">
                                <Button
                                  size="small"
                                  variant="contained"
                                  color="success"
                                  startIcon={<CheckCircle />}
                                  onClick={() =>
                                    setActiveAction({
                                      kind: "approve",
                                      patternId: item.pattern_id,
                                      proposalId: item.proposal_id,
                                      initialMapping: mapping,
                                      label: "Approve Mapping",
                                      proposalDetails: {
                                        proposalId: item.proposal_id,
                                        vendor: item.vendor,
                                        confidence: item.confidence,
                                        explanation: item.explanation,
                                      },
                                    })
                                  }
                                >
                                  Approve Mapping
                                </Button>
                                <Button
                                  size="small"
                                  variant="outlined"
                                  color="primary"
                                  startIcon={<Edit />}
                                  onClick={() =>
                                    setActiveAction({
                                      kind: "correct",
                                      patternId: item.pattern_id,
                                      proposalId: item.proposal_id,
                                      initialMapping: mapping,
                                      label: "Correct & Approve",
                                      proposalDetails: {
                                        proposalId: item.proposal_id,
                                        vendor: item.vendor,
                                        confidence: item.confidence,
                                        explanation: item.explanation,
                                      },
                                    })
                                  }
                                >
                                  Correct & Approve
                                </Button>
                                <Button
                                  size="small"
                                  variant="outlined"
                                  color="error"
                                  startIcon={<Cancel />}
                                  onClick={() =>
                                    setActiveAction({
                                      kind: "reject",
                                      patternId: item.pattern_id,
                                      proposalId: item.proposal_id,
                                      initialMapping: mapping,
                                      label: "Reject",
                                      proposalDetails: {
                                        proposalId: item.proposal_id,
                                        vendor: item.vendor,
                                        confidence: item.confidence,
                                        explanation: item.explanation,
                                      },
                                    })
                                  }
                                >
                                  Reject
                                </Button>
                              </Stack>
                            ) : (
                              <Typography variant="caption" color="text.secondary">
                                {!isAuthorized ? "Reviewer role required" : item.status}
                              </Typography>
                            )}
                          </TableCell>
                        </TableRow>
                      );
                    })}
                  </TableBody>
                </Table>
              )}
            </Stack>
          </CardContent>
        </Card>

        {/* Section 2: Active Approved Knowledge Base */}
        <Card variant="outlined">
          <CardContent>
            <Stack spacing={1.5}>
              <Stack direction="row" justifyContent="space-between" alignItems="center">
                <Box>
                  <Typography variant="h6">Active Approved Knowledge Base (Versioned)</Typography>
                  <Typography variant="body2" color="text.secondary">
                    Versioned semantic mappings authorized by human reviewers, available for mapping-aware re-analysis.
                  </Typography>
                </Box>
                <Chip
                  label={`${active.length} Active`}
                  color={active.length > 0 ? "success" : "default"}
                  size="small"
                />
              </Stack>
              <Divider />
              {active.length === 0 ? (
                <Typography variant="body2" color="text.secondary" sx={{ py: 2 }}>
                  No active approved knowledge entries currently stored.
                </Typography>
              ) : (
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell>Knowledge ID</TableCell>
                      <TableCell>Version</TableCell>
                      <TableCell>Vendor</TableCell>
                      <TableCell>Target Property</TableCell>
                      <TableCell>Approved Mapping</TableCell>
                      <TableCell>Reviewer</TableCell>
                      <TableCell>Status</TableCell>
                      {isAuthorized && <TableCell align="right">Actions</TableCell>}
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {active.map((item) => (
                      <TableRow key={`${item.knowledge_id}-v${item.version}`}>
                        <TableCell sx={{ fontFamily: "monospace", fontSize: "0.8rem" }}>
                          {item.knowledge_id}
                        </TableCell>
                        <TableCell>
                          <Chip label={`v${item.version}`} size="small" color="primary" variant="outlined" />
                        </TableCell>
                        <TableCell>{item.vendor}</TableCell>
                        <TableCell sx={{ fontFamily: "monospace" }}>{item.target_property}</TableCell>
                        <TableCell sx={{ fontFamily: "monospace" }}>
                          {JSON.stringify(item.approved_mapping ?? {})}
                        </TableCell>
                        <TableCell>{item.reviewer_id ?? "unknown"}</TableCell>
                        <TableCell>
                          <Chip label={item.status} size="small" color="success" />
                        </TableCell>
                        {isAuthorized && (
                          <TableCell align="right">
                            <Tooltip title="Deactivate — revoke this approved knowledge from future re-analyses">
                              <Button
                                size="small"
                                variant="outlined"
                                color="error"
                                startIcon={<Block />}
                                onClick={() =>
                                  setActiveAction({
                                    kind: "deactivate",
                                    patternId: item.knowledge_id,
                                    knowledgeId: item.knowledge_id,
                                    initialMapping: item.approved_mapping ?? {},
                                    label: "Deactivate Knowledge",
                                  })
                                }
                              >
                                Deactivate
                              </Button>
                            </Tooltip>
                          </TableCell>
                        )}
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </Stack>
          </CardContent>
        </Card>

        {/* Section 3: Deactivated Knowledge */}
        {deactivated.length > 0 && (
          <Card variant="outlined">
            <CardContent>
              <Stack spacing={1.5}>
                <Typography variant="h6">Deactivated Knowledge History</Typography>
                <Divider />
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell>Knowledge ID</TableCell>
                      <TableCell>Version</TableCell>
                      <TableCell>Vendor</TableCell>
                      <TableCell>Target Property</TableCell>
                      <TableCell>Reviewer</TableCell>
                      <TableCell>Status</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {deactivated.map((item) => (
                      <TableRow key={`${item.knowledge_id}-v${item.version}`}>
                        <TableCell sx={{ fontFamily: "monospace", fontSize: "0.8rem" }}>
                          {item.knowledge_id}
                        </TableCell>
                        <TableCell>v{item.version}</TableCell>
                        <TableCell>{item.vendor}</TableCell>
                        <TableCell sx={{ fontFamily: "monospace" }}>{item.target_property}</TableCell>
                        <TableCell>{item.reviewer_id ?? "unknown"}</TableCell>
                        <TableCell>
                          <Chip label={item.status} size="small" />
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </Stack>
            </CardContent>
          </Card>
        )}
      </Stack>
    );
  }

  // Standard generic console view for Devices, Configurations, Analyses, Batches, etc.
  const page = "items" in data ? (data as ConsolePageType) : null;
  const items = page ? page.items : [];
  const columns = items[0]
    ? Object.keys(items[0])
        .filter(
          (k) =>
            !["results", "evidence", "unknown_patterns", "metadata_provenance"].includes(k)
        )
        .slice(0, 10)
    : [];

  return (
    <Stack spacing={2}>
      <Box>
        <Typography variant="overline" color="secondary.main">
          PERSISTENT AUDITOR CONSOLE
        </Typography>
        <Typography variant="h4">{title}</Typography>
      </Box>
      <TextField
        size="small"
        label="Search persisted records"
        value={q}
        onChange={(e) => {
          setQ(e.target.value);
          setOffset(0);
        }}
      />
      <Card>
        <CardContent>
          {!page ? (
            <pre>{JSON.stringify(data, null, 2)}</pre>
          ) : items.length === 0 ? (
            <Typography color="text.secondary">
              No persisted records match this view.
            </Typography>
          ) : (
            <>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    {columns.map((c) => (
                      <TableCell key={c}>{c.replaceAll("_", " ")}</TableCell>
                    ))}
                  </TableRow>
                </TableHead>
                <TableBody>
                  {items.map((item, i) => (
                    <TableRow
                      key={String(
                        item.analysis_id ??
                          item.device_id ??
                          item.configuration_id ??
                          item.batch_id ??
                          i
                      )}
                    >
                      {columns.map((c) => (
                        <TableCell key={c}>
                          {typeof item[c] === "object" ? (
                            <Chip size="small" label={JSON.stringify(item[c]).slice(0, 56)} />
                          ) : (
                            String(item[c] ?? "—")
                          )}
                        </TableCell>
                      ))}
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
              <Stack direction="row" justifyContent="space-between" sx={{ mt: 2 }}>
                <Typography variant="caption">{page.total} persisted records</Typography>
                <Stack direction="row" spacing={1}>
                  <Button
                    disabled={!offset}
                    onClick={() => setOffset(Math.max(0, offset - 25))}
                  >
                    Previous
                  </Button>
                  <Button
                    disabled={offset + page.limit >= page.total}
                    onClick={() => setOffset(offset + 25)}
                  >
                    Next
                  </Button>
                </Stack>
              </Stack>
            </>
          )}
        </CardContent>
      </Card>
    </Stack>
  );
}
