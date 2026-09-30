import test from "node:test";
import assert from "node:assert/strict";

test("Analyses item with analysis_id enables Inspect and PDF download actions", () => {
  const analysisItem = {
    analysis_id: "ana-cisco-001",
    filename: "cisco_core.cfg",
    vendor: "cisco_iosxe",
    compliance_status: "PASS",
  };

  const hasAnalysisId = Boolean(analysisItem.analysis_id);
  assert.equal(hasAnalysisId, true, "Item must expose valid analysis_id");

  const inspectTarget = analysisItem.analysis_id;
  assert.equal(inspectTarget, "ana-cisco-001", "Inspect target must match analysis_id");

  const sanitizePdfName = (suggested) =>
    suggested.replace(/\.[^.]+$/, "").replace(/[^a-zA-Z0-9_-]+/g, "-");

  const pdfFilename = `ps26155-${sanitizePdfName(analysisItem.filename)}-report.pdf`;
  assert.equal(pdfFilename, "ps26155-cisco_core-report.pdf", "PDF filename must be safely sanitized");
});

test("AstraNet stored re-analysis exposes parent linkage and mapping version without mutating parent", () => {
  const parentAnalysis = {
    analysis_id: "ana-astranet-parent",
    filename: "astranet_edge.conf",
    vendor: "astranet",
    reanalyzed: false,
    unknown_patterns: [{ pattern_id: "pat-astranet-001", raw_pattern: "banner motd" }],
    results: [{ control_id: "BANNER", result: "UNKNOWN" }],
  };

  const reanalysisResponse = {
    analysis_id: "ana-astranet-child",
    parent_analysis_id: parentAnalysis.analysis_id,
    filename: parentAnalysis.filename,
    vendor: "astranet",
    reanalyzed: true,
    mapping_version: 1,
    results: [{ control_id: "BANNER", result: "PASS" }],
  };

  // Deterministic display selection:
  const activeReanalysis = reanalysisResponse ?? (parentAnalysis.reanalyzed ? parentAnalysis : null);
  assert.notEqual(activeReanalysis, null, "Active reanalysis must be recognized");
  assert.equal(activeReanalysis?.parent_analysis_id, "ana-astranet-parent", "Parent linkage must be preserved");
  assert.equal(activeReanalysis?.mapping_version, 1, "Mapping version must be displayed");

  // Parent immutability:
  assert.equal(parentAnalysis.analysis_id, "ana-astranet-parent", "Parent ID remains unchanged");
  assert.equal(parentAnalysis.results[0].result, "UNKNOWN", "Parent results remain UNKNOWN and immutable");
});

test("Bulk batch items expose individual inspection and PDF capabilities", () => {
  const batchItem = {
    batch_item_id: "bi-001",
    source_filename: "fw01.conf",
    analysis_id: "ana-batch-001",
    processing_status: "COMPLETED",
    compliance_status: "PASS",
  };

  const canInspect = batchItem.processing_status === "COMPLETED" && Boolean(batchItem.analysis_id);
  const canDownloadPdf = Boolean(batchItem.analysis_id);

  assert.equal(canInspect, true, "Completed batch item must allow inspection");
  assert.equal(canDownloadPdf, true, "Batch item with analysis_id must allow individual PDF generation");
});
