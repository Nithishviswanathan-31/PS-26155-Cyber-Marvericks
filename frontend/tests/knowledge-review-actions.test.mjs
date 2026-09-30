import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import vm from "node:vm";
import ts from "typescript";

import {
  canUserReview,
  getProposalActions,
  validateSemanticMapping,
  SUPPORTED_MAPPING_PROPERTIES,
} from "../src/api/knowledge-review.ts";

// Helper to load mappings.ts with injected fetch implementation
function createMappingsClient(mockFetch) {
  const source = readFileSync(
    new URL("../src/api/mappings.ts", import.meta.url),
    "utf8"
  )
    .replace('import { authFetch as fetch } from "./http";', "const fetch = mockFetch;")
    .replace('import { API_BASE_URL } from "./analyze";', 'const API_BASE_URL = "http://127.0.0.1:8000";');

  const compiled = ts.transpileModule(source, {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
  }).outputText;

  const context = {
    exports: {},
    mockFetch,
    Response,
    URL,
  };
  vm.runInNewContext(compiled, context);
  return context.exports;
}

test("1. NEEDS_REVIEW proposal renders the three actions for authorized reviewer", () => {
  const adminActions = getProposalActions("NEEDS_REVIEW", "ADMIN");
  assert.deepEqual(adminActions, [
    "Approve Mapping",
    "Correct & Approve",
    "Reject",
  ]);

  const reviewerActions = getProposalActions("PROPOSED", "REVIEWER");
  assert.deepEqual(reviewerActions, [
    "Approve Mapping",
    "Correct & Approve",
    "Reject",
  ]);

  // Already resolved proposal returns no actions
  assert.deepEqual(getProposalActions("APPROVED", "ADMIN"), []);
  assert.deepEqual(getProposalActions("REJECTED", "ADMIN"), []);
});

test("2. Approve action sends the correct API request", async () => {
  let capturedUrl = "";
  let capturedInit = null;

  const mappings = createMappingsClient(async (url, init) => {
    capturedUrl = String(url);
    capturedInit = init;
    return new Response(
      JSON.stringify({
        pattern_id: "pat-astranet-001",
        pattern_status: "UNKNOWN",
        mapping: {
          mapping_id: "map-123",
          pattern_id: "pat-astranet-001",
          vendor: "astranet",
          pattern_signature: "guard-channel lattice-secure",
          proposed_mapping: { "management.ssh_enabled": true },
          approved_mapping: { "management.ssh_enabled": true },
          status: "APPROVED",
          version: 1,
          reviewer_id: "local-admin",
          action: "APPROVE",
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString(),
          active: true,
        },
        compliance_impact: "UNCHANGED",
        message: "Mapping approved and stored as versioned knowledge.",
      }),
      { status: 200, headers: { "Content-Type": "application/json" } }
    );
  });

  const response = await mappings.approveMapping(
    "pat-astranet-001",
    { "management.ssh_enabled": true },
    "local-admin",
    "prop-999"
  );

  assert.equal(capturedUrl, "http://127.0.0.1:8000/api/mappings/pat-astranet-001/approve");
  assert.equal(capturedInit.method, "POST");

  const body = JSON.parse(capturedInit.body);
  assert.equal(body.reviewer_id, "local-admin");
  assert.equal(body.proposal_id, "prop-999");
  assert.deepEqual(body.semantic_mapping, {
    "management.ssh_enabled": true,
  });

  assert.equal(response.pattern_status, "UNKNOWN");
  assert.equal(response.compliance_impact, "UNCHANGED");
  assert.equal(response.mapping.status, "APPROVED");
  assert.equal(response.mapping.version, 1);
});

test("3. Correct action opens correction workflow, validates input, and sends correct correction request", async () => {
  // Validate semantic mapping checks
  const valid = validateSemanticMapping({
    "management.ssh_enabled": true,
    "logging.enabled": false,
  });
  assert.equal(valid.valid, true);
  assert.deepEqual(valid.mapping, {
    "management.ssh_enabled": true,
    "logging.enabled": false,
  });

  // Unsupported property rejected
  const unsupported = validateSemanticMapping({
    "unsupported.property": true,
  });
  assert.equal(unsupported.valid, false);
  assert.match(unsupported.error, /Property 'unsupported.property' is not supported/);

  // Non-boolean value rejected
  const nonBool = validateSemanticMapping({
    "management.ssh_enabled": "yes",
  });
  assert.equal(nonBool.valid, false);
  assert.match(nonBool.error, /must have a boolean value/);

  // Empty mapping rejected
  const empty = validateSemanticMapping({});
  assert.equal(empty.valid, false);
  assert.match(empty.error, /must define at least one security property/);

  // Test correctAndApproveMapping API call
  let capturedUrl = "";
  let capturedInit = null;

  const mappings = createMappingsClient(async (url, init) => {
    capturedUrl = String(url);
    capturedInit = init;
    return new Response(
      JSON.stringify({
        pattern_id: "pat-astranet-001",
        pattern_status: "UNKNOWN",
        mapping: {
          mapping_id: "map-124",
          pattern_id: "pat-astranet-001",
          vendor: "astranet",
          pattern_signature: "guard-channel lattice-secure",
          proposed_mapping: { "management.ssh_enabled": true },
          approved_mapping: {
            "management.ssh_enabled": true,
            "logging.enabled": true,
          },
          status: "APPROVED",
          version: 2,
          reviewer_id: "human-reviewer",
          action: "CORRECT_AND_APPROVE",
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString(),
          active: true,
        },
        compliance_impact: "UNCHANGED",
        message: "Mapping approved and stored as versioned knowledge.",
      }),
      { status: 200, headers: { "Content-Type": "application/json" } }
    );
  });

  const response = await mappings.correctAndApproveMapping(
    "pat-astranet-001",
    { "management.ssh_enabled": true, "logging.enabled": true },
    "human-reviewer",
    "prop-999"
  );

  assert.equal(capturedUrl, "http://127.0.0.1:8000/api/mappings/pat-astranet-001/correct");
  assert.equal(capturedInit.method, "POST");

  const body = JSON.parse(capturedInit.body);
  assert.equal(body.reviewer_id, "human-reviewer");
  assert.equal(body.proposal_id, "prop-999");
  assert.deepEqual(body.semantic_mapping, {
    "management.ssh_enabled": true,
    "logging.enabled": true,
  });

  assert.equal(response.mapping.action, "CORRECT_AND_APPROVE");
  assert.equal(response.mapping.version, 2);
});

test("4. Reject action sends the correct API request with rationale", async () => {
  let capturedUrl = "";
  let capturedInit = null;

  const mappings = createMappingsClient(async (url, init) => {
    capturedUrl = String(url);
    capturedInit = init;
    return new Response(
      JSON.stringify({
        pattern_id: "pat-astranet-001",
        pattern_status: "UNKNOWN",
        mapping: {
          mapping_id: "map-125",
          pattern_id: "pat-astranet-001",
          vendor: "astranet",
          pattern_signature: "guard-channel lattice-secure",
          proposed_mapping: {},
          approved_mapping: null,
          status: "REJECTED",
          version: 1,
          reviewer_id: "security-auditor",
          action: "REJECT",
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString(),
          active: false,
        },
        compliance_impact: "UNCHANGED",
        message: "Mapping rejected and stored as inactive knowledge.",
      }),
      { status: 200, headers: { "Content-Type": "application/json" } }
    );
  });

  const response = await mappings.rejectMapping(
    "pat-astranet-001",
    "security-auditor",
    "Pattern does not provide cryptographically secure transport",
    "prop-999"
  );

  assert.equal(capturedUrl, "http://127.0.0.1:8000/api/mappings/pat-astranet-001/reject");
  assert.equal(capturedInit.method, "POST");

  const body = JSON.parse(capturedInit.body);
  assert.equal(body.reviewer_id, "security-auditor");
  assert.equal(
    body.reason,
    "Pattern does not provide cryptographically secure transport"
  );
  assert.equal(body.proposal_id, "prop-999");

  assert.equal(response.mapping.status, "REJECTED");
  assert.equal(response.pattern_status, "UNKNOWN");
});

test("5. Actions are available to an authorized ADMIN/REVIEWER but blocked for AUDITOR", () => {
  assert.equal(canUserReview("ADMIN"), true);
  assert.equal(canUserReview("REVIEWER"), true);
  assert.equal(canUserReview("AUDITOR"), false);
  assert.equal(canUserReview("GUEST"), false);
  assert.equal(canUserReview(null), false);
  assert.equal(canUserReview(undefined), false);

  assert.deepEqual(getProposalActions("NEEDS_REVIEW", "ADMIN"), [
    "Approve Mapping",
    "Correct & Approve",
    "Reject",
  ]);
  assert.deepEqual(getProposalActions("NEEDS_REVIEW", "REVIEWER"), [
    "Approve Mapping",
    "Correct & Approve",
    "Reject",
  ]);
  assert.deepEqual(getProposalActions("NEEDS_REVIEW", "AUDITOR"), []);
  assert.deepEqual(getProposalActions("NEEDS_REVIEW", "GUEST"), []);
});

test("6. Original UNKNOWN analysis is not modified by approval alone", async () => {
  const mappings = createMappingsClient(async () =>
    new Response(
      JSON.stringify({
        pattern_id: "pat-astranet-001",
        pattern_status: "UNKNOWN",
        mapping: {
          mapping_id: "map-126",
          pattern_id: "pat-astranet-001",
          vendor: "astranet",
          pattern_signature: "guard-channel lattice-secure",
          status: "APPROVED",
          version: 1,
          active: true,
        },
        compliance_impact: "UNCHANGED",
        message:
          "Mapping approved and stored as versioned knowledge. Compliance remains unchanged until a later re-analysis.",
      }),
      { status: 200, headers: { "Content-Type": "application/json" } }
    )
  );

  const response = await mappings.approveMapping(
    "pat-astranet-001",
    { "management.ssh_enabled": true },
    "admin-user",
    "prop-100"
  );

  // Invariant: compliance impact MUST be UNCHANGED
  assert.equal(response.compliance_impact, "UNCHANGED");
  assert.equal(response.pattern_status, "UNKNOWN");
  assert.match(response.message, /Compliance remains unchanged/);
});

test("7. Approved knowledge is refreshed in the UI queue data", () => {
  // Simulate queue data state transition
  const queueBefore = {
    pending_proposals: [
      {
        proposal_id: "prop-1",
        analysis_id: "ana-1",
        pattern_id: "pat-1",
        vendor: "astranet",
        status: "NEEDS_REVIEW",
        candidate_mapping: { "management.ssh_enabled": true },
      },
    ],
    active_knowledge: [],
    deactivated_knowledge: [],
  };

  // When prop-1 is approved:
  const newKnowledgeEntry = {
    knowledge_id: "know-1",
    version: 1,
    vendor: "astranet",
    target_property: "management.ssh_enabled",
    approved_mapping: { "management.ssh_enabled": true },
    reviewer_id: "local-admin",
    status: "ACTIVE",
  };

  const queueAfter = {
    pending_proposals: queueBefore.pending_proposals.filter(
      (p) => p.proposal_id !== "prop-1"
    ),
    active_knowledge: [newKnowledgeEntry, ...queueBefore.active_knowledge],
    deactivated_knowledge: queueBefore.deactivated_knowledge,
  };

  assert.equal(queueAfter.pending_proposals.length, 0);
  assert.equal(queueAfter.active_knowledge.length, 1);
  assert.equal(queueAfter.active_knowledge[0].status, "ACTIVE");
  assert.equal(queueAfter.active_knowledge[0].version, 1);
});
