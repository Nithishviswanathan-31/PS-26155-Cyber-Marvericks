import assert from "node:assert/strict";
import test from "node:test";

import { isSeverity, parseFrameworkMappings, parseResults } from "../src/api/framework-parsers.ts";

test("isSeverity correctly validates allowed severity levels", () => {
  assert.equal(isSeverity("LOW"), true);
  assert.equal(isSeverity("MEDIUM"), true);
  assert.equal(isSeverity("HIGH"), true);
  assert.equal(isSeverity("CRITICAL"), true);
  assert.equal(isSeverity("URGENT"), false);
  assert.equal(isSeverity(null), false);
  assert.equal(isSeverity(undefined), false);
  assert.equal(isSeverity(123), false);
});

test("parseFrameworkMappings parses verified and prototype mappings", () => {
  const input = [
    {
      framework_name: "CIS",
      framework_version: "v8",
      reference_id: "4.2",
      title: "Network Infrastructure",
      description: "Secure config",
      mapping_status: "VERIFIED",
    },
    {
      framework_name: "DISA_STIG",
      framework_version: "Network Device STIG",
      reference_id: "STIG-NET-MGT-001-PROTO",
      title: "Management Security (Prototype)",
      description: "Prototype mapping",
      mapping_status: "PROTOTYPE",
    },
  ];

  const parsed = parseFrameworkMappings(input);
  assert.equal(parsed.length, 2);

  assert.equal(parsed[0].framework_name, "CIS");
  assert.equal(parsed[0].framework_version, "v8");
  assert.equal(parsed[0].reference_id, "4.2");
  assert.equal(parsed[0].mapping_status, "VERIFIED");

  assert.equal(parsed[1].framework_name, "DISA_STIG");
  assert.equal(parsed[1].reference_id, "STIG-NET-MGT-001-PROTO");
  assert.equal(parsed[1].mapping_status, "PROTOTYPE");
});

test("parseFrameworkMappings handles non-array and invalid items gracefully", () => {
  assert.deepEqual(parseFrameworkMappings(null), []);
  assert.deepEqual(parseFrameworkMappings(undefined), []);
  assert.deepEqual(parseFrameworkMappings("not-an-array"), []);
  assert.deepEqual(parseFrameworkMappings([{ invalid: true }]), []);
});

test("parseResults parses full metadata when present", () => {
  const rawResults = [
    {
      control_id: "CTRL-001",
      control_name: "Secure management transport",
      result: "PASS",
      expected: "SSH enabled and Telnet disabled",
      actual: { "management.ssh_enabled": true, "management.telnet_enabled": false },
      explanation: "Conditions satisfied.",
      diagnostic_of: null,
      severity: "HIGH",
      category: "MANAGEMENT_ACCESS",
      framework_mappings: [
        {
          framework_name: "CIS",
          framework_version: "v8",
          reference_id: "4.2",
          title: "Network Infrastructure",
          mapping_status: "VERIFIED",
        },
      ],
    },
  ];

  const results = parseResults(rawResults);
  assert.ok(results);
  assert.equal(results.length, 1);
  assert.equal(results[0].control_id, "CTRL-001");
  assert.equal(results[0].severity, "HIGH");
  assert.equal(results[0].category, "MANAGEMENT_ACCESS");
  assert.equal(results[0].framework_mappings.length, 1);
  assert.equal(results[0].framework_mappings[0].framework_name, "CIS");
  assert.equal(results[0].framework_mappings[0].reference_id, "4.2");
});

test("parseResults falls back to safe defaults when metadata is missing (backward compatibility)", () => {
  const legacyRawResults = [
    {
      control_id: "CTRL-001",
      control_name: "Secure management transport",
      result: "FAIL",
      expected: "SSH enabled",
      actual: false,
      explanation: "Failed condition.",
    },
  ];

  const results = parseResults(legacyRawResults);
  assert.ok(results);
  assert.equal(results.length, 1);
  assert.equal(results[0].control_id, "CTRL-001");
  assert.equal(results[0].severity, null);
  assert.equal(results[0].category, null);
  assert.deepEqual(results[0].framework_mappings, []);
});
