import test from "node:test";
import assert from "node:assert/strict";
import {
  validateEvidenceRecord,
  canClassifyClaimAsVerified
} from "../evidence.ts";

const validVerifiedEvidence = () => ({
  evidenceId: "EV-001",
  status: "VERIFIED",
  source: {
    uri: "https://api.github.com/repos/example/repo/commits/abc123",
    system: "github",
    authority: "AUTHORITATIVE",
    retrievedAt: "2026-11-18T08:55:00.000Z",
    observedAt: "2026-11-18T08:54:00.000Z",
    contentDigest: {
      algorithm: "SHA-256",
      value: "a".repeat(64)
    }
  },
  verification: {
    method: "authenticated-provider-read",
    verifier: "github-read-adapter",
    verifiedAt: "2026-11-18T08:55:01.000Z"
  }
});

test("accepts a verified record only with authoritative provenance and integrity metadata", () => {
  assert.deepEqual(validateEvidenceRecord(validVerifiedEvidence()), []);
});

test("rejects a verified record with a malformed SHA-256 digest", () => {
  const record = validVerifiedEvidence();
  record.source.contentDigest.value = "abc";
  assert.ok(validateEvidenceRecord(record).some(issue => issue.includes("digest")));
});

test("does not allow a reported source to qualify as verified evidence", () => {
  const record = {
    evidenceId: "EV-REPORTED",
    status: "REPORTED",
    source: {
      uri: "https://example.com/report",
      system: "external-report",
      authority: "NON_AUTHORITATIVE",
      retrievedAt: "2026-11-18T08:55:00.000Z"
    }
  };
  assert.deepEqual(validateEvidenceRecord(record), []);
  assert.equal(canClassifyClaimAsVerified([record]), false);
});

test("requires an explicit simulation label and scenario identifier", () => {
  const record = {
    evidenceId: "EV-SIM",
    status: "SIMULATED",
    simulation: { label: "SIMULATION_ONLY", scenarioId: "SCENARIO-1" }
  };
  assert.deepEqual(validateEvidenceRecord(record), []);
  record.simulation.label = "LIVE";
  assert.ok(validateEvidenceRecord(record).length > 0);
});

test("rejects a conflicted record without two distinct evidence references", () => {
  const record = {
    evidenceId: "EV-CONFLICT",
    status: "CONFLICTED",
    conflict: {
      reason: "Two authoritative sources disagree",
      withEvidenceIds: ["EV-002", "EV-002"]
    }
  };
  assert.ok(validateEvidenceRecord(record).some(issue => issue.includes("distinct")));
});

test("allows verified claim classification only when every supporting record is valid and verified", () => {
  assert.equal(canClassifyClaimAsVerified([validVerifiedEvidence()]), true);
  assert.equal(canClassifyClaimAsVerified([validVerifiedEvidence(), {
    evidenceId: "EV-SIM",
    status: "SIMULATED",
    simulation: { label: "SIMULATION_ONLY", scenarioId: "SCENARIO-1" }
  }]), false);
  assert.equal(canClassifyClaimAsVerified([]), false);
});

test("does not treat duplicate identifiers as independent verified support", () => {
  const record = validVerifiedEvidence();
  assert.equal(canClassifyClaimAsVerified([record, { ...record }]), false);
});
