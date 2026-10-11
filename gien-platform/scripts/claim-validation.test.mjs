import test from "node:test";
import assert from "node:assert/strict";
import { validateClaimRecord, validateClaimSet } from "../src/evidence/claim-validation.mjs";

const NOW = new Date("2026-10-12T12:00:00.000Z");

function source(overrides = {}) {
  return {
    id: "SRC-001",
    url: "https://example.org/standard",
    title: "Example primary source",
    excerpt: "The cited passage is preserved here for manual claim verification.",
    retrievedAt: "2026-10-12T10:00:00.000Z",
    ...overrides,
  };
}

function supportedClaim(overrides = {}) {
  return {
    id: "CLM-001",
    text: "The example source supports this test claim.",
    sources: [source()],
    verdict: "SUPPORTED",
    review: {
      reviewer: "reviewer@example.org",
      reviewedAt: "2026-10-12T11:00:00.000Z",
      rationale: "Manually compared the claim wording with the recorded supporting passage.",
    },
    ...overrides,
  };
}

test("a fully evidenced, recently retrieved and reviewed supported claim is eligible", () => {
  const result = validateClaimRecord(supportedClaim(), { now: NOW });
  assert.equal(result.eligibleForRelease, true);
  assert.deepEqual(result.issues, []);
});

test("missing sources block an otherwise supported claim", () => {
  const result = validateClaimRecord(supportedClaim({ sources: [] }), { now: NOW });
  assert.equal(result.eligibleForRelease, false);
  assert.ok(result.issues.some((issue) => issue.code === "MISSING_SOURCE"));
});

test("non-HTTPS sources are rejected", () => {
  const result = validateClaimRecord(supportedClaim({ sources: [source({ url: "http://example.org/source" })] }), { now: NOW });
  assert.ok(result.issues.some((issue) => issue.code === "INVALID_SOURCE_URL"));
  assert.equal(result.eligibleForRelease, false);
});

test("URLs embedding credentials are rejected", () => {
  const result = validateClaimRecord(supportedClaim({ sources: [source({ url: "https://user:pass@example.org/source" })] }), { now: NOW });
  assert.ok(result.issues.some((issue) => issue.code === "SOURCE_URL_CREDENTIALS"));
});

test("missing title, excerpt, and retrieval timestamp are reported", () => {
  const result = validateClaimRecord(supportedClaim({
    sources: [source({ title: " ", excerpt: "", retrievedAt: "yesterday" })],
  }), { now: NOW });
  const codes = result.issues.map((issue) => issue.code);
  assert.ok(codes.includes("MISSING_SOURCE_TITLE"));
  assert.ok(codes.includes("MISSING_SOURCE_EXCERPT"));
  assert.ok(codes.includes("INVALID_RETRIEVED_AT"));
});

test("stale source retrieval blocks release according to the configured freshness window", () => {
  const result = validateClaimRecord(supportedClaim({
    sources: [source({ retrievedAt: "2026-01-01T00:00:00.000Z" })],
  }), { now: NOW, maxAgeDays: 90 });
  assert.ok(result.issues.some((issue) => issue.code === "STALE_SOURCE"));
  assert.equal(result.eligibleForRelease, false);
});

test("future retrieval timestamps are rejected", () => {
  const result = validateClaimRecord(supportedClaim({
    sources: [source({ retrievedAt: "2026-10-13T00:00:00.000Z" })],
  }), { now: NOW });
  assert.ok(result.issues.some((issue) => issue.code === "FUTURE_RETRIEVAL_TIMESTAMP"));
});

test("SUPPORTED cannot release without a named human review", () => {
  const result = validateClaimRecord(supportedClaim({ review: undefined }), { now: NOW });
  assert.ok(result.issues.some((issue) => issue.code === "MISSING_REVIEW"));
  assert.equal(result.eligibleForRelease, false);
});

test("unverified and contradicted verdicts are never release eligible", () => {
  for (const verdict of ["UNVERIFIED", "CONTRADICTED", "OUTDATED", "PARTIALLY_SUPPORTED"]) {
    const result = validateClaimRecord(supportedClaim({ verdict }), { now: NOW });
    assert.equal(result.eligibleForRelease, false, verdict + " must block release");
  }
});

test("stale or incomplete review attestations block release", () => {
  const stale = validateClaimRecord(supportedClaim({
    review: {
      reviewer: "reviewer@example.org",
      reviewedAt: "2025-01-01T00:00:00.000Z",
      rationale: "Historical review.",
    },
  }), { now: NOW, maxAgeDays: 90 });
  assert.ok(stale.issues.some((issue) => issue.code === "STALE_REVIEW"));

  const incomplete = validateClaimRecord(supportedClaim({
    review: { reviewer: " ", reviewedAt: "2026-10-12T11:00:00.000Z", rationale: "" },
  }), { now: NOW });
  assert.ok(incomplete.issues.some((issue) => issue.code === "MISSING_REVIEWER"));
  assert.ok(incomplete.issues.some((issue) => issue.code === "MISSING_REVIEW_RATIONALE"));
});

test("duplicate source IDs within one claim are rejected", () => {
  const result = validateClaimRecord(supportedClaim({ sources: [source(), source()] }), { now: NOW });
  assert.ok(result.issues.some((issue) => issue.code === "DUPLICATE_SOURCE_ID"));
});

test("a duplicate claim ID blocks the entire bundle", () => {
  const claim = supportedClaim();
  const result = validateClaimSet([claim, { ...claim, text: "Duplicate ID." }], { now: NOW });
  assert.equal(result.releaseEligible, false);
  assert.ok(result.issues.some((issue) => issue.code === "DUPLICATE_CLAIM_ID"));
  assert.equal(result.blockedClaimCount, 2);
});

test("empty bundles fail closed", () => {
  const result = validateClaimSet([], { now: NOW });
  assert.equal(result.releaseEligible, false);
  assert.ok(result.issues.some((issue) => issue.code === "EMPTY_CLAIM_SET"));
});

test("an empty claim and impossible calendar date are rejected", () => {
  const result = validateClaimRecord(supportedClaim({
    text: " ",
    sources: [source({ retrievedAt: "2026-02-30T10:00:00.000Z" })],
  }), { now: NOW });
  assert.ok(result.issues.some((issue) => issue.code === "EMPTY_CLAIM"));
  assert.ok(result.issues.some((issue) => issue.code === "INVALID_RETRIEVED_AT"));
});
