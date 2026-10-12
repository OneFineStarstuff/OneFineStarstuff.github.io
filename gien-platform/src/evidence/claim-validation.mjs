/**
 * Deterministic structural validation for research claim evidence.
 *
 * This module checks evidence completeness and workflow gates. It does not fetch
 * source URLs, judge semantic entailment, or certify that a source is truthful.
 * SUPPORTED is an explicit reviewer verdict, never an automatic model verdict.
 */
export const EVIDENCE_VERDICTS = Object.freeze([
  "SUPPORTED",
  "PARTIALLY_SUPPORTED",
  "CONTRADICTED",
  "OUTDATED",
  "UNVERIFIED",
]);

const VERDICT_SET = new Set(EVIDENCE_VERDICTS);
const ISO_UTC_PATTERN = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,3})?Z$/;

function isIsoUtc(value) {
  if (typeof value !== "string") return false;
  const match = ISO_UTC_PATTERN.exec(value);
  if (!match) return false;
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) return false;
  return date.getUTCFullYear() === Number(match[1])
    && date.getUTCMonth() + 1 === Number(match[2])
    && date.getUTCDate() === Number(match[3])
    && date.getUTCHours() === Number(match[4])
    && date.getUTCMinutes() === Number(match[5])
    && date.getUTCSeconds() === Number(match[6]);
}

function normalizedNow(value) {
  if (value instanceof Date) return value;
  const date = value === undefined ? new Date() : new Date(value);
  return Number.isFinite(date.getTime()) ? date : new Date();
}

function addIssue(issues, code, message) {
  if (!issues.some((issue) => issue.code === code)) issues.push({ code, message });
}

function validateSource(source, index, issues, now, maxAgeDays) {
  const label = "Source " + (index + 1);
  if (!source || typeof source !== "object") {
    addIssue(issues, "INVALID_SOURCE", label + " is not a structured source record.");
    return;
  }
  if (typeof source.id !== "string" || !source.id.trim()) {
    addIssue(issues, "MISSING_SOURCE_ID", label + " needs a stable source ID.");
  }
  if (typeof source.url !== "string" || !source.url.trim()) {
    addIssue(issues, "MISSING_SOURCE_URL", label + " needs a URL.");
  } else {
    try {
      const url = new URL(source.url);
      if (url.protocol !== "https:") {
        addIssue(issues, "INVALID_SOURCE_URL", label + " must use HTTPS.");
      }
      if (url.username || url.password) {
        addIssue(issues, "SOURCE_URL_CREDENTIALS", label + " URL must not embed credentials.");
      }
      if (!url.hostname) {
        addIssue(issues, "INVALID_SOURCE_URL", label + " URL must have a hostname.");
      }
    } catch {
      addIssue(issues, "INVALID_SOURCE_URL", label + " URL is not a valid absolute URL.");
    }
  }
  if (typeof source.title !== "string" || !source.title.trim()) {
    addIssue(issues, "MISSING_SOURCE_TITLE", label + " needs a source title.");
  }
  if (typeof source.excerpt !== "string" || !source.excerpt.trim()) {
    addIssue(issues, "MISSING_SOURCE_EXCERPT", label + " needs an excerpt or precise supporting passage.");
  }
  if (!isIsoUtc(source.retrievedAt)) {
    addIssue(issues, "INVALID_RETRIEVED_AT", label + " needs a valid UTC ISO-8601 retrieval timestamp.");
  } else {
    const retrievedAt = new Date(source.retrievedAt);
    if (retrievedAt.getTime() > now.getTime() + 5 * 60 * 1000) {
      addIssue(issues, "FUTURE_RETRIEVAL_TIMESTAMP", label + " retrieval timestamp is in the future.");
    } else {
      const ageDays = (now.getTime() - retrievedAt.getTime()) / 86400000;
      if (ageDays > maxAgeDays) {
        addIssue(issues, "STALE_SOURCE", label + " retrieval is older than the configured " + maxAgeDays + "-day freshness window.");
      }
    }
  }
  if (source.publishedAt !== undefined && source.publishedAt !== null && source.publishedAt !== "" && !isIsoUtc(source.publishedAt)) {
    addIssue(issues, "INVALID_PUBLISHED_AT", label + " publication timestamp must be UTC ISO-8601 when provided.");
  }
}

/**
 * @param {import("./claim-validation.d.mts").ClaimRecord} claim
 * @param {{ now?: Date|string|number, maxAgeDays?: number }} [options]
 */
export function validateClaimRecord(claim, options = {}) {
  const now = normalizedNow(options.now);
  const configuredAge = Number(options.maxAgeDays);
  const maxAgeDays = Number.isFinite(configuredAge) && configuredAge >= 0 ? configuredAge : 90;
  const issues = [];
  const safeClaim = claim && typeof claim === "object" ? claim : {};
  const id = typeof safeClaim.id === "string" ? safeClaim.id.trim() : "";
  const text = typeof safeClaim.text === "string" ? safeClaim.text.trim() : "";
  const verdict = typeof safeClaim.verdict === "string" ? safeClaim.verdict : "UNVERIFIED";
  const sources = Array.isArray(safeClaim.sources) ? safeClaim.sources : [];

  if (!id) addIssue(issues, "MISSING_CLAIM_ID", "Claim needs a stable ID.");
  if (!text) addIssue(issues, "EMPTY_CLAIM", "Claim text is required.");
  if (!Array.isArray(safeClaim.sources) || sources.length === 0) {
    addIssue(issues, "MISSING_SOURCE", "At least one linked source is required.");
  }

  const sourceIds = new Set();
  sources.forEach((source, index) => {
    validateSource(source, index, issues, now, maxAgeDays);
    if (source && typeof source.id === "string" && source.id.trim()) {
      if (sourceIds.has(source.id.trim())) {
        addIssue(issues, "DUPLICATE_SOURCE_ID", "Source ID " + source.id.trim() + " is repeated in this claim.");
      }
      sourceIds.add(source.id.trim());
    }
  });

  if (!VERDICT_SET.has(verdict)) {
    addIssue(issues, "INVALID_VERDICT", "Verdict is not in the approved evidence-verdict vocabulary.");
  }
  if (verdict === "UNVERIFIED") {
    addIssue(issues, "UNVERIFIED_VERDICT", "Claim remains unverified and cannot be released as evidence-qualified.");
  } else if (verdict !== "SUPPORTED") {
    addIssue(issues, "NON_SUPPORTING_VERDICT", "Verdict " + verdict + " does not qualify the claim for evidence-qualified release.");
  }

  const review = safeClaim.review;
  if (!review || typeof review !== "object") {
    addIssue(issues, "MISSING_REVIEW", "A named human reviewer must attest to the current claim text, sources, and verdict.");
  } else {
    if (typeof review.reviewer !== "string" || !review.reviewer.trim()) {
      addIssue(issues, "MISSING_REVIEWER", "Reviewer identity is required.");
    }
    if (typeof review.rationale !== "string" || !review.rationale.trim()) {
      addIssue(issues, "MISSING_REVIEW_RATIONALE", "Review rationale is required.");
    }
    if (!isIsoUtc(review.reviewedAt)) {
      addIssue(issues, "INVALID_REVIEWED_AT", "Review attestation needs a valid UTC ISO-8601 timestamp.");
    } else {
      const reviewAge = (now.getTime() - new Date(review.reviewedAt).getTime()) / 86400000;
      if (reviewAge < -5 / 1440) {
        addIssue(issues, "FUTURE_REVIEW_TIMESTAMP", "Review timestamp is in the future.");
      } else if (reviewAge > maxAgeDays) {
        addIssue(issues, "STALE_REVIEW", "Review is older than the configured " + maxAgeDays + "-day review window.");
      }
    }
  }

  return {
    claimId: id,
    verdict,
    sourceCount: sources.length,
    eligibleForRelease: issues.length === 0 && verdict === "SUPPORTED",
    issues,
  };
}

/**
 * Validate a whole claim bundle and make duplicate claim IDs a bundle-level
 * blocker. A bundle is eligible only when every claim is individually eligible.
 * @param {import("./claim-validation.d.mts").ClaimRecord[]} claims
 * @param {{ now?: Date|string|number, maxAgeDays?: number }} [options]
 */
export function validateClaimSet(claims, options = {}) {
  const input = Array.isArray(claims) ? claims : [];
  const topIssues = [];
  if (input.length === 0) {
    addIssue(topIssues, "EMPTY_CLAIM_SET", "The evidence bundle contains no claims.");
  }
  const counts = new Map();
  input.forEach((claim) => {
    const id = claim && typeof claim.id === "string" ? claim.id.trim() : "";
    if (id) counts.set(id, (counts.get(id) || 0) + 1);
  });
  const duplicateIds = new Set([...counts].filter(([, count]) => count > 1).map(([id]) => id));
  for (const id of duplicateIds) {
    addIssue(topIssues, "DUPLICATE_CLAIM_ID", "Claim ID " + id + " appears more than once in the bundle.");
  }
  const claimResults = input.map((claim) => {
    const result = validateClaimRecord(claim, options);
    if (duplicateIds.has(result.claimId)) {
      result.issues = [...result.issues, { code: "DUPLICATE_CLAIM_ID", message: "Claim ID " + result.claimId + " is duplicated in this bundle." }];
      result.eligibleForRelease = false;
    }
    return result;
  });
  const eligibleClaimCount = claimResults.filter((result) => result.eligibleForRelease).length;
  return {
    claimCount: input.length,
    eligibleClaimCount,
    blockedClaimCount: input.length - eligibleClaimCount,
    releaseEligible: input.length > 0 && topIssues.length === 0 && eligibleClaimCount === input.length,
    claimResults,
    issues: topIssues,
  };
}
