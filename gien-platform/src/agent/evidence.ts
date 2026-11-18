export type EvidenceStatus =
  | "VERIFIED"
  | "REPORTED"
  | "SIMULATED"
  | "INFERRED"
  | "CONFLICTED"
  | "UNAVAILABLE";

export type SourceAuthority =
  | "AUTHORITATIVE"
  | "NON_AUTHORITATIVE"
  | "INTERNAL"
  | "UNKNOWN";

export interface EvidenceDigest {
  algorithm: "SHA-256" | "SHA-384";
  value: string;
}

export interface EvidenceSource {
  uri: string;
  system: string;
  authority: SourceAuthority;
  retrievedAt: string;
  observedAt?: string;
  contentDigest?: EvidenceDigest;
}

export interface EvidenceRecord {
  evidenceId: string;
  status: EvidenceStatus;
  source?: EvidenceSource;
  verification?: {
    method: string;
    verifier: string;
    verifiedAt: string;
  };
  simulation?: {
    label: "SIMULATION_ONLY";
    scenarioId: string;
  };
  inference?: {
    method: string;
    basedOnEvidenceIds: string[];
  };
  conflict?: {
    reason: string;
    withEvidenceIds: string[];
  };
  unavailable?: {
    reason: string;
    attemptedAt: string;
  };
}

type UnknownRecord = Record<string, unknown>;

function isRecord(value: unknown): value is UnknownRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function nonEmpty(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

function isTimestamp(value: unknown): value is string {
  if (!nonEmpty(value) || !value.includes("T")) return false;
  if (!/(Z|[+-]\d{2}:\d{2})$/.test(value)) return false;
  return Number.isFinite(Date.parse(value));
}

function isHttpsUri(value: unknown): value is string {
  if (!nonEmpty(value)) return false;
  try {
    return new URL(value).protocol === "https:";
  } catch {
    return false;
  }
}

function validateSource(value: unknown, issues: string[]): void {
  if (!isRecord(value)) {
    issues.push("source must be an object");
    return;
  }

  if (!isHttpsUri(value.uri)) issues.push("source URI must be a valid HTTPS URL");
  if (!nonEmpty(value.system)) issues.push("source system is required");
  if (!["AUTHORITATIVE", "NON_AUTHORITATIVE", "INTERNAL", "UNKNOWN"].includes(String(value.authority))) {
    issues.push("source authority is invalid");
  }
  if (!isTimestamp(value.retrievedAt)) {
    issues.push("source retrievedAt must be an offset-aware timestamp");
  }
}

export function validateEvidenceRecord(input: unknown): string[] {
  const issues: string[] = [];
  if (!isRecord(input)) return ["evidence record must be an object"];

  if (!nonEmpty(input.evidenceId)) issues.push("evidenceId is required");
  const status = input.status;

  if (!["VERIFIED", "REPORTED", "SIMULATED", "INFERRED", "CONFLICTED", "UNAVAILABLE"].includes(String(status))) {
    issues.push("evidence status is invalid");
    return issues;
  }

  if (status === "VERIFIED") {
    validateSource(input.source, issues);
    const source = isRecord(input.source) ? input.source : {};
    if (source.authority !== "AUTHORITATIVE") {
      issues.push("VERIFIED evidence requires an AUTHORITATIVE source");
    }
    if (!isTimestamp(source.observedAt)) {
      issues.push("VERIFIED evidence requires an observedAt timestamp");
    }
    if (isTimestamp(source.observedAt) && isTimestamp(source.retrievedAt) &&
        Date.parse(source.observedAt) > Date.parse(source.retrievedAt)) {
      issues.push("source observedAt cannot be later than retrievedAt");
    }

    const digest = source.contentDigest;
    if (!isRecord(digest)) {
      issues.push("VERIFIED evidence requires a content digest");
    } else {
      const algorithm = digest.algorithm;
      const value = digest.value;
      const expectedLength = algorithm === "SHA-256" ? 64 : algorithm === "SHA-384" ? 96 : 0;
      if (expectedLength === 0 || !nonEmpty(value) || value.length !== expectedLength || !/^[a-fA-F0-9]+$/.test(value)) {
        issues.push("content digest does not match the declared digest algorithm");
      }
    }

    if (!isRecord(input.verification)) {
      issues.push("VERIFIED evidence requires verification metadata");
    } else {
      if (!nonEmpty(input.verification.method)) issues.push("verification method is required");
      if (!nonEmpty(input.verification.verifier)) issues.push("verification verifier is required");
      if (!isTimestamp(input.verification.verifiedAt)) {
        issues.push("verification verifiedAt must be an offset-aware timestamp");
      }
      if (isTimestamp(input.verification.verifiedAt) && isTimestamp(source.retrievedAt) &&
          Date.parse(input.verification.verifiedAt) < Date.parse(source.retrievedAt)) {
        issues.push("verification cannot precede source retrieval");
      }
    }
  }

  if (status === "REPORTED") {
    validateSource(input.source, issues);
  }

  if (status === "SIMULATED") {
    if (!isRecord(input.simulation)) {
      issues.push("SIMULATED evidence requires simulation metadata");
    } else {
      if (input.simulation.label !== "SIMULATION_ONLY") {
        issues.push("SIMULATED evidence must carry the SIMULATION_ONLY label");
      }
      if (!nonEmpty(input.simulation.scenarioId)) {
        issues.push("SIMULATED evidence requires a scenarioId");
      }
    }
  }

  if (status === "INFERRED") {
    if (!isRecord(input.inference)) {
      issues.push("INFERRED evidence requires inference metadata");
    } else {
      if (!nonEmpty(input.inference.method)) issues.push("inference method is required");
      const ids = input.inference.basedOnEvidenceIds;
      if (!Array.isArray(ids) || ids.length === 0 || !ids.every(nonEmpty)) {
        issues.push("INFERRED evidence requires one or more supporting evidence IDs");
      }
    }
  }

  if (status === "CONFLICTED") {
    if (!isRecord(input.conflict)) {
      issues.push("CONFLICTED evidence requires conflict metadata");
    } else {
      if (!nonEmpty(input.conflict.reason)) issues.push("conflict reason is required");
      const ids = input.conflict.withEvidenceIds;
      const distinct = Array.isArray(ids) ? new Set(ids.filter(nonEmpty)) : new Set<string>();
      if (distinct.size < 2) issues.push("conflict requires at least two distinct evidence IDs");
    }
  }

  if (status === "UNAVAILABLE") {
    if (!isRecord(input.unavailable)) {
      issues.push("UNAVAILABLE evidence requires unavailability metadata");
    } else {
      if (!nonEmpty(input.unavailable.reason)) issues.push("unavailability reason is required");
      if (!isTimestamp(input.unavailable.attemptedAt)) {
        issues.push("unavailable attemptedAt must be an offset-aware timestamp");
      }
    }
  }

  return issues;
}

/**
 * Digest format is validated here; byte-level digest recomputation and source
 * authenticity verification belong to the authenticated source adapter.
 */
export function canClassifyClaimAsVerified(records: readonly unknown[]): boolean {
  if (records.length === 0) return false;

  const seen = new Set<string>();
  for (const record of records) {
    if (!isRecord(record) || record.status !== "VERIFIED") return false;
    if (!nonEmpty(record.evidenceId) || seen.has(record.evidenceId)) return false;
    if (validateEvidenceRecord(record).length > 0) return false;
    seen.add(record.evidenceId);
  }
  return true;
}
