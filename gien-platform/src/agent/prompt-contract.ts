export type PromptEffectAuthority = "READ_ONLY" | "HUMAN_APPROVAL_REQUIRED";

export interface PromptContract {
  promptId: string;
  version: string;
  role: string;
  objective: string;
  inputSchemaVersion: string;
  outputSchemaVersion: string;
  allowedTools: string[];
  effectAuthority: PromptEffectAuthority;
  evidencePolicy: {
    requireSourceReferences: true;
    preserveConflicts: true;
    prohibitSimulationPromotion: true;
  };
  limits: {
    maxAttempts: number;
    maxOutputTokens: number;
    maxExecutionTimeMs: number;
  };
}

type UnknownRecord = Record<string, unknown>;

function isRecord(value: unknown): value is UnknownRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function nonEmpty(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

function isSemver(value: unknown): value is string {
  return typeof value === "string" && /^\d+\.\d+\.\d+$/.test(value);
}

function isIntegerInRange(value: unknown, minimum: number, maximum: number): value is number {
  return typeof value === "number" &&
    Number.isSafeInteger(value) &&
    value >= minimum &&
    value <= maximum;
}

export function validatePromptContract(input: unknown): string[] {
  const issues: string[] = [];
  if (!isRecord(input)) return ["prompt contract must be an object"];

  if (!/^[A-Z0-9][A-Z0-9._-]{2,100}$/.test(String(input.promptId))) {
    issues.push("promptId must be a stable uppercase identifier");
  }
  if (!isSemver(input.version)) issues.push("version must be semantic version");
  if (!nonEmpty(input.role)) issues.push("role is required");
  if (!nonEmpty(input.objective)) issues.push("objective is required");
  if (!isSemver(input.inputSchemaVersion)) issues.push("inputSchemaVersion must be semantic version");
  if (!isSemver(input.outputSchemaVersion)) issues.push("outputSchemaVersion must be semantic version");

  if (!Array.isArray(input.allowedTools) || input.allowedTools.length === 0 ||
      !input.allowedTools.every(tool => typeof tool === "string" && /^[a-z0-9_-]+\.read$/.test(tool))) {
    issues.push("allowedTools must be a non-empty list of read-only tool identifiers");
  }

  if (input.effectAuthority !== "READ_ONLY" && input.effectAuthority !== "HUMAN_APPROVAL_REQUIRED") {
    issues.push("effectAuthority must be READ_ONLY or HUMAN_APPROVAL_REQUIRED");
  }

  if (!isRecord(input.evidencePolicy)) {
    issues.push("evidencePolicy is required");
  } else {
    if (input.evidencePolicy.requireSourceReferences !== true) {
      issues.push("source references must be mandatory");
    }
    if (input.evidencePolicy.preserveConflicts !== true) {
      issues.push("source conflicts must be preserved");
    }
    if (input.evidencePolicy.prohibitSimulationPromotion !== true) {
      issues.push("simulation promotion must be prohibited");
    }
  }

  if (!isRecord(input.limits)) {
    issues.push("limits are required");
  } else {
    if (!isIntegerInRange(input.limits.maxAttempts, 1, 5)) {
      issues.push("maxAttempts must be between 1 and 5");
    }
    if (!isIntegerInRange(input.limits.maxOutputTokens, 1, 32_000)) {
      issues.push("maxOutputTokens must be between 1 and 32000");
    }
    if (!isIntegerInRange(input.limits.maxExecutionTimeMs, 1, 600_000)) {
      issues.push("maxExecutionTimeMs must be between 1 and 600000");
    }
  }

  return issues;
}
