import { validateEvidenceRecord, type EvidenceRecord } from "./evidence.ts";

export interface ContextEnvelope {
  contextId: string;
  schemaVersion: string;
  runId: string;
  asOf: string;
  task: {
    objective: string;
    windowStart: string;
    windowEnd: string;
    scope: string[];
  };
  sources: EvidenceRecord[];
  constraints: string[];
  unresolvedConflicts: string[];
  budgets: {
    maxContextTokens: number;
    estimatedTokens: number;
    maxToolCalls: number;
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

function isTimestamp(value: unknown): value is string {
  return nonEmpty(value) &&
    value.includes("T") &&
    /(Z|[+-]\d{2}:\d{2})$/.test(value) &&
    Number.isFinite(Date.parse(value));
}

function isStringArray(value: unknown, minimum = 0): value is string[] {
  return Array.isArray(value) && value.length >= minimum && value.every(nonEmpty);
}

function isBoundedInteger(value: unknown, minimum: number, maximum: number): value is number {
  return typeof value === "number" &&
    Number.isSafeInteger(value) &&
    value >= minimum &&
    value <= maximum;
}

export function validateContextEnvelope(input: unknown): string[] {
  const issues: string[] = [];
  if (!isRecord(input)) return ["context envelope must be an object"];

  if (!nonEmpty(input.contextId)) issues.push("contextId is required");
  if (!/^\d+\.\d+\.\d+$/.test(String(input.schemaVersion))) issues.push("schemaVersion must be semantic version");
  if (!nonEmpty(input.runId)) issues.push("runId is required");
  if (!isTimestamp(input.asOf)) issues.push("asOf must be an offset-aware timestamp");

  if (!isRecord(input.task)) {
    issues.push("task must be an object");
  } else {
    if (!nonEmpty(input.task.objective)) issues.push("task objective is required");
    const validWindow = isTimestamp(input.task.windowStart) && isTimestamp(input.task.windowEnd);
    if (!validWindow) {
      issues.push("task reporting window must use offset-aware timestamps");
    } else if (Date.parse(input.task.windowEnd as string) <= Date.parse(input.task.windowStart as string)) {
      issues.push("task reporting window end must be after its start");
    } else if (isTimestamp(input.asOf) && Date.parse(input.asOf) < Date.parse(input.task.windowEnd as string)) {
      issues.push("asOf must not precede the reporting window end");
    }
    if (!isStringArray(input.task.scope, 1)) issues.push("task scope requires at least one non-empty entry");
  }

  if (!Array.isArray(input.sources)) {
    issues.push("sources must be an array");
  } else {
    if (input.sources.length === 0) issues.push("context must explicitly include source observations");
    const ids = new Set<string>();
    for (const source of input.sources) {
      const sourceIssues = validateEvidenceRecord(source);
      issues.push(...sourceIssues.map(issue => "source: " + issue));
      if (isRecord(source) && nonEmpty(source.evidenceId)) {
        if (ids.has(source.evidenceId)) issues.push("duplicate evidenceId in context sources");
        ids.add(source.evidenceId);
      }
      const sourceRecord = isRecord(source) ? source : {};
      const sourceDetails = isRecord(sourceRecord.source) ? sourceRecord.source : {};
      if (isTimestamp(input.asOf) && isTimestamp(sourceDetails.retrievedAt) &&
          Date.parse(sourceDetails.retrievedAt) > Date.parse(input.asOf)) {
        issues.push("source retrievedAt cannot be later than context asOf");
      }
      if (isTimestamp(input.asOf) && isTimestamp(sourceDetails.observedAt) &&
          Date.parse(sourceDetails.observedAt) > Date.parse(input.asOf)) {
        issues.push("source observedAt cannot be later than context asOf");
      }
    }
  }

  if (!isStringArray(input.constraints)) issues.push("constraints must be an array of non-empty strings");
  if (!isStringArray(input.unresolvedConflicts)) issues.push("unresolvedConflicts must be an array of non-empty strings");

  if (!isRecord(input.budgets)) {
    issues.push("budgets must be an object");
  } else {
    const maxTokens = input.budgets.maxContextTokens;
    const estimatedTokens = input.budgets.estimatedTokens;
    if (!isBoundedInteger(maxTokens, 1, 1_000_000)) issues.push("maxContextTokens must be between 1 and 1000000");
    if (!isBoundedInteger(estimatedTokens, 0, 1_000_000)) issues.push("estimatedTokens must be between 0 and 1000000");
    if (typeof maxTokens === "number" && typeof estimatedTokens === "number" && estimatedTokens > maxTokens) {
      issues.push("estimated context exceeds the token budget");
    }
    if (!isBoundedInteger(input.budgets.maxToolCalls, 1, 500)) {
      issues.push("maxToolCalls must be between 1 and 500");
    }
    if (!isBoundedInteger(input.budgets.maxExecutionTimeMs, 1, 3_600_000)) {
      issues.push("maxExecutionTimeMs must be between 1 and 3600000");
    }
  }

  return issues;
}
