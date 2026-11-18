import test from "node:test";
import assert from "node:assert/strict";
import { validateContextEnvelope } from "../context.ts";

const validContext = () => ({
  contextId: "CTX-001",
  schemaVersion: "1.0.0",
  runId: "RUN-001",
  asOf: "2026-11-18T09:00:00.000Z",
  task: {
    objective: "Assess deployment readiness",
    windowStart: "2026-11-17T09:00:00.000Z",
    windowEnd: "2026-11-18T09:00:00.000Z",
    scope: ["github", "vercel"]
  },
  sources: [
    {
      evidenceId: "EV-001",
      status: "REPORTED",
      source: {
        uri: "https://example.com/source",
        system: "test-source",
        authority: "NON_AUTHORITATIVE",
        retrievedAt: "2026-11-18T08:55:00.000Z"
      }
    }
  ],
  constraints: ["Read-only"],
  unresolvedConflicts: [],
  budgets: {
    maxContextTokens: 10000,
    estimatedTokens: 4000,
    maxToolCalls: 30,
    maxExecutionTimeMs: 120000
  }
});

test("accepts a well-formed task-scoped context envelope", () => {
  assert.deepEqual(validateContextEnvelope(validContext()), []);
});

test("rejects estimated context above the declared token budget", () => {
  const context = validContext();
  context.budgets.estimatedTokens = 10001;
  assert.ok(validateContextEnvelope(context).some(issue => issue.includes("token budget")));
});

test("rejects duplicate evidence identifiers", () => {
  const context = validContext();
  context.sources.push(context.sources[0]);
  assert.ok(validateContextEnvelope(context).some(issue => issue.includes("duplicate")));
});

test("rejects a reporting window whose end is not after its start", () => {
  const context = validContext();
  context.task.windowEnd = context.task.windowStart;
  assert.ok(validateContextEnvelope(context).some(issue => issue.includes("window")));
});

test("rejects a context cutoff earlier than the reporting window end", () => {
  const context = validContext();
  context.asOf = "2026-11-18T08:59:59.000Z";
  assert.ok(validateContextEnvelope(context).some(issue => issue.includes("asOf")));
});

test("rejects invalid or unbounded execution budgets", () => {
  const context = validContext();
  context.budgets.maxToolCalls = 0;
  assert.ok(validateContextEnvelope(context).some(issue => issue.includes("maxToolCalls")));
});
