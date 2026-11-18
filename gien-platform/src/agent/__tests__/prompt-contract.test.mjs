import test from "node:test";
import assert from "node:assert/strict";
import { validatePromptContract } from "../prompt-contract.ts";

const validPrompt = () => ({
  promptId: "GIEN-DAILY-001",
  version: "1.0.0",
  role: "supervisory_analyst",
  objective: "Produce an evidence-backed daily supervisory report",
  inputSchemaVersion: "1.0.0",
  outputSchemaVersion: "1.0.0",
  allowedTools: ["github.read", "vercel.read"],
  effectAuthority: "READ_ONLY",
  evidencePolicy: {
    requireSourceReferences: true,
    preserveConflicts: true,
    prohibitSimulationPromotion: true
  },
  limits: {
    maxAttempts: 3,
    maxOutputTokens: 12000,
    maxExecutionTimeMs: 180000
  }
});

test("accepts a versioned read-only prompt contract", () => {
  assert.deepEqual(validatePromptContract(validPrompt()), []);
});

test("rejects malformed prompt versions", () => {
  const prompt = validPrompt();
  prompt.version = "latest";
  assert.ok(validatePromptContract(prompt).some(issue => issue.includes("version")));
});

test("rejects autonomous write authority", () => {
  const prompt = validPrompt();
  prompt.effectAuthority = "AUTONOMOUS_WRITE";
  assert.ok(validatePromptContract(prompt).some(issue => issue.includes("effectAuthority")));
});

test("requires explicit simulation and citation guardrails", () => {
  const prompt = validPrompt();
  prompt.evidencePolicy.prohibitSimulationPromotion = false;
  assert.ok(validatePromptContract(prompt).length > 0);
});

test("rejects unbounded retry and execution budgets", () => {
  const prompt = validPrompt();
  prompt.limits.maxAttempts = 1000;
  assert.ok(validatePromptContract(prompt).some(issue => issue.includes("maxAttempts")));
});
