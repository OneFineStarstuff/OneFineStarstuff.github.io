import test from "node:test";
import assert from "node:assert/strict";
import {
  createWorkflowRun,
  advanceWorkflow,
  recordStepAttempt
} from "../workflow.ts";

test("creates a workflow with explicit finite execution limits", () => {
  const run = createWorkflowRun({ runId: "RUN-001" });
  assert.equal(run.status, "CREATED");
  assert.equal(run.maxAttempts, 3);
  assert.equal(run.maxTransitions, 12);
});

test("accepts valid state transitions and rejects invalid transitions", () => {
  const initial = createWorkflowRun({ runId: "RUN-002" });
  const collecting = advanceWorkflow(initial, "COLLECTING");
  assert.equal(collecting.status, "COLLECTING");
  assert.throws(() => advanceWorkflow(collecting, "COMPLETE"), /transition/i);
});

test("limits verification feedback to one re-analysis cycle", () => {
  let run = createWorkflowRun({ runId: "RUN-003" });
  run = advanceWorkflow(run, "COLLECTING");
  run = advanceWorkflow(run, "NORMALIZING");
  run = advanceWorkflow(run, "ANALYZING");
  run = advanceWorkflow(run, "VERIFYING");
  run = advanceWorkflow(run, "ANALYZING");
  run = advanceWorkflow(run, "VERIFYING");
  assert.throws(() => advanceWorkflow(run, "ANALYZING"), /re-analysis|cycle/i);
});

test("permits bounded retries for read-only and idempotent operations", () => {
  let run = createWorkflowRun({ runId: "RUN-004", maxAttempts: 2 });
  run = recordStepAttempt(run, "COLLECT", "READ_ONLY");
  run = recordStepAttempt(run, "COLLECT", "READ_ONLY");
  assert.equal(run.stepAttempts.COLLECT, 2);
  assert.throws(() => recordStepAttempt(run, "COLLECT", "READ_ONLY"), /maximum|limit/i);
});

test("blocks retries for irreversible effects", () => {
  let run = createWorkflowRun({ runId: "RUN-005" });
  run = recordStepAttempt(run, "PROMOTE", "IRREVERSIBLE", { humanApproval: true });
  assert.throws(
    () => recordStepAttempt(run, "PROMOTE", "IRREVERSIBLE", { humanApproval: true }),
    /retry|irreversible/i
  );
});

test("requires compensation readiness before retrying compensatable effects", () => {
  let run = createWorkflowRun({ runId: "RUN-006" });
  run = recordStepAttempt(run, "PUBLISH", "COMPENSATABLE", { humanApproval: true });
  assert.throws(() => recordStepAttempt(run, "PUBLISH", "COMPENSATABLE"), /compensation/i);
  run = recordStepAttempt(run, "PUBLISH", "COMPENSATABLE", { compensationReady: true });
  assert.equal(run.stepAttempts.PUBLISH, 2);
});

test("blocks an irreversible first attempt without human approval", () => {
  const run = createWorkflowRun({ runId: "RUN-007" });
  assert.throws(() => recordStepAttempt(run, "PROMOTE", "IRREVERSIBLE"), /approval/i);
});
