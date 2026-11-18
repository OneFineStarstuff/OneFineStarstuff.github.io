export type WorkflowStatus =
  | "CREATED"
  | "COLLECTING"
  | "NORMALIZING"
  | "ANALYZING"
  | "VERIFYING"
  | "SYNTHESIZING"
  | "COMPLETE"
  | "INCOMPLETE"
  | "FAILED";

export type WorkflowStep =
  | "COLLECT"
  | "NORMALIZE"
  | "ANALYZE"
  | "VERIFY"
  | "SYNTHESIZE"
  | "PROMOTE";

export type EffectClass =
  | "READ_ONLY"
  | "IDEMPOTENT"
  | "ISOLATED"
  | "COMPENSATABLE"
  | "IRREVERSIBLE";

export interface WorkflowRun {
  runId: string;
  status: WorkflowStatus;
  stepAttempts: Record<WorkflowStep, number>;
  maxAttempts: number;
  transitions: number;
  maxTransitions: number;
  verificationReworkCycles: number;
}

export interface CreateWorkflowRunInput {
  runId: string;
  maxAttempts?: number;
  maxTransitions?: number;
}

export interface AttemptOptions {
  humanApproval?: boolean;
  compensationReady?: boolean;
}

const INITIAL_ATTEMPTS: Record<WorkflowStep, number> = {
  COLLECT: 0,
  NORMALIZE: 0,
  ANALYZE: 0,
  VERIFY: 0,
  SYNTHESIZE: 0,
  PROMOTE: 0
};

const ALLOWED_TRANSITIONS: Record<WorkflowStatus, readonly WorkflowStatus[]> = {
  CREATED: ["COLLECTING", "FAILED"],
  COLLECTING: ["NORMALIZING", "INCOMPLETE", "FAILED"],
  NORMALIZING: ["ANALYZING", "INCOMPLETE", "FAILED"],
  ANALYZING: ["VERIFYING", "INCOMPLETE", "FAILED"],
  VERIFYING: ["ANALYZING", "SYNTHESIZING", "INCOMPLETE", "FAILED"],
  SYNTHESIZING: ["COMPLETE", "INCOMPLETE", "FAILED"],
  COMPLETE: [],
  INCOMPLETE: [],
  FAILED: []
};

const TERMINAL_STATES: readonly WorkflowStatus[] = ["COMPLETE", "INCOMPLETE", "FAILED"];

export function createWorkflowRun(input: CreateWorkflowRunInput): WorkflowRun {
  if (!input || typeof input.runId !== "string" || input.runId.trim().length === 0) {
    throw new Error("runId is required");
  }
  const maxAttempts = input.maxAttempts ?? 3;
  const maxTransitions = input.maxTransitions ?? 12;

  if (!Number.isSafeInteger(maxAttempts) || maxAttempts < 1 || maxAttempts > 5) {
    throw new Error("maxAttempts must be between 1 and 5");
  }
  if (!Number.isSafeInteger(maxTransitions) || maxTransitions < 1 || maxTransitions > 20) {
    throw new Error("maxTransitions must be between 1 and 20");
  }

  return {
    runId: input.runId,
    status: "CREATED",
    stepAttempts: { ...INITIAL_ATTEMPTS },
    maxAttempts,
    transitions: 0,
    maxTransitions,
    verificationReworkCycles: 0
  };
}

export function advanceWorkflow(run: WorkflowRun, nextStatus: WorkflowStatus): WorkflowRun {
  if (TERMINAL_STATES.includes(run.status)) {
    throw new Error("terminal workflow runs cannot transition");
  }
  if (!ALLOWED_TRANSITIONS[run.status].includes(nextStatus)) {
    throw new Error("invalid workflow transition from " + run.status + " to " + nextStatus);
  }
  if (run.transitions >= run.maxTransitions) {
    throw new Error("maximum workflow transition limit reached");
  }

  let verificationReworkCycles = run.verificationReworkCycles;
  if (run.status === "VERIFYING" && nextStatus === "ANALYZING") {
    if (verificationReworkCycles >= 1) {
      throw new Error("verification re-analysis cycle limit reached");
    }
    verificationReworkCycles += 1;
  }

  return {
    ...run,
    status: nextStatus,
    transitions: run.transitions + 1,
    verificationReworkCycles
  };
}

function canRetry(effect: EffectClass, options: AttemptOptions): boolean {
  if (effect === "READ_ONLY" || effect === "IDEMPOTENT" || effect === "ISOLATED") return true;
  if (effect === "COMPENSATABLE") return options.compensationReady === true;
  return false;
}

/**
 * Records a bounded attempt. The first irreversible attempt requires human
 * approval. Later retries require a discard-safe effect class; irreversible
 * effects are never blindly re-dispatched.
 */
export function recordStepAttempt(
  run: WorkflowRun,
  step: WorkflowStep,
  effect: EffectClass,
  options: AttemptOptions = {}
): WorkflowRun {
  if (!(step in run.stepAttempts)) throw new Error("unknown workflow step");
  const currentAttempts = run.stepAttempts[step];

  if (currentAttempts >= run.maxAttempts) {
    throw new Error("maximum attempt limit reached for " + step);
  }
  if (effect === "IRREVERSIBLE" && options.humanApproval !== true) {
    throw new Error("human approval is required before an irreversible attempt");
  }
  if (currentAttempts > 0 && !canRetry(effect, options)) {
    throw new Error("retry is not permitted for effect class " + effect);
  }

  return {
    ...run,
    stepAttempts: {
      ...run.stepAttempts,
      [step]: currentAttempts + 1
    }
  };
}
