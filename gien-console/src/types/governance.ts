export type SourceStatus =
  | "LIVE"
  | "SYNTHETIC"
  | "REPLAY"
  | "EXTERNAL_ATTESTED"
  | "EVIDENCE_PENDING";

export type ThresholdDirection = "MAXIMUM" | "MINIMUM";
export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
export type AlertState = "OPEN" | "ACKNOWLEDGED" | "RESOLVED";

export interface RiskMetric {
  id: string;
  name: string;
  value: number;
  unit: string;
  threshold?: number;
  thresholdDirection: ThresholdDirection;
  sourceStatus: SourceStatus;
  sourceRef: string;
  observedAt: string;
  methodVersion: string;
  limitation: string;
}

export interface AlertRecord {
  id: string;
  title: string;
  severity: Severity;
  state: AlertState;
  occurredAt: string;
  owner: string;
  sourceStatus: SourceStatus;
  evidenceRef: string;
}

export interface ComplianceRecord {
  id: string;
  framework: string;
  obligation: string;
  owner: string;
  assessment: "NOT ASSESSED" | "IN REVIEW" | "EVIDENCE REQUIRED";
  evidenceCount: number;
  nextReview: string;
}

export interface RagSourceRecord {
  id: string;
  document: string;
  version: string;
  accessedAt: string;
  sourceStatus: SourceStatus;
  citationCoverage: number | null;
  accessDecision: "ALLOWED" | "DENIED" | "PENDING";
}
