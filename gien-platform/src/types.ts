export type Severity = 'GREEN' | 'AMBER' | 'RED' | 'CRITICAL';
export type Role = 'regulator' | 'g-sifi' | 'engineer' | 'executive' | 'college' | 'educational';
export type Layer = 'executive' | 'engineering' | 'crypto';

export type EvidenceSourceKind = 'live' | 'synthetic' | 'replay' | 'external-attested' | 'pending';
export type AssessmentStatus = 'ASSESSED' | 'NOT_ASSESSED' | 'STALE' | 'CONFLICTED' | 'INVALID' | 'EVIDENCE_PENDING' | 'SIMULATED';

export interface EvidenceMetadata {
  sourceKind: EvidenceSourceKind;
  assessmentStatus: AssessmentStatus;
  evidenceRefs: string[];
  observedAt: string | null;
  windowStart: string | null;
  windowEnd: string | null;
  methodVersion: string | null;
}

export interface RiskIndex extends EvidenceMetadata {
  id: string;
  label: string;
  value: number;
  delta: number;
  thresholds: { amber: number; red: number; critical: number };
  series: number[];
  /** Legacy presentation flag. New code must use sourceKind and assessmentStatus. */
  fictional: boolean;
  description: string;
}

export interface AlertEvent {
  id: string;
  ts: string;
  severity: Severity;
  source: string;
  message: string;
  acknowledged: boolean;
}

export type FrameworkStatus = 'NOT ASSESSED' | 'EVIDENCE PENDING' | 'COMPLIANT' | 'PARTIAL' | 'NON-COMPLIANT' | 'PENDING';
export type ApplicabilityStatus = 'APPLICABLE' | 'NOT_APPLICABLE' | 'PENDING_REVIEW';

export interface Framework extends EvidenceMetadata {
  id: string;
  name: string;
  family: 'ai' | 'financial' | 'operational' | 'privacy' | 'fictional';
  status: FrameworkStatus;
  controls: number | null;
  total: number | null;
  oscalSsp: boolean | null;
  oscalAr: boolean | null;
  opaViolations: number | null;
  opaWarnings: number | null;
  lastAssessed: string | null;
  applicability: ApplicabilityStatus;
  applicabilityRationale: string | null;
}

export interface ControlDomain {
  id: string;
  name: string;
  status: Severity;
  risk: number;
  openRemediations: number;
}

export interface Phase {
  id: string;
  name: string;
  epoch: string;
  readiness: number;
  maturity: number;
  objectives: string[];
  invariants: string[];
  milestones: { label: string; done: boolean }[];
}

export interface AttestationNode {
  id: string;
  region: string;
  valid: boolean;
  algorithm: 'ML-DSA-65' | 'ML-DSA-87' | 'SPHINCS+' | 'Falcon' | 'SLH-DSA';
  lastQuoteMin: number;
}
