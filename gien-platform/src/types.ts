export type Severity = 'GREEN' | 'AMBER' | 'RED' | 'CRITICAL';
export type Role = 'regulator' | 'g-sifi' | 'engineer' | 'executive' | 'college' | 'educational';
export type Layer = 'executive' | 'engineering' | 'crypto';

export interface RiskIndex {
  id: string;
  label: string;
  value: number;
  delta: number;
  thresholds: { amber: number; red: number; critical: number };
  series: number[];
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

export interface Framework {
  id: string;
  name: string;
  family: 'ai' | 'financial' | 'operational' | 'privacy' | 'fictional';
  status: 'COMPLIANT' | 'PARTIAL' | 'NON-COMPLIANT' | 'PENDING';
  controls: number;
  total: number;
  oscalSsp: boolean;
  oscalAr: boolean;
  opaViolations: number;
  opaWarnings: number;
  lastAssessed: string;
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
