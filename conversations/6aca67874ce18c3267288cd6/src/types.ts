// Core domain types for the fictional GIEN governance universe.
// All data is fictional/simulated. Strict typing: no `any` anywhere.

export type Role = 'REGULATOR' | 'INSTITUTION' | 'EXECUTIVE' | 'EDUCATION';

export type OperationalStatus = 'NOMINAL' | 'ELEVATED' | 'CRITICAL' | 'SAFEGUARD';

export type ComplianceStatus =
  | 'COMPLIANT'
  | 'PARTIAL'
  | 'NON_COMPLIANT'
  | 'NOT_APPLICABLE'
  | 'PENDING';

export type VerificationStatus = 'VERIFIED' | 'UNVERIFIED' | 'VIOLATED';

export type TlaProofStatus = 'PROVED' | 'UNPROVED' | 'COUNTEREXAMPLE_FOUND';

export interface RiskIndex {
  id: string; // e.g. "S_sys"
  name: string;
  description: string;
  value: number;
  delta24h: number;
  threshold: number;
  status: OperationalStatus;
  methodology: string;
  factors: string[];
  remediationTriggers: string[];
  regulatoryMappings: string[];
  history: number[]; // 24h simulated series
}

export interface ControlDomain {
  id: string; // CD-01 .. CD-10
  name: string;
  description: string;
  complianceScore: number; // 0-100
  activeControls: number;
  openFindings: number;
  status: OperationalStatus;
}

export interface ComplianceFramework {
  id: string;
  name: string;
  references: string[]; // articles / clauses / functions
  compliancePercent: number;
  gapCount: number;
  criticalGaps: string[];
  treatyGrade: boolean;
}

export interface PQCAlgorithm {
  name: string;
  standard: string;
  status: 'ACTIVE' | 'STANDBY' | 'DEPRECATED';
  keySizeBytes: number;
  lastRotation: string; // ISO 8601
}

export interface SupervisoryAgent {
  id: string;
  role: string;
  driftScore: number;
  containmentStatus: 'UNCONTAINED' | 'WATCH' | 'SOFT_CONTAINED' | 'HARD_CONTAINED';
  lastAttestation: string;
  interventionCount24h: number;
}

export interface ReplayBundle {
  id: string;
  panel: string;
  scenario: string;
  timestamp: string;
  deterministic: boolean;
  merkleRoot: string;
  pqcSignature: string;
}

export interface Drill {
  id: string; // DRILL-042 ..
  scenario: string;
  status: 'SCHEDULED' | 'ACTIVE' | 'COMPLETED' | 'FAILED';
  startTime: string;
  durationMinutes: number;
  outcomeScore: number;
  lessonsLearned: string;
}

export interface ConstitutionalInvariant {
  id: string; // CI-001 .. CI-024
  name: string;
  statement: string;
  tlaSpecRef: string;
  tlaProofStatus: TlaProofStatus;
  verificationStatus: VerificationStatus;
  lastVerified: string;
  proofHash: string;
  epochs: string[];
  regulatoryMappings: string[];
}

export interface GovernancePhase {
  id: string; // VI-δ, VII, .. XIII, Ω-GAR
  epoch: string;
  name: string;
  objectives: string[];
  invariantsActive: number;
  treatyFrameworks: string[];
  pillarStatus: string;
}

export interface InfinityPillar {
  id: string; // IP-I .. IP-VII
  name: string;
  description: string;
  readinessScore: number; // 0-100
  prerequisites: string[];
  status: 'DORMANT' | 'INITIALIZING' | 'ACTIVE' | 'SEALED';
}

export interface GovernanceAlert {
  id: string;
  severity: 'ELEVATED' | 'CRITICAL';
  message: string;
}

export interface SLAException {
  id: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH';
  trigger: string;
  raisedAt: string;
  resolutionStatus: 'OPEN' | 'IN_PROGRESS' | 'RESOLVED';
}

export interface RteeNode {
  id: string;
  type: 'TEE' | 'TPM' | 'vTPM' | 'RTEE';
  platform: string;
  attestationStatus: 'VALID' | 'STALE' | 'FAILED';
  lastQuote: string;
  pcrSummary: string;
  firmware: string;
}
