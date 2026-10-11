export type EvidenceVerdict =
  | "SUPPORTED"
  | "PARTIALLY_SUPPORTED"
  | "CONTRADICTED"
  | "OUTDATED"
  | "UNVERIFIED";

export interface EvidenceSource {
  id: string;
  url: string;
  title: string;
  excerpt: string;
  retrievedAt: string;
  publishedAt?: string | null;
}

export interface ReviewAttestation {
  reviewer: string;
  reviewedAt: string;
  rationale: string;
}

export interface ClaimRecord {
  id: string;
  text: string;
  sources: EvidenceSource[];
  verdict: EvidenceVerdict;
  review?: ReviewAttestation;
}

export interface ValidationIssue {
  code: string;
  message: string;
}

export interface ClaimValidationResult {
  claimId: string;
  verdict: EvidenceVerdict | string;
  sourceCount: number;
  eligibleForRelease: boolean;
  issues: ValidationIssue[];
}

export interface ClaimSetValidationResult {
  claimCount: number;
  eligibleClaimCount: number;
  blockedClaimCount: number;
  releaseEligible: boolean;
  claimResults: ClaimValidationResult[];
  issues: ValidationIssue[];
}

export interface ValidationOptions {
  now?: Date | string | number;
  maxAgeDays?: number;
}

export declare const EVIDENCE_VERDICTS: readonly EvidenceVerdict[];
export declare function validateClaimRecord(claim: ClaimRecord, options?: ValidationOptions): ClaimValidationResult;
export declare function validateClaimSet(claims: ClaimRecord[], options?: ValidationOptions): ClaimSetValidationResult;
