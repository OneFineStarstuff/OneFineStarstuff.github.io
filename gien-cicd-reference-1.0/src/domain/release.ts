export type BreakGlassApproval = { id: string; role: string };
export type ReleaseEvaluationInput = {
  releaseId: string; imageDigest: string;
  schema: { compatible: boolean };
  contracts: { productionCompatible: boolean };
  build: { provenanceVerified: boolean; slsaLevel: number; subjectDigest: string; sourceRevision: string; expectedSourceRevision: string; builderId: string; expectedBuilderId: string };
  signature: { verified: boolean; signer: string; expectedSigner: string; subjectDigest: string };
  sbom: { policyPassed: boolean; subjectDigest: string };
  vulnerabilityScan: { policyPassed: boolean; subjectDigest: string; reportSha256: string };
  admission: { policyEnforced: boolean; decision: "ALLOW" | "DENY" };
  freeze: { active: boolean; exceptionApproved: boolean; exceptionId?: string; exceptionScope?: string; exceptionExpiresAt?: string };
  change: { classification: number; approved: boolean; riskApprovals: number };
  breakGlass?: { incidentId: string; requestedBy: string; approvers: BreakGlassApproval[]; expiresAt: string; scope: string; authorized: boolean };
};
export type Gate = { id: `C${1 | 2 | 3 | 4 | 5 | 6 | 7 | 8}`; name: string; status: "PASS" | "FAIL"; reason: string };

function validDigest(value: string): boolean { return /^sha256:[a-f0-9]{64}$/.test(value); }
function evaluateBreakGlass(request: NonNullable<ReleaseEvaluationInput["breakGlass"]>, now: number): { pass: boolean; reason: string } {
  if (!request.incidentId.trim() || !request.scope.trim()) return { pass: false, reason: "External incident identifier and bounded scope are required." };
  if (!request.authorized) return { pass: false, reason: "Emergency authorization is not approved." };
  const expiry = Date.parse(request.expiresAt);
  if (!Number.isFinite(expiry) || expiry <= now) return { pass: false, reason: "Emergency authorization is expired or has an invalid expiry." };
  const approverIds = request.approvers.map((approver) => approver.id.trim());
  const uniqueIds = new Set(approverIds);
  const hasDistinctApprovers = uniqueIds.size >= 2 && approverIds.every(Boolean);
  const requesterNotApprover = Boolean(request.requestedBy.trim()) && !uniqueIds.has(request.requestedBy.trim());
  const permittedRoles = new Set(["incident_commander", "service_owner", "security_on_call"]);
  const hasAuthorizedRoles = request.approvers.filter((a) => permittedRoles.has(a.role)).length >= 2;
  if (!hasDistinctApprovers || !requesterNotApprover || !hasAuthorizedRoles) return { pass: false, reason: "Two distinct authorized approvers, separate from the requester, are required." };
  return { pass: true, reason: "External incident, bounded scope, expiry and four-eyes claims are present." };
}

export function evaluateRelease(input: ReleaseEvaluationInput, now = Date.now()): {
  decision: "ALLOW" | "DENY"; releaseId: string; evaluatedAt: string; gates: Gate[]; failedGates: string[]; warning: string;
} {
  const digestMatches = validDigest(input.imageDigest);
  const buildMatches = digestMatches && input.build.subjectDigest === input.imageDigest && input.build.sourceRevision === input.build.expectedSourceRevision && Boolean(input.build.builderId.trim()) && input.build.builderId === input.build.expectedBuilderId;
  const signatureMatches = digestMatches && input.signature.subjectDigest === input.imageDigest && Boolean(input.signature.signer.trim()) && Boolean(input.signature.expectedSigner.trim());
  const sbomMatches = digestMatches && input.sbom.subjectDigest === input.imageDigest;
  const vulnerabilityScanMatches = digestMatches && input.vulnerabilityScan.subjectDigest === input.imageDigest && /^[a-f0-9]{64}$/.test(input.vulnerabilityScan.reportSha256);
  const changeClassValid = Number.isInteger(input.change.classification) && input.change.classification >= 0 && input.change.classification <= 3;
  const requiredRiskApprovals = input.change.classification === 3 ? 2 : input.change.classification === 2 ? 1 : 0;
  const changeApproved = input.change.approved && changeClassValid && input.change.riskApprovals >= requiredRiskApprovals;
  const freezeExceptionValid = input.freeze.exceptionApproved && Boolean(input.freeze.exceptionId?.trim()) && Boolean(input.freeze.exceptionScope?.trim()) && Number.isFinite(Date.parse(input.freeze.exceptionExpiresAt ?? "")) && Date.parse(input.freeze.exceptionExpiresAt ?? "") > now;
  const freezeAllowed = !input.freeze.active || freezeExceptionValid;
  const emergency = input.breakGlass ? evaluateBreakGlass(input.breakGlass, now) : { pass: true, reason: "Not applicable; no emergency override requested." };
  const gates: Gate[] = [
    { id: "C1", name: "Schema compatibility", status: input.schema.compatible ? "PASS" : "FAIL", reason: input.schema.compatible ? "Schema validation and compatibility claim passed." : "Schema compatibility failed." },
    { id: "C2", name: "Pact production compatibility", status: input.contracts.productionCompatible ? "PASS" : "FAIL", reason: input.contracts.productionCompatible ? "Production compatibility claim passed." : "Pact production compatibility failed or is unverified." },
    { id: "C3", name: "SLSA Build L3 provenance", status: input.build.provenanceVerified && input.build.slsaLevel === 3 && buildMatches ? "PASS" : "FAIL", reason: input.build.provenanceVerified && input.build.slsaLevel === 3 && buildMatches ? "Provenance claim matches expected builder, source revision and image digest." : "Verified SLSA level 3 provenance from the expected builder and source revision, bound to the exact image digest, is required." },
    { id: "C4", name: "Keyless image signature", status: input.signature.verified && input.signature.signer === input.signature.expectedSigner && signatureMatches ? "PASS" : "FAIL", reason: input.signature.verified && input.signature.signer === input.signature.expectedSigner && signatureMatches ? "Image signature and expected signer claims passed." : "Signature, non-empty signer identity or subject digest is invalid." },
    { id: "C5", name: "SBOM, vulnerability scan and admission", status: input.sbom.policyPassed && sbomMatches && input.vulnerabilityScan.policyPassed && vulnerabilityScanMatches && input.admission.policyEnforced && input.admission.decision === "ALLOW" ? "PASS" : "FAIL", reason: input.sbom.policyPassed && sbomMatches && input.vulnerabilityScan.policyPassed && vulnerabilityScanMatches && input.admission.policyEnforced && input.admission.decision === "ALLOW" ? "Digest-bound SBOM, signed vulnerability-scan result and fail-closed admission claims passed." : "Accepted digest-bound SBOM, vulnerability scan and enforced ALLOW admission decision are required." },
    { id: "C6", name: "Supervisory freeze window", status: freezeAllowed ? "PASS" : "FAIL", reason: !input.freeze.active ? "No applicable release freeze is active." : freezeExceptionValid ? "A scoped, identified and unexpired freeze exception is approved." : "An active freeze blocks deployment unless a scoped, identified and unexpired exception is approved." },
    { id: "C7", name: "Material-change authorization", status: changeApproved ? "PASS" : "FAIL", reason: changeApproved ? "Change classification and applicable approval claims passed." : `Change approval is missing, invalid, or has fewer than ${requiredRiskApprovals} required risk approval(s).` },
    { id: "C8", name: "Four-eyes break-glass", status: emergency.pass ? "PASS" : "FAIL", reason: emergency.reason },
  ];
  const failedGates = gates.filter((gate) => gate.status === "FAIL").map((gate) => gate.id);
  return { decision: failedGates.length === 0 ? "ALLOW" : "DENY", releaseId: input.releaseId, evaluatedAt: new Date(now).toISOString(), gates, failedGates, warning: "This evaluator checks supplied claims only. It does not authenticate approvers, verify signatures/provenance, query Pact/Kubernetes, or persist an audit decision." };
}
