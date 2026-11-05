package gien.release

import rego.v1

default allow := false

gates := {
  "C1_schema": input.schema.compatible == true,
  "C2_pact": input.contracts.productionCompatible == true,
  "C3_slsa_l3": input.build.provenanceVerified == true
    and input.build.slsaLevel == 3
    and input.build.subjectDigest == input.imageDigest
    and input.build.sourceRevision == input.build.expectedSourceRevision
    and input.build.builderId != ""
    and input.build.builderId == input.build.expectedBuilderId,
  "C4_cosign": input.signature.verified == true
    and input.signature.signer == input.signature.expectedSigner
    and input.signature.subjectDigest == input.imageDigest
    and input.signature.signer != ""
    and input.signature.expectedSigner != "",
  "C5_sbom_scan_admission": input.sbom.policyPassed == true
    and input.sbom.subjectDigest == input.imageDigest
    and input.vulnerabilityScan.policyPassed == true
    and input.vulnerabilityScan.subjectDigest == input.imageDigest
    and regex.match("^[a-f0-9]{64}$", input.vulnerabilityScan.reportSha256)
    and input.admission.policyEnforced == true
    and input.admission.decision == "ALLOW",
  "C6_freeze": input.freeze.active == false or (
    input.freeze.exceptionApproved == true
    and input.freeze.exceptionId != ""
    and input.freeze.exceptionScope != ""
    and time.parse_rfc3339_ns(input.freeze.exceptionExpiresAt) > time.now_ns()
  ),
  "C7_change": input.change.approved == true
    and input.change.classification >= 0
    and input.change.classification <= 3
    and (input.change.classification < 2 or input.change.classification == 2 and input.change.riskApprovals >= 1 or input.change.classification == 3 and input.change.riskApprovals >= 2),
  "C8_breakglass": not has_breakglass or valid_breakglass,
}

has_breakglass if object.get(input, "breakGlass", null) != null

valid_breakglass if {
  bg := input.breakGlass
  bg.incidentId != ""
  bg.requestedBy != ""
  bg.scope != ""
  bg.authorized == true
  time.parse_rfc3339_ns(bg.expiresAt) > time.now_ns()
  count({a.id | a := bg.approvers[_]; a.id != ""}) >= 2
  not requester_is_approver
  count({a.role | a := bg.approvers[_]; a.role in {"incident_commander", "service_owner", "security_on_call"}}) >= 2
}

requester_is_approver if {
  some a in input.breakGlass.approvers
  a.id == input.breakGlass.requestedBy
}

allow if {
  every _, passed in gates { passed }
}

deny_reasons := [gate | gate := object.keys(gates)[_]; gates[gate] == false]
