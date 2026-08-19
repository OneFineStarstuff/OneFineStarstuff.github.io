---- MODULE DailyGIENContainmentInvariants20260718 ----
EXTENDS Naturals, TLC

CONSTANTS Tier3, Enforced, Blocked
VARIABLES riskTier, containmentState, supervisoryQuorum, releaseAuthorized,
          wormReceiptCommitted, zkProofVerified, openSeverityOne

Init ==
  /\ riskTier \in 0..3
  /\ containmentState \in {Enforced, Blocked}
  /\ supervisoryQuorum \in 0..5
  /\ releaseAuthorized \in BOOLEAN
  /\ wormReceiptCommitted \in BOOLEAN
  /\ zkProofVerified \in BOOLEAN
  /\ openSeverityOne \in BOOLEAN

NoUnsanctionedHighRisk ==
  [](riskTier = Tier3 /\ releaseAuthorized => containmentState = Enforced)

DualControlForCritical ==
  [](riskTier = Tier3 /\ releaseAuthorized => supervisoryQuorum >= 2)

ProofBeforeCriticalRelease ==
  [](riskTier = Tier3 /\ releaseAuthorized => zkProofVerified)

EvidenceBeforeRelease ==
  [](releaseAuthorized => wormReceiptCommitted)

NoCriticalReleaseDuringSevOne ==
  [](openSeverityOne => ~releaseAuthorized)

Safety ==
  /\ NoUnsanctionedHighRisk
  /\ DualControlForCritical
  /\ ProofBeforeCriticalRelease
  /\ EvidenceBeforeRelease
  /\ NoCriticalReleaseDuringSevOne
====
