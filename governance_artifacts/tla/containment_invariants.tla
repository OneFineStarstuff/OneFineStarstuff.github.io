---- MODULE ContainmentInvariants ----
EXTENDS Naturals, Sequences

VARIABLES actions, containmentState

IsHighRisk(a) == a.risk = "high"
HasQuorum(a) == a.supervisoryQuorum >= 2
HasToken(a) == a.policyTokenValid = TRUE

NoUnsanctionedHighRisk ==
  \A a \in actions : IsHighRisk(a) => (HasToken(a) /\ HasQuorum(a) /\ containmentState = "ENFORCED")

=============================================================================
