---- MODULE SentinelContainmentProtocol ----
EXTENDS Naturals, Sequences, FiniteSets

\* Constants for safety thresholds
CONSTANT HeartbeatThreshold, MaxRiskTier

VARIABLES
    actions,           \* Set of requested model actions
    containmentState,  \* "ENFORCED", "MONITORED", "TRIPPED"
    lastHeartbeat,     \* Timestamp of last valid monitor heartbeat
    currentTime        \* Current system time

\* Type Invariants
TypeOK ==
    /\ containmentState \in {"ENFORCED", "MONITORED", "TRIPPED"}
    /\ lastHeartbeat \in Naturals
    /\ currentTime \in Naturals

\* Helper definitions
IsHighRisk(a) == a.riskTier >= 4
HasQuorum(a) == a.supervisoryQuorum >= 2
HasToken(a) == a.policyTokenValid = TRUE
LivenessValid == (currentTime - lastHeartbeat) <= HeartbeatThreshold

\* Safety Invariants
\* Invariant 1: No high-risk action without quorum and token in enforced state
NoUnsanctionedHighRisk ==
    \A a \in actions : IsHighRisk(a) => (HasToken(a) /\ HasQuorum(a) /\ containmentState = "ENFORCED")

\* Invariant 2: Kill-switch triggers if heartbeat fails
KillSwitchIntegrity ==
    (currentTime - lastHeartbeat > HeartbeatThreshold) => containmentState = "TRIPPED"

\* Next state relations (simplified)
Next ==
    \/ /\ currentTime' = currentTime + 1
       /\ lastHeartbeat' = lastHeartbeat
       /\ UNCHANGED <<actions, containmentState>>
    \/ /\ lastHeartbeat' = currentTime
       /\ UNCHANGED <<actions, containmentState, currentTime>>
    \/ /\ containmentState = "MONITORED"
       /\ currentTime - lastHeartbeat > HeartbeatThreshold
       /\ containmentState' = "TRIPPED"
       /\ UNCHANGED <<actions, lastHeartbeat, currentTime>>

Spec == Init /\ [][Next]_<<actions, containmentState, lastHeartbeat, currentTime>>

=============================================================================
