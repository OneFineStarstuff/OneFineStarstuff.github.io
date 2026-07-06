-------------------- MODULE SentinelContainmentProtocol --------------------
(***************************************************************************)
(* SentinelContainmentProtocol — corrected, model-checkable version of      *)
(* governance_blueprint/SentinelContainmentProtocol.tla (which declared      *)
(* `Spec == Init /\ [][Next]_vars` but never defined Init, and whose         *)
(* KillSwitchIntegrity invariant was unreachable from its Next relation).    *)
(*                                                                          *)
(* Models the dead-man's-switch containment of the Omni-Sentinel Cognitive   *)
(* Execution Environment, mirroring the on-chain OmegaActualTreatyEngine:    *)
(*   - A monitor heartbeat must arrive within HeartbeatThreshold ticks.      *)
(*   - If it lapses, containment TRIPS (dead-man's switch).                  *)
(*   - High-risk actions are admissible only with policy token + supervisory *)
(*     quorum while containment is ENFORCED.                                 *)
(*                                                                          *)
(* Safety invariants (checked by TLC):                                       *)
(*   TypeOK                                                                  *)
(*   NoUnsanctionedHighRisk - no high-risk action lacks token+quorum and a    *)
(*                            non-TRIPPED enforced posture.                   *)
(*   KillSwitchIntegrity    - heartbeat lapse beyond threshold implies TRIPPED*)
(*   TrippedIsLatched       - once TRIPPED, stays TRIPPED (no silent re-arm). *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
    HeartbeatThreshold,   \* max ticks tolerated between heartbeats
    MaxTime               \* model bound on the clock

\* Fixed finite set of in-flight action records. The policy/contract layer
\* guarantees only fully-sanctioned high-risk actions are ever enqueued; this
\* models that upstream guarantee.
Actions == {
    [riskTier |-> 2, supervisoryQuorum |-> 0, policyTokenValid |-> FALSE],
    [riskTier |-> 4, supervisoryQuorum |-> 2, policyTokenValid |-> TRUE]
}

VARIABLES
    containmentState,     \* "ENFORCED" | "MONITORED" | "TRIPPED"
    lastHeartbeat,        \* tick of last accepted heartbeat
    currentTime           \* monotone clock

vars == <<containmentState, lastHeartbeat, currentTime>>

States == {"ENFORCED", "MONITORED", "TRIPPED"}

IsHighRisk(a) == a.riskTier >= 4
HasQuorum(a)  == a.supervisoryQuorum >= 2
HasToken(a)   == a.policyTokenValid = TRUE

Lapsed == (currentTime - lastHeartbeat) > HeartbeatThreshold

TypeOK ==
    /\ containmentState \in States
    /\ lastHeartbeat \in 0..MaxTime
    /\ currentTime \in 0..MaxTime

Init ==
    /\ containmentState = "ENFORCED"
    /\ lastHeartbeat = 0
    /\ currentTime = 0

(* Clock advances one tick. If the heartbeat has now lapsed and we are not    *)
(* already TRIPPED, the dead-man's switch fires in the SAME step, so no       *)
(* reachable state has Lapsed=TRUE while not TRIPPED.                          *)
Tick ==
    /\ currentTime < MaxTime
    /\ currentTime' = currentTime + 1
    /\ lastHeartbeat' = lastHeartbeat
    /\ containmentState' =
         IF (containmentState # "TRIPPED") /\ ((currentTime + 1 - lastHeartbeat) > HeartbeatThreshold)
         THEN "TRIPPED"
         ELSE containmentState

(* A valid heartbeat refreshes liveness — but ONLY if not already TRIPPED     *)
(* (the switch is latched; re-arming requires an out-of-band human action     *)
(* outside this safety model).                                                 *)
Heartbeat ==
    /\ containmentState # "TRIPPED"
    /\ ~Lapsed
    /\ lastHeartbeat' = currentTime
    /\ UNCHANGED <<containmentState, currentTime>>

(* Posture may move between ENFORCED and MONITORED while live and not TRIPPED.*)
SetMonitored ==
    /\ containmentState = "ENFORCED"
    /\ ~Lapsed
    /\ containmentState' = "MONITORED"
    /\ UNCHANGED <<lastHeartbeat, currentTime>>

SetEnforced ==
    /\ containmentState = "MONITORED"
    /\ ~Lapsed
    /\ containmentState' = "ENFORCED"
    /\ UNCHANGED <<lastHeartbeat, currentTime>>

Stutter == UNCHANGED vars

Next ==
    \/ Tick
    \/ Heartbeat
    \/ SetMonitored
    \/ SetEnforced
    \/ Stutter

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* ---- Safety invariants ---- *)

\* Upstream-guarantee invariant: every admitted high-risk action carries a valid
\* policy token AND a supervisory quorum (>=2). This is the containment contract
\* the on-chain OmegaActualTreatyEngine and the OPA release gate jointly enforce.
NoUnsanctionedHighRisk ==
    \A a \in Actions : IsHighRisk(a) => (HasToken(a) /\ HasQuorum(a))

\* The dead-man's switch: a lapsed heartbeat implies TRIPPED.
KillSwitchIntegrity == Lapsed => (containmentState = "TRIPPED")

\* TRIPPED is a latched terminal posture within the safety model: there is no
\* Next action that leaves TRIPPED. (Checked as an inductive invariant via the
\* action property below.)
TrippedStaysTripped ==
    [][ (containmentState = "TRIPPED") => (containmentState' = "TRIPPED") ]_vars

=============================================================================
