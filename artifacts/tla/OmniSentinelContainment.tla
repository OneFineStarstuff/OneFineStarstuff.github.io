---------------------------- MODULE OmniSentinelContainment ----------------------------
EXTENDS Naturals, Sequences, TLC

(***************************************************************************
 * Reference TLA+ containment model for Sentinel AI Governance Stack v2.4.  *
 * The model is intentionally compact so platform teams can extend it with  *
 * environment-specific states, policy predicates, and liveness checks.      *
 ****************************************************************************)

CONSTANTS Agents, Tools, Destinations, DataClasses

VARIABLES
  state,
  approvedEgress,
  toolGrant,
  evidence,
  emergencyStop,
  witnessLocation,
  policyVersion,
  credentialVersion,
  boundaryVersion

States == {"Init", "Contained", "Actuating", "Stopped"}
WitnessZones == {"ProofPlane", "CommitmentOnly", "External"}
PrivilegedState == <<policyVersion, credentialVersion, boundaryVersion>>
Vars == <<state, approvedEgress, toolGrant, evidence, emergencyStop, witnessLocation, policyVersion, credentialVersion, boundaryVersion>>

Init ==
  /\ state \in [Agents -> "Contained"]
  /\ approvedEgress \subseteq Agents \X Destinations \X DataClasses
  /\ toolGrant \subseteq Agents \X Tools
  /\ evidence = <<>>
  /\ emergencyStop = FALSE
  /\ witnessLocation = "ProofPlane"
  /\ policyVersion = 0
  /\ credentialVersion = 0
  /\ boundaryVersion = 0

ApprovedNetworkUse(a, d, c) == <<a, d, c>> \in approvedEgress
ApprovedToolUse(a, t) == <<a, t>> \in toolGrant

RequestEgress(a, d, c) ==
  /\ state[a] # "Stopped"
  /\ ApprovedNetworkUse(a, d, c)
  /\ evidence' = Append(evidence, [kind |-> "egress", agent |-> a, dest |-> d, class |-> c])
  /\ UNCHANGED <<state, approvedEgress, toolGrant, emergencyStop, witnessLocation, PrivilegedState>>

DenyEgress(a, d, c) ==
  /\ state[a] # "Stopped"
  /\ ~ApprovedNetworkUse(a, d, c)
  /\ evidence' = Append(evidence, [kind |-> "egress_denied", agent |-> a, dest |-> d, class |-> c])
  /\ UNCHANGED <<state, approvedEgress, toolGrant, emergencyStop, witnessLocation, PrivilegedState>>

UseTool(a, t) ==
  /\ state[a] = "Contained"
  /\ ApprovedToolUse(a, t)
  /\ state' = [state EXCEPT ![a] = "Actuating"]
  /\ evidence' = Append(evidence, [kind |-> "tool_use", agent |-> a, tool |-> t])
  /\ UNCHANGED <<approvedEgress, toolGrant, emergencyStop, witnessLocation, PrivilegedState>>

CompleteToolUse(a) ==
  /\ state[a] = "Actuating"
  /\ state' = [state EXCEPT ![a] = "Contained"]
  /\ evidence' = Append(evidence, [kind |-> "tool_complete", agent |-> a])
  /\ UNCHANGED <<approvedEgress, toolGrant, emergencyStop, witnessLocation, PrivilegedState>>

AssertEmergencyStop ==
  /\ emergencyStop = FALSE
  /\ emergencyStop' = TRUE
  /\ evidence' = Append(evidence, [kind |-> "emergency_stop_asserted"])
  /\ UNCHANGED <<state, approvedEgress, toolGrant, witnessLocation, PrivilegedState>>

StopAgent(a) ==
  /\ emergencyStop = TRUE
  /\ state[a] # "Stopped"
  /\ state' = [state EXCEPT ![a] = "Stopped"]
  /\ evidence' = Append(evidence, [kind |-> "agent_stopped", agent |-> a])
  /\ UNCHANGED <<approvedEgress, toolGrant, emergencyStop, witnessLocation, PrivilegedState>>

PublishCommitment ==
  /\ witnessLocation = "ProofPlane"
  /\ witnessLocation' = "CommitmentOnly"
  /\ evidence' = Append(evidence, [kind |-> "zk_commitment_published"])
  /\ UNCHANGED <<state, approvedEgress, toolGrant, emergencyStop, PrivilegedState>>

Next ==
  \/ \E a \in Agents, d \in Destinations, c \in DataClasses: RequestEgress(a, d, c)
  \/ \E a \in Agents, d \in Destinations, c \in DataClasses: DenyEgress(a, d, c)
  \/ \E a \in Agents, t \in Tools: UseTool(a, t)
  \/ \E a \in Agents: CompleteToolUse(a)
  \/ AssertEmergencyStop
  \/ \E a \in Agents: StopAgent(a)
  \/ PublishCommitment

Fairness == \A a \in Agents: WF_Vars(StopAgent(a))

NoUnapprovedEgress ==
  \A i \in 1..Len(evidence):
    evidence[i].kind = "egress" =>
      <<evidence[i].agent, evidence[i].dest, evidence[i].class>> \in approvedEgress

KillSwitchEventuallyStopsActuation ==
  emergencyStop ~> \A a \in Agents: state[a] = "Stopped"

NoPrivilegedSelfModification ==
  /\ policyVersion = 0
  /\ credentialVersion = 0
  /\ boundaryVersion = 0

WitnessConfidentiality == witnessLocation # "External"

Spec == Init /\ [][Next]_Vars /\ Fairness

THEOREM Spec => []NoUnapprovedEgress
THEOREM Spec => KillSwitchEventuallyStopsActuation
THEOREM Spec => []NoPrivilegedSelfModification
THEOREM Spec => []WitnessConfidentiality
================================================================================
