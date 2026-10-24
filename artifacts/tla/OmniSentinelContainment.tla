(**** Omni-Sentinel containment specification -- fictional governance simulation ****)

------- MODULE OmniSentinelContainment -------

EXTENDS Naturals, Sequences

VARIABLES actuation, egressQueue, approvedDestinations, privilegedSelfModification, witnessLog, killSwitchArmed

Vars == <<actuation, egressQueue, approvedDestinations, privilegedSelfModification, witnessLog, killSwitchArmed>>

Init ==
    / actuation \in {"idle", "running"}
    /\ egressQueue = <<>>
    /\ approvedDestinations = {"supervisory-college", "worm-ledger"}
    /\ privilegedSelfModification = FALSE
    /\ witnessLog = <<>>
    /\ killSwitchArmed = TRUE

SubmitEgress(dest) ==
    /\ dest \in approvedDestinations
    /\ egressQueue' = Append(egressQueue, dest)
    /\ UNCHANGED <<actuation, approvedDestinations, privilegedSelfModification, witnessLog, killSwitchArmed>>

DrainEgress ==
    /\ egressQueue # <<>>
    /\ egressQueue' = Tail(egressQueue)
    /\ UNCHANGED <<actuation, approvedDestinations, privilegedSelfModification, witnessLog, killSwitchArmed>>

AttemptPrivilegedSelfModification ==
    /\ privilegedSelfModification' = TRUE
    /\ UNCHANGED <<actuation, egressQueue, approvedDestinations, witnessLog, killSwitchArmed>>

RecordWitness(event) ==
    /\ witnessLog' = Append(witnessLog, event)
    /\ UNCHANGED <<actuation, egressQueue, approvedDestinations, privilegedSelfModification, killSwitchArmed>>

TripKillSwitch ==
    /\ killSwitchArmed
    /\ actuation' = "idle"
    /\ egressQueue' = <<>>
    /\ UNCHANGED <<approvedDestinations, privilegedSelfModification, witnessLog, killSwitchArmed>>

Next ==
    \/ SubmitEgress("supervisory-college")
    \/ SubmitEgress("worm-ledger")
    \/ DrainEgress
    \/ AttemptPrivilegedSelfModification
    \/ RecordWitness("containment-heartbeat")
    \/ TripKillSwitch

TypeOK ==
    /\ actuation \in {"idle", "running"}
    /\ killSwitchArmed \in BOOLEAN

Invariant == TypeOK

Spec == Init /\ [][Next]_Vars

NoUnapprovedEgress ==
    \A i \in 1..Len(egressQueue) : egressQueue[i] \in approvedDestinations

KillSwitchEventuallyStopsActuation ==
    []<>(killSwitchArmed => (actuation = "idle"))

NoPrivilegedSelfModification ==
    privilegedSelfModification = FALSE

WitnessConfidentiality ==
    \A w \in witnessLog : w \notin approvedDestinations

Fairness == WF_vars(Next)

THEOREM Spec => []NoUnapprovedEgress
THEOREM Spec => KillSwitchEventuallyStopsActuation
THEOREM Spec => []NoPrivilegedSelfModification
THEOREM Spec => []WitnessConfidentiality

=============================================================================
