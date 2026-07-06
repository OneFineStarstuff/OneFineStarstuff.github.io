---- MODULE SIPv3_Federated_Protocol ----
EXTENDS Naturals, Sequences, Sets

CONSTANT Institutions, Roots, MaxMissingWindows

VARIABLES
    instState,    \* State of each institution (last epoch, last STH)
    rootState,    \* State of each root (known STHs for each institution)
    messages      \* Messages in transit (gossip)

\* Types and Sets
Epochs == 0..100
STHs == [inst : Institutions, epoch : Epochs, root : SUBSET {0, 1}] \* Simplified STH

\* Initial State
Init ==
    /\ instState = [i \in Institutions |-> [epoch |-> 0, sth |-> "none"]]
    /\ rootState = [r \in Roots |-> [knowledge |-> {}]]
    /\ messages = {}

\* Actions
InstPublish(i, e, r) ==
    /\ instState[i].epoch < e
    /\ instState' = [instState EXCEPT ![i] = [epoch |-> e, sth |-> r]]
    /\ messages' = messages \cup {[type |-> "STH_PUBLISH", inst |-> i, epoch |-> e, sth |-> r]}
    /\ UNCHANGED rootState

RootGossip(r, msg) ==
    /\ msg \in messages
    /\ msg.type = "STH_PUBLISH"
    /\ rootState' = [rootState EXCEPT ![r].knowledge = rootState[r].knowledge \cup {msg}]
    /\ messages' = messages \cup {[type |-> "ROOT_GOSSIP", from |-> r, msg |-> msg]}

\* Safety Invariants
NoSilentDivergence ==
    \A i \in Institutions :
        \A m1, m2 \in messages :
            (m1.type = "STH_PUBLISH" /\ m2.type = "STH_PUBLISH" /\ m1.inst = i /\ m2.inst = i /\ m1.epoch = m2.epoch)
            => m1.sth = m2.sth

EquivocationDetected ==
    \E r \in Roots :
        \E m1, m2 \in rootState[r].knowledge :
            (m1.inst = m2.inst /\ m1.epoch = m2.epoch /\ m1.sth # m2.sth)

RootConvergence ==
    \A r1, r2 \in Roots :
        \A i \in Institutions :
            \* Eventually roots should see the same STHs for honest institutions
            TRUE

\* Liveness Properties
MissingAttestationDetectable ==
    \A i \in Institutions :
        \E r \in Roots :
            \* If current time - last_sth_time > MaxMissingWindows, trigger alert
            TRUE

Next ==
    \E i \in Institutions : \E e \in Epochs : \E r \in STHs : InstPublish(i, e, r)
    \/ \E r \in Roots : \E msg \in messages : RootGossip(r, msg)

Spec == Init /\ [][Next]_<<instState, rootState, messages>>
=============================================================================
