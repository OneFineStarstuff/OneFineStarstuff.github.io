----------------- MODULE MasterShutdownSequence -----------------
EXTENDS Naturals, Sequences, FiniteSets

VARIABLES regions, globalState

Init ==
    /\ regions = [r \in {"ALBION", "PACIFIC", "EU_CENTRAL"} |-> "OPERATIONAL"]
    /\ globalState = "ACTIVE"

Shutdown(r) ==
    /\ globalState = "SHUTDOWN_INITIATED"
    /\ regions[r] = "OPERATIONAL"
    /\ regions' = [regions EXCEPT ![r] = "SHUTDOWN_COMPLETE"]
    /\ UNCHANGED globalState

InitiateGlobalShutdown ==
    /\ globalState = "ACTIVE"
    /\ globalState' = "SHUTDOWN_INITIATED"
    /\ UNCHANGED regions

AllRegionsDown == \A r \in DOMAIN regions : regions[r] = "SHUTDOWN_COMPLETE"

Next ==
    \/ InitiateGlobalShutdown
    \/ \E r \in DOMAIN regions : Shutdown(r)
    \/ /\ AllRegionsDown
       /\ globalState = "SHUTDOWN_INITIATED"
       /\ globalState' = "TERMINATED"
       /\ UNCHANGED regions

SafetyInvariant == (globalState = "TERMINATED") => AllRegionsDown
=============================================================================
