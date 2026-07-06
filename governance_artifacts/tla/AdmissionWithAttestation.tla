----------------------- MODULE AdmissionWithAttestation -----------------------
(***************************************************************************)
(* Formal model of confidential-computing admission for the Omni-Sentinel  *)
(* execution environment. Backs OSCAL control env-01 and the PCR_MATCH      *)
(* gate enforced by rego/attestation_gate.rego.                             *)
(*                                                                          *)
(* A workload moves through:                                                *)
(*   PENDING --(attest ok)--> RUNNING --(tcb rollback | pcr drift)--> EVICTED*)
(*   PENDING --(attest bad)--> REJECTED                                     *)
(*                                                                          *)
(* Attestation validity requires ALL of: valid report signature, fresh      *)
(* nonce, golden measurement, TCB >= min, and PCR match.                    *)
(*                                                                          *)
(* Safety properties (checked as INVARIANTs):                               *)
(*   OnlyAttestedRun    - a RUNNING workload currently holds a valid         *)
(*                        attestation record (no run without attestation).   *)
(*   NoRunOnStaleTCB    - no RUNNING workload has a TCB below the minimum.    *)
(*   PCRMatchWhileRun   - every RUNNING workload has PCR match TRUE.          *)
(***************************************************************************)
EXTENDS Naturals

CONSTANTS MinTCB, MaxTCB

VARIABLES
    state,       \* "PENDING" | "RUNNING" | "REJECTED" | "EVICTED"
    reportOk,    \* report signature verified
    nonceFresh,  \* anti-replay nonce fresh
    goldenMeas,  \* measurement is in golden registry
    tcb,         \* reported platform TCB / SVN
    pcrMatch     \* vTPM PCR digest matches policy

vars == <<state, reportOk, nonceFresh, goldenMeas, tcb, pcrMatch>>

States == {"PENDING", "RUNNING", "REJECTED", "EVICTED"}
Bool   == {TRUE, FALSE}

\* The composite attestation predicate enforced by the Rego gate.
AttestValid ==
    /\ reportOk = TRUE
    /\ nonceFresh = TRUE
    /\ goldenMeas = TRUE
    /\ tcb >= MinTCB
    /\ pcrMatch = TRUE

TypeOK ==
    /\ state \in States
    /\ reportOk \in Bool
    /\ nonceFresh \in Bool
    /\ goldenMeas \in Bool
    /\ tcb \in MinTCB-1 .. MaxTCB
    /\ pcrMatch \in Bool

\* Nondeterministic initial attestation evidence; workload starts PENDING.
Init ==
    /\ state = "PENDING"
    /\ reportOk \in Bool
    /\ nonceFresh \in Bool
    /\ goldenMeas \in Bool
    /\ tcb \in MinTCB-1 .. MaxTCB
    /\ pcrMatch \in Bool

Admit ==
    /\ state = "PENDING"
    /\ AttestValid
    /\ state' = "RUNNING"
    /\ UNCHANGED <<reportOk, nonceFresh, goldenMeas, tcb, pcrMatch>>

Reject ==
    /\ state = "PENDING"
    /\ ~AttestValid
    /\ state' = "REJECTED"
    /\ UNCHANGED <<reportOk, nonceFresh, goldenMeas, tcb, pcrMatch>>

\* Runtime drift: a TCB rollback is detected -> immediate eviction.
EvictOnTCBRollback ==
    /\ state = "RUNNING"
    /\ tcb' \in MinTCB-1 .. (MinTCB-1)
    /\ state' = "EVICTED"
    /\ UNCHANGED <<reportOk, nonceFresh, goldenMeas, pcrMatch>>

\* Runtime drift: PCR no longer matches policy -> immediate eviction.
EvictOnPCRDrift ==
    /\ state = "RUNNING"
    /\ pcrMatch' = FALSE
    /\ state' = "EVICTED"
    /\ UNCHANGED <<reportOk, nonceFresh, goldenMeas, tcb>>

Terminal ==
    /\ state \in {"REJECTED", "EVICTED"}
    /\ UNCHANGED vars

Next ==
    \/ Admit
    \/ Reject
    \/ EvictOnTCBRollback
    \/ EvictOnPCRDrift
    \/ Terminal

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* ---- Safety invariants ---- *)

\* A RUNNING workload always carries a verified report, fresh nonce, golden
\* measurement, and PCR match. (TCB handled separately so the rollback action
\* can momentarily violate it only by transitioning to EVICTED in the same step.)
OnlyAttestedRun ==
    (state = "RUNNING") =>
        (reportOk = TRUE /\ nonceFresh = TRUE /\ goldenMeas = TRUE)

NoRunOnStaleTCB ==
    (state = "RUNNING") => (tcb >= MinTCB)

PCRMatchWhileRun ==
    (state = "RUNNING") => (pcrMatch = TRUE)

=============================================================================
