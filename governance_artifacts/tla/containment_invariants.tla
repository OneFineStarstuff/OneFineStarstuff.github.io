---------------- MODULE containment_invariants ----------------
EXTENDS Naturals, Sequences

VARIABLES
    enclave_state,    (* "SECURE", "COMPROMISED" *)
    kill_switch,      (* "INACTIVE", "ACTIVE" *)
    g_sri_value,      (* 0..100 *)
    action_log        (* Sequence of actions *)

Vars == <<enclave_state, kill_switch, g_sri_value, action_log>>

Init ==
    /\ enclave_state = "SECURE"
    /\ kill_switch = "INACTIVE"
    /\ g_sri_value = 0
    /\ action_log = << >>

Next ==
    \/ /\ g_sri_value < 90
       /\ g_sri_value' = g_sri_value + 1
       /\ UNCHANGED <<enclave_state, kill_switch, action_log>>
    \/ /\ g_sri_value >= 90
       /\ kill_switch' = "ACTIVE"
       /\ UNCHANGED <<enclave_state, g_sri_value, action_log>>

(* INVARIANTS *)

(* Invariant: If systemic risk is critical, the kill switch must be active *)
Safety_SystemicContainment ==
    (g_sri_value >= 90) => (kill_switch = "ACTIVE")

(* Invariant: No actions allowed if enclave is compromised or kill switch is active *)
Safety_ExecutionGated ==
    (enclave_state = "COMPROMISED" \/ kill_switch = "ACTIVE") =>
        (Len(action_log) = 0 \/ action_log[Len(action_log)] = "HALT")

==============================================================
