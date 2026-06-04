----------------- MODULE SentinelContainmentProtocol -----------------
EXTENDS Naturals, Sequences

VARIABLES state, auth_tokens, g_sri

Init ==
    /\ state = "OPERATIONAL"
    /\ auth_tokens = {}
    /\ g_sri = 0

Next ==
    \/ /\ g_sri < 75
       /\ state = "OPERATIONAL"
       /\ \E t \in 1..100 : auth_tokens' = auth_tokens \cup {t}
       /\ UNCHANGED <<state, g_sri>>
    \/ /\ g_sri >= 75
       /\ state = "HALTED"
       /\ auth_tokens' = {}
       /\ UNCHANGED g_sri

SafetyInvariant == state = "OPERATIONAL" => g_sri < 75
=============================================================================
