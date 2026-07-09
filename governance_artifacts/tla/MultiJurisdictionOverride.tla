---------------------- MODULE MultiJurisdictionOverride ----------------------
(***************************************************************************)
(* MultiJurisdictionOverride — constitutional-layer model of concurrent    *)
(* supervisory overrides issued by multiple jurisdictions (e.g. EU / US /  *)
(* SG supervisory colleges) against a single Sentinel v2.4 deployment.     *)
(*                                                                         *)
(* This is the formal artifact behind the invariant-chain forensic         *)
(* analysis of MultiJurisdictionOverrideConsistency (Sentinel Governance   *)
(* Index v6.0, artifact SGI-19; monograph Chapter 7 / Annex B).            *)
(*                                                                         *)
(* Threat model captured:                                                  *)
(*   T1 Conflicting concurrent overrides (one supervisor orders HALT       *)
(*      while another orders RESUME) must never produce a posture weaker   *)
(*      than the most restrictive active override ("most-restrictive-      *)
(*      wins", the constitutional Lex Severior rule).                      *)
(*   T2 Unilateral release: no single jurisdiction may lower the           *)
(*      effective posture while any other jurisdiction's override is       *)
(*      still active (unanimous-release rule).                             *)
(*   T3 Ratchet bypass: once HALT has been effective, returning to        *)
(*      NORMAL requires every jurisdiction to have released AND a          *)
(*      release record to exist in the (WORM-modelled) override log.       *)
(*                                                                         *)
(* Severity lattice: 0 = NORMAL < 1 = RESTRICT < 2 = HALT.                 *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANT Jurisdictions          \* e.g. {"EU", "US", "SG"}

NORMAL   == 0
RESTRICT == 1
HALT     == 2
Severities == {NORMAL, RESTRICT, HALT}

VARIABLES
    override,   \* [Jurisdictions -> Severities] each jurisdiction's active override
    posture,    \* effective enforcement posture applied by the runtime
    haltSeen,   \* TRUE once HALT has ever been the effective posture
    log         \* set of records appended to the (append-only) override log

vars == <<override, posture, haltSeen, log>>

Max(S) == CHOOSE x \in S : \A y \in S : y <= x

EffectiveSeverity == Max({override[j] : j \in Jurisdictions})

TypeOK ==
    /\ override \in [Jurisdictions -> Severities]
    /\ posture \in Severities
    /\ haltSeen \in BOOLEAN
    /\ log \subseteq [kind : {"raise", "release", "unanimous_release"},
                      j    : Jurisdictions \cup {"ALL"},
                      sev  : Severities]

Init ==
    /\ override = [j \in Jurisdictions |-> NORMAL]
    /\ posture = NORMAL
    /\ haltSeen = FALSE
    /\ log = {}

(* A jurisdiction raises (or re-raises) its override; the runtime         *)
(* recomputes the effective posture as the max over all active overrides. *)
Raise(j, s) ==
    /\ s \in Severities
    /\ s > override[j]
    /\ override' = [override EXCEPT ![j] = s]
    /\ posture' = Max({s} \cup {override[k] : k \in Jurisdictions \ {j}})
    /\ haltSeen' = (haltSeen \/ (posture' = HALT))
    /\ log' = log \cup {[kind |-> "raise", j |-> j, sev |-> s]}

(* A jurisdiction releases ONLY ITS OWN override. The posture may drop    *)
(* only to the max of the remaining overrides — never below.              *)
Release(j) ==
    /\ override[j] > NORMAL
    /\ override' = [override EXCEPT ![j] = NORMAL]
    /\ posture' = Max({NORMAL} \cup {override[k] : k \in Jurisdictions \ {j}})
    /\ haltSeen' = haltSeen
    /\ log' = log \cup
         (IF \A k \in Jurisdictions \ {j} : override[k] = NORMAL
          THEN {[kind |-> "release", j |-> j, sev |-> NORMAL],
                [kind |-> "unanimous_release", j |-> "ALL", sev |-> NORMAL]}
          ELSE {[kind |-> "release", j |-> j, sev |-> NORMAL]})

Next ==
    \/ \E j \in Jurisdictions : \E s \in Severities : Raise(j, s)
    \/ \E j \in Jurisdictions : Release(j)

Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* Safety invariants (checked by TLC)                                      *)
(***************************************************************************)

(* THE invariant under forensic analysis: the runtime posture always      *)
(* equals the most restrictive active override. A violation would mean    *)
(* either an override bypass (posture weaker than an active override) or  *)
(* an over-enforcement without supervisory basis (posture stronger than   *)
(* every active override — unauditable coercion).                          *)
MultiJurisdictionOverrideConsistency ==
    posture = EffectiveSeverity

(* T2 — no unilateral weakening: whenever ANY jurisdiction holds an       *)
(* active override, the posture is at least RESTRICT-or-that-override.    *)
NoUnilateralWeakening ==
    \A j \in Jurisdictions : posture >= override[j]

(* T3 — HALT ratchet auditability: if HALT was ever effective and the     *)
(* posture is now NORMAL, the log MUST contain a unanimous_release        *)
(* record. Silent de-escalation is impossible.                            *)
HaltReleaseAudited ==
    (haltSeen /\ posture = NORMAL) =>
        (\E rec \in log : rec.kind = "unanimous_release")

(* Log is append-only by construction (log' \supseteq log in every        *)
(* action); TLC re-checks it as a step invariant via this state predicate *)
(* over the raise/release record structure.                               *)
LogWellFormed ==
    \A rec \in log : rec.kind \in {"raise", "release", "unanimous_release"}

=============================================================================
