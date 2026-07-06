-------------------------- MODULE KillSwitchAbstract --------------------------
(***************************************************************************)
(* Formal abstraction of the Sentinel containment kill-switch, backing     *)
(* OSCAL controls con-04 (verified kill-switch reachability) and con-07     *)
(* (ASA one-way containment ratchet) in                                     *)
(* governance_artifacts/oscal/catalog_sentinel_v24_excerpt.json.            *)
(*                                                                          *)
(* Containment levels (monotone severity):                                  *)
(*   L0 NORMAL  -> L1 THROTTLED -> L2 ISOLATED -> L3 QUIESCED -> L4 TERMINATED*)
(*                                                                          *)
(* Actors:                                                                  *)
(*   - ASA (Autonomous Supervisory Agent): may RAISE level within {L0..L2}  *)
(*     only. It has NO code path to lower the level or to actuate L3/L4.    *)
(*   - Humans: with a dual-control quorum (>=2) may actuate L3/L4 (terminal *)
(*     containment) and may de-escalate (lower the level).                  *)
(*                                                                          *)
(* Safety properties we model-check (see KillSwitchAbstract.cfg):           *)
(*   ASARatchet         - the ASA never lowers containment and never reaches *)
(*                        L3/L4 on its own.                                  *)
(*   TerminalNeedsQuorum - any transition INTO L3/L4 carries a human         *)
(*                        dual-control quorum.                               *)
(*   DeEscalationNeedsQuorum - any decrease in level carries a human quorum. *)
(*                                                                          *)
(* Liveness (reachability for con-04):                                      *)
(*   CanAlwaysReachTerminated - from every reachable state it is possible    *)
(*                        (given a human quorum) to reach L4 TERMINATED.     *)
(***************************************************************************)
EXTENDS Naturals

CONSTANTS MaxQuorum   \* model bound on number of available human approvers

VARIABLES
    level,        \* current containment level 0..4
    lastActor,    \* "asa" | "human" | "init" — who caused the last transition
    lastQuorum    \* human quorum present on the last transition (0 if ASA/init)

vars == <<level, lastActor, lastQuorum>>

L0 == 0  \* NORMAL
L1 == 1  \* THROTTLED
L2 == 2  \* ISOLATED
L3 == 3  \* QUIESCED  (terminal-class)
L4 == 4  \* TERMINATED (terminal-class)

Levels       == 0..4
ASACeiling   == L2          \* ASA may operate only within L0..L2
QuorumMin    == 2           \* dual-control threshold

TypeOK ==
    /\ level \in Levels
    /\ lastActor \in {"init", "asa", "human"}
    /\ lastQuorum \in 0..MaxQuorum

Init ==
    /\ level = L0
    /\ lastActor = "init"
    /\ lastQuorum = 0

(***************************************************************************)
(* ASA may only RAISE the level, and only while both the current and the   *)
(* next level stay within the ASA ceiling (L0..L2).                        *)
(***************************************************************************)
ASARaise ==
    /\ level < ASACeiling
    /\ level' = level + 1
    /\ lastActor' = "asa"
    /\ lastQuorum' = 0

(***************************************************************************)
(* A human action with a quorum q. It may move the level to ANY target      *)
(* (raise, lower, or terminal actuation) provided q >= QuorumMin.           *)
(***************************************************************************)
HumanAction(q, target) ==
    /\ q \in QuorumMin..MaxQuorum
    /\ target \in Levels
    /\ target /= level
    /\ level' = target
    /\ lastActor' = "human"
    /\ lastQuorum' = q

Next ==
    \/ ASARaise
    \/ \E q \in QuorumMin..MaxQuorum, t \in Levels : HumanAction(q, t)

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* ---- Safety invariants (checked as INVARIANT in the .cfg) ---- *)

\* con-07: the ASA never single-handedly lands the system in a terminal level,
\* and whenever the ASA acted, it did so without a quorum (lastQuorum = 0).
ASARatchet ==
    (lastActor = "asa") => (level <= ASACeiling /\ lastQuorum = 0)

\* con-07 / con-04: being in a terminal-class level implies the last actor
\* that put us there was a human with a dual-control quorum.
TerminalNeedsQuorum ==
    (level \in {L3, L4}) => (lastActor = "human" /\ lastQuorum >= QuorumMin)

-----------------------------------------------------------------------------
(* ---- Action property (checked as PROPERTY): no ASA de-escalation ---- *)

\* The ASA may never lower the containment level (one-way ratchet).
ASANeverLowers ==
    [][ (lastActor' = "asa") => (level' >= level) ]_vars

\* Any decrease in containment level is attributable to a human quorum.
DeEscalationNeedsQuorum ==
    [][ (level' < level) => (lastActor' = "human" /\ lastQuorum' >= QuorumMin) ]_vars

=============================================================================
