# TLA+ Model Checking Guide: SIP v3.0 Federated Protocol

This guide provides technical auditors and platform engineers with a walkthrough of the formal verification process for the Sentinel Interoperability Protocol (SIP) v3.0.

## 1. Specification Overview: `SIPv3_Federated_Protocol.tla`
The specification models a network of Institutions and Roots. It uses a gossip mechanism to ensure that all honest roots eventually converge on a consistent view of the institutional state (Merkle tree heads).

## 2. Model Setup in the TLA+ Toolbox
To run the model checker (TLC), configure the following constants in a new Model:

- **Institutions:** `{inst1, inst2}` (Minimal set for safety checks).
- **Roots:** `{rootA, rootB}` (Required for gossip consistency).
- **MaxMissingWindows:** `2` (Threshold for missing attestation alerts).
- **Epochs:** `0..5` (Bounded for state space efficiency).

## 3. Verifying Safety Invariants
Safety properties define what "bad things" should never happen.

### Invariant: `NoSilentDivergence`
- **Definition:** `\A i \in Institutions : \A m1, m2 \in messages : (m1.type = "STH_PUBLISH" /\ m2.type = "STH_PUBLISH" /\ m1.inst = i /\ m1.epoch = m2.epoch) => m1.sth = m2.sth`
- **Verification:** TLC explores all reachable states. If an institution publishes two different STHs for the same epoch, TLC generates an error trace.

### Invariant: `EquivocationDetected`
- **Definition:** Triggered when a root sees two different STHs for the same (inst, epoch).
- **Adversarial Testing:** Use a "Byzantine Institution" model (manual state override) to force an equivocation and confirm the invariant is flagged.

## 4. Verifying Liveness Properties
Liveness properties define what "good things" must eventually happen.

### Property: `RootConvergence`
- **Definition:** Under honest conditions, all roots eventually possess the same knowledge set.
- **Check:** TLC verifies that there is no infinite path where roots remain divergent while messages are pending.

### Property: `MissingAttestationDetectable`
- **Check:** Verify that if an institution stops calling `InstPublish`, the system state eventually triggers an alert state after `MaxMissingWindows` have passed.

## 5. Model Checking under Byzantine Conditions
To simulate a G-SIFI pilot environment, the model must be checked against:
1. **Byzantine Institution:** Forks its Merkle log (Equivocation).
2. **Byzantine Root:** Drops gossip messages or presents stale STHs.
3. **Network Partition:** Bounded message delivery latency simulations.

## 6. Expected TLC Output
A successful verification should yield:
- **Status:** Finished.
- **Distinct States:** ~10,000 to 100,000 depending on constant bounds.
- **Invariants:** No violations found (except when explicitly testing adversarial triggers).
