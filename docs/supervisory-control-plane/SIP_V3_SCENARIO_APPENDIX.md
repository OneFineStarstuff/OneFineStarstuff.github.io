# SIP v3.0 Scenario Appendix: TLA+ TLC Walkthroughs

This appendix provides detailed walkthroughs of the Sentinel Interoperability Protocol (SIP) v3.0 formal specification, demonstrating how safety and liveness invariants are upheld across various operational scenarios.

## Scenario 1: Normal Convergence (Honest System)
In this scenario, all Institutions and Roots act according to the protocol.

1. **Initial State:** All institutions at epoch 0 with no published STHs.
2. **Action: `InstPublish(Inst1, Epoch1, Root1)`:** Institution 1 signs and gossips its first Signed Tree Head (STH).
3. **Action: `RootGossip(RootA, msg)`:** Root A receives the publish message and shares it with other roots.
4. **TLC Verification:**
* **Invariant `RootConvergence`:** Observed. All roots eventually update their local knowledge state to include Inst1's Epoch1 STH.
* **Invariant `NoSilentDivergence`:** Held. Only one STH exists for (Inst1, Epoch1).
5. **Regulator View:** Verifier nodes observe consistent STHs across all GIEN roots, confirming institutional stability.

## Scenario 2: Equivocation Detection (Byzantine Institution)
An institution attempts to present different versions of its history to different parts of the network (forking the Merkle log).

1. **Action: `InstPublish(Inst1, Epoch5, RootA_Hash)`:** Inst1 sends one STH to Root A.
2. **Action: `InstPublish(Inst1, Epoch5, RootB_Hash)`:** Inst1 sends a *different* STH for the same epoch to Root B.
3. **Protocol Response:** As roots gossip (`RootGossip`), they exchange these conflicting messages.
4. **TLC Verification:**
* **Invariant `EquivocationDetected`:** Triggered. The state transition logic flags that `rootState[r].knowledge` contains two distinct STHs for the same (inst, epoch).
* **Safety Action:** The protocol initiates an "Equivocation Alert," and Verifier Nodes mark Inst1 as "Unreliable."
5. **Regulator View:** Verifier Node CLI displays an "Equivocation Detected" error with the two conflicting PQC-signed traces as evidence.

## Scenario 3: Missing Attestation Detection (Silent Institution)
An institution goes silent, failing to provide the required heartbeats or Merkle log updates.

1. **Context:** The system expects an STH publish every window.
2. **State:** Clock advances, but Inst2 fails to call `InstPublish`.
3. **TLC Verification:**
* **Invariant `MissingAttestationDetectable`:** Triggered. The model checker verifies that if `current_epoch - last_published_epoch > MAX_MISSING_WINDOWS`, the system enters a "Violation" state.
4. **Regulator View:** Verifier Node dashboard highlights Inst2 in Red with a "Stale Attestation" warning.
5. **Safety Action:** GSM transitions to "QUARANTINE" for any models dependent on Inst2's telemetry until the missing attestation is resolved or explained.

## Invariant Summary Table

| Invariant | Scenario 1 | Scenario 2 | Scenario 3 |
| :--- | :---: | :---: | :---: |
| NoSilentDivergence | PASS | FAIL (Detected) | PASS |
| EquivocationDetected | FALSE | TRUE (Triggered) | FALSE |
| RootConvergence | PASS | N/A (Alerted) | PASS |
| MissingAttestationDetectable | FALSE | FALSE | TRUE (Triggered) |
| NoProtocolError | PASS | PASS | PASS |
