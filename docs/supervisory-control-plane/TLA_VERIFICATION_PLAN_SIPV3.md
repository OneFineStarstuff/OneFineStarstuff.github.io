# TLA+ Verification Plan for SIP v3.0 Federated Protocol

## 1. Objective
To formally verify the safety and liveness properties of the Sentinel Interoperability Protocol (SIP) v3.0, focusing on its ability to detect equivocation and missing attestations in a federated environment.

## 2. Protocol Scope: SIP v3.0
SIP v3.0 enables institutions to gossip Signed Tree Heads (STHs) to a set of Roots. Roots then exchange this information to ensure global consistency.

## 3. Critical Invariants

### Safety Invariants
- **NoSilentDivergence:** An honest institution never publishes two different STHs for the same epoch.
- **EquivocationDetected:** If an institution attempts to fork its Merkle log (equivocation), at least one honest root will eventually detect the conflicting STHs.
- **RootConvergence:** All honest roots eventually agree on the state of all honest institutions.

### Liveness Invariants
- **MissingAttestationDetectable:** If an institution fails to publish an STH within `MaxMissingWindows`, the supervisory system triggers a "Missing Attestation" alert.
- **NoProtocolError:** The protocol should never reach a deadlocked state where valid STHs cannot be propagated.

## 4. Verification Workflow
1. **Model Setup:** Define constants for `Institutions`, `Roots`, and `MaxMissingWindows`.
2. **State Exploration:** Use the TLC model checker to explore all reachable states of the `SIPv3_Federated_Protocol.tla` specification.
3. **Property Checking:**
   - Verify `NoSilentDivergence` holds in all states.
   - Inject "Byzantine" behavior (manual STH publication forking) to verify `EquivocationDetected` is triggered.
   - Simulate silence beyond `MaxMissingWindows` to verify detection.
4. **Refinement:** Adjust the protocol logic if invariants are violated.

## 5. Phase 0 Sandbox Validation
The TLA+ specification serves as the formal foundation for the Phase 0 sandbox, where simulated Decision Trace Packs are anchored to the Merkle log and verified by Regulator Verifier Nodes.
