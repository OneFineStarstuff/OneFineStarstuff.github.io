# Design Principles for Federated Supervisory Protocols (TLA+)

This document outlines the theoretical framework for designing and validating protocols like SIP v3.0 using TLA+.

## 1. Modeling Byzantine Faults
When designing for G-SIFI environments, "Byzantine" actors (institutions or roots that act arbitrarily or maliciously) must be first-class entities in the spec.

- **Equivocation:** Modeled by allowing an institution to non-deterministically choose between two different STHs for the same epoch.
- **Silence:** Modeled by allowing an institution to skip the `InstPublish` action.
- **Gossip Corruption:** Roots may (in the model) fail to propagate certain messages or reorder them.

## 2. Defining Safety (No Silent Divergence)
A protocol is safe if it detects divergence before it impacts the systemic risk of the mesh.

- **Invariant:** `DivergenceDetected == \forall i : sth_a[i] \neq sth_b[i] \implies \exists r : alert(r, i)`.
- **Model Check:** TLC must prove that no state exists where institutions have diverged but no alert has been triggered.

## 3. Defining Liveness (Root Convergence)
Liveness ensures the system doesn't "freeze" under normal or stressed conditions.

- **Property:** `EventuallyConverged == <>( \forall r1, r2 : knowledge[r1] = knowledge[r2] )`.
- **Constraint:** This assumes a "fair" scheduler where roots eventually gossip their messages.

## 4. Detecting Missing Attestations (Completeness)
Completeness ensures that the absence of evidence is itself a form of evidence.

- **The Windowing Strategy:** Use an incremental epoch or global clock in the TLA+ spec.
- **The Detector:** A root action that checks `current_time - last_seen[inst] > Threshold`.

## 5. Validation Workflow
1. **Abstract the Data:** Don't model actual Merkle proofs in TLA+; model them as unique hashes or set members.
2. **Bound the Model:** Keep Institutions and Roots small (e.g., 2-3 each) to avoid state explosion while still capturing federated edge cases.
3. **Trace Playback:** Use TLC error traces to refine the OPA/Rego implementations in the actual SCP Core.
