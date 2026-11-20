# CONSTITUTION.md

Treaty-grade constitutional invariants of the GIEN mesh and Omni-Sentinel stack (B7, WP-114), under CFE-1.0 and Protocol SGR-028.

## Invariants (verify with TLA+, currently rev 1184, 72/72)

1. **Sealed continuity** — every window closes with one frozen Merkle root, identical across all occurrences; zero ledger gaps on the WORM chain.
2. **Honest evidence** — no artefact may claim verification it cannot perform; root_recomputable=false for static corpora is mandatory and gate-enforced (PROMO-R9).
3. **Deny-by-default governance** — compliance profiles and promotions deny unless every invariant holds (PROMO-R1..R11; ANSM-R1..R5 per profile).
4. **Adjudicated promotion** — profile state changes require college adjudication (PROMO-R11) recorded in the zk voting transcript.
5. **Replay discipline** — Supervisory Digital Twin panels and RAG pipelines replay bit-identically, permanently adopted by college vote 2026-11-19.
6. **Deterministic or crypto-seeded derivation** — no unreplayable randomness in governed artefacts (A1).
7. **Human override** — kill-switch heartbeats 5/5 per window; emergency stop is the only autonomous-action exit and is logged to AlertHistory.
8. **Progressive disclosure** — supervisor audiences see bands and outcomes; engineer audiences see hashes and notes; the classification banner and fictional-simulation disclaimer travel with every view (A2).

## Epochs

- 2026-2035: zk-verified control plane, PQC-sealed supervision, SGR filing series, drill discipline.
- 2035-2100+: long-horizon stewardship through Phase Omega-GAR (2081-2100+), dissolution arc, Safeguard Mode readiness.

*Fictional governance simulation; this constitution governs simulated artefacts and no real system.*
