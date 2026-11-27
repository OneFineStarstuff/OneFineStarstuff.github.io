# WP-098 — Evidence Contract and Regulatory Crosswalk Hardening

**Date:** 2026-11-10  
**Base:** main at ae9cebb8a317cabba5fa272dfaf5a406f85f0400

## Changes
- Adds explicit OBSERVED, SIMULATED, UNKNOWN, NOT_ESTIMATED and NOT_ASSESSED evidence states.
- Requires null values for unavailable/unestimated/unassessed observations; missing values are not zero or GREEN.
- Makes digest length algorithm-specific for SHA-256, SHA-384, SHA-512 and SHA3-512.
- Adds a twelve-index semantic catalog; CGR-I, CCR-I and G-SRI-VII remain unresolved; Delta_OSCAL is structured-only; p(doom) variants remain unvalidated.
- Updates current model-risk mapping to SR 26-2 and preserves SR 11-7 as historical lineage only.
- Separates simulation controls and analogy-only references from real regulatory mappings.
- Adds primary source register entries for EU AI Act amendment, SR 26-2, MAS 2026 AI risk guidelines, FIPS 203 and OSCAL 1.1.2.
- Adds focused JSON Schema and crosswalk tests with path-scoped CI.

## Explicit limitations
No legal review, institution-specific applicability decision, validated GIEN formula, native OSCAL conformance, cryptographic recomputation, live institutional telemetry, regulator endorsement or compliance certification is claimed.

## Acceptance
Merge only after the contract workflow passes and a human reviewer approves the crosswalk and schema changes.
