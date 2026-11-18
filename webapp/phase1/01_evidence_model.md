# 01 — Evidence Model (WP-098 hardening)

**Contract version:** 1.1.0  
**Metric catalog:** GIEN-METRIC-CATALOG-0.2.0  
**Status:** Provisional design contract; production use not approved.

## Evidence chain
Every displayed observation must resolve through: metric definition/version → observation state and window → source observation IDs → applicable controls → evidence artifacts → algorithm-labelled digest and Merkle root → verification result and reviewer.

A hash establishes consistency against a digest, not the truthfulness or completeness of the source. A signature supports attribution/integrity subject to identity, key and trust controls. Neither proves legal applicability or control effectiveness.

## Observation states
| State | Value | Band | Meaning |
|---|---|---|---|
| OBSERVED | Numeric | GREEN/AMBER/RED/UNKNOWN | Source-backed observation with source IDs and real evidence artifacts |
| SIMULATED | Numeric | GREEN/AMBER/RED/UNKNOWN | Synthetic/scenario result; all linked artifacts are simulation-layer |
| UNKNOWN | null | UNKNOWN | Evidence insufficient |
| NOT_ESTIMATED | null | NOT_ESTIMATED | Estimate not produced |
| NOT_ASSESSED | null | NOT_ASSESSED | No qualifying assessment performed |

Missing values must never be converted to zero or GREEN.

## Metric semantic conflicts
CGR-I and CCR-I have conflicting readiness/risk semantics in prior artifacts. G-SRI-VII is a fictional Phase VII construct whose meaning is not ratified. Delta_OSCAL is a structured catalog diff, not a scalar count. p(doom) variants are unvalidated and require event definition, population, horizon, calibration and uncertainty evidence.

## Algorithm-aware digests
SHA-256 = 64 hex characters; SHA-384 = 96; SHA-512 = 128; SHA3-512 = 128, excluding the 0x prefix. Record the algorithm explicitly for every artifact digest and Merkle root. FIPS 203 ML-KEM is key establishment, not a signature algorithm; FIPS 204 ML-DSA and FIPS 205 SLH-DSA are signature standards.

## Crosswalk boundary
The webapp crosswalk is an internal OSCAL-oriented seed, not a native OSCAL Catalog. Real mappings remain PROPOSED_UNREVIEWED; simulation controls are SIMULATION_ONLY; conceptual comparisons are stored under analogy_only; superseded guidance is historical only.
