# Enterprise AI Agent Interoperability Protocol (EAIP) — Canonical Specification

This directory is the canonical home of the EAIP specification inside the OneFineStarstuff.github.io governance hub, consolidating the two formerly fragmented specification repositories (Pinn and Hesaitun).

## Canonical spec

- `eaip_specification.xml` — EAIP v3.4.1 (FINALIZED 2026-03-15), migrated verbatim from the Pinn repository. Designated canonical: highest spec version, RCE schema_version 3, and the name used across the GIEN governance documentation ("EAIP agent interoperability", WP-064 / WP-070 / WP-083).
- `eaip-spec-v3.xsd` — companion XML Schema (v3.4.1), migrated verbatim from Pinn.

## Preserved alternate lineage

- `lineage/EAIP_Technical_Specification.xml` — EAIP v2.4.1 "Enterprise AI Integration Protocol" (FINALIZED 2026-03-16), migrated verbatim from the Hesaitun repository. Retained for its STRICT conformance profile (C-T / C-I / C-R requirements), structured error-code registry (EAIP-1001 through EAIP-3001), and the six-domain AGI/ASI governance framework that remains in Hesaitun/governance/.

## Pillars (both lineages)

1. **Transport**: gRPC over HTTP/2, mutual TLS, schema-first proto contracts.
2. **Identity**: SPIFFE/SPIRE workload identity, short-lived X.509 SVIDs.
3. **State**: Recursive Context Envelope (RCE) for distributed agentic state propagation.

See [PROVENANCE.md](./PROVENANCE.md) for sources, blob SHAs, and the consolidation decision.
