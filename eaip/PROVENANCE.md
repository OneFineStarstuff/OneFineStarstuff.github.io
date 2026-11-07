# EAIP Consolidation Provenance

Consolidated 2026-11-07 as WP-094 into the governance hub (OneFineStarstuff.github.io). First pushed during the 2026-11-06 estate-consolidation turn, then briefly withdrawn from the dossier-311 delivery branch (PR #233) to keep that pull request a pure dossier delivery, and re-delivered here unchanged.

## Sources (migrated verbatim)

| File in this directory | Source | Version |
| --- | --- | --- |
| `eaip_specification.xml` | OneFineStarstuff/Pinn, blob 01636ae16d2384a0f28ad04e37aac02ed39955bf | v3.4.1 (FINALIZED 2026-03-15) |
| `eaip-spec-v3.xsd` | OneFineStarstuff/Pinn, blob 01636ae16d2384a0f28ad04e37aac02ed39955bf | v3.4.1 |
| `lineage/EAIP_Technical_Specification.xml` | OneFineStarstuff/Hesaitun, blob 1d91e622b6e78d611676694b21c70426082daf33 | v2.4.1 (FINALIZED 2026-03-16) |

## Decision

Two FINALIZED lineages existed: "Enterprise AI Agent Interoperability Protocol" v3.4.1 (Pinn) and "Enterprise AI Integration Protocol" v2.4.1 (Hesaitun). Both cover the same three pillars (gRPC transport, SPIFFE/SPIRE identity, Recursive Context Envelope) but use incompatible namespaces (urn:eaip:v1 vs urn:eaip:schema:v2) and independent version histories. The v3.4.1 lineage is designated canonical (higher major version; RCE schema_version 3; name matches GIEN governance usage). The v2.4.1 lineage is preserved under lineage/ for its conformance profile and error-code registry. Future EAIP revisions should continue from v3.4.1.

## Verification

To verify verbatim migration, diff these files against the source blobs at the SHAs listed above.

## Supersession

The Pinn and Hesaitun repositories remain untouched as historical sources; future EAIP work happens here. Repository archival or deletion requires GitHub account administration and was outside the scope of the integration token used for this consolidation.
