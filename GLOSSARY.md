# GLOSSARY.md

GIEN / Omni-Sentinel program glossary (B7, WP-114). Published at repo root; cited by the daily dossier footer.

- **GIEN-DOSSIER-YYYY-DDD** — daily supervisory dossier naming, numbered by day of year; evaluation window ends 09:00 UTC.
- **Window Merkle root** — one frozen SHA-384 Merkle root per window, byte-identical across every occurrence in the dossier and its exports.
- **Hash format** — 0x-prefixed, exactly 64 lowercase hex characters, audited per window (26 artefacts + root + 3 signature blocks).
- **PQC** — NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA-87 primary), Falcon-1024 (high-throughput), FIPS 205 (SLH-DSA backstop).
- **WP-nnn** — work-package numbering; one WP per PR; neutral PR numbers are never touched.
- **SGR-028 / SGR-030 / SGR-031** — supervisory filing protocol lineage; SGR-031 sealed 2026-11-17 with zero verification queries.
- **CFE-1.0** — constitutional framework governing TLA+ invariant verification for epochs 2026-2035 and 2035-2100+.
- **Delta_drift** — Autonomous Supervisory Agent drift, in sigma; 0.0 is centered.
- **Delta_OSCAL** — OSCAL operational-catalog diff (controls added/removed, rev change); emitted by scripts/oscal_diff.mjs.
- **DI floor** — Disparate Impact Ratio >= 0.800 fair-lending floor (FCRA/ECOA), zkML-attested.
- **Bands** — GREEN/AMBER/RED bands from the single machine-readable source webapp/src/data/bands.json, consumed by TS, Python monitors, and tests.
- **EL-1..EL-5** — alert escalation levels; GREEN plus four escalation tiers.
- **SDT Panels 13-15** — Supervisory Digital Twin stress-test panels; replay determinism must be 100% bit-identical.
- **RAGStressTest** — adversarial retrieval drill class (prompt-injection, poisoned-corpus, stale-index) under permanently adopted bit-identical replay discipline.
- **PROMO-R1..R11** — deny-by-default OPA-Rego promotion gates (compliance/promotion/promotion-gates.rego).
- **root_recomputable=false** — webapp evidence honesty model: the static corpus carries the sealed archive root but not the WORM leaf set.
- **Omega-GAR** — long-horizon governance phase (2081-2100+); indices CESI, UCSI, UCI, CDS, Infinity Pillar.

*Fictional governance simulation; all terms describe simulated artefacts.*
