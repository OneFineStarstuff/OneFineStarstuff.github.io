# Changelog

## WP-106 — Phase 2 M2 (2026-11-14)

- Evidence drawers on every systemic-risk index tile, payloads conforming to the WP-096 evidence-drawer JSON Schema (webapp/phase1/evidence-drawer.schema.json); in-app contract validation with honest PASS/deviation reporting.
- Evidence payloads for the 12 contract indices from the sealed GIEN-DOSSIER-2026-318 values; the evidence quote age tile intentionally has no drawer (its index id is outside the WP-096 enum).
- Merkle inspector: in-browser SHA-384 leaf recomputation and binary-tree root derivation, with an honest verdict — the static fixture carries the sealed archive root but not the WORM leaf set, so the root comparison reports MISMATCH-by-design until ledger access exists (verification.root_recomputable = false in every payload).
- Fixture upgraded to GIEN-DOSSIER-2026-318 (WP-104, PR #258, merged 1cce4695); dossier-2026-316 retained as archive.
- Role-based progressive disclosure preserved: drawer digests unsealed only for the Governance Engineer role; Escape-to-close and aria labeling on the drawer.

## WP-102 — Phase 2 M1 (2026-11-12)

- Static shell: router, classification banner, theme toggle (light/dark), toast-free minimal notification strip, footer disclaimer on every view.
- BriefingViewer renders the three-tag dossier corpus: GIEN-DOSSIER-2026-316 fixture (sealed values: Merkle root, PQC signature blocks, indices, domains, drills, regimes).
- Role-based progressive disclosure: Supervisor/Regulator (summary + bands), Governance Engineer (full telemetry + hashes), Educational (definitions inline).
- Systemic-risk telemetry table with GREEN/AMBER/RED band badges (12 indices + evidence quote age).
- Vite dev server reliability: pinned plugin versions; host flag documented for containerized dev; build verified target es2020.
