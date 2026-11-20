# Changelog

## WP-116 - ANSM enforced + Dashboard fixture upgrade (2026-11-20)

- ANSM regime entry promoted advisory -> enforced in src/data/regimes.ts, recording the PROMO-R11 college adjudication (2026-11-19, 5/5, zero gate denies; catalog rev 1165 unchanged), so the compliance matrix matches the sealed dossier lineage (GIEN-DOSSIER-2026-323/324).
- Dashboard fixture upgraded to GIEN-DOSSIER-2026-321 (WP-109, PR #266, merged 041e7081): new src/data/dossier-2026-321.ts with the sealed values (frozen Merkle root 0x5b3e9a72...59c3e61, PQC signature blocks, 13 index tiles, ten control domains, drills, regimes); dossier-2026-318 retained as archive.
- Drills register updated: RAGStressTest R-2026-321 "Sable-Quorum" recorded as executed (live, CONTAINED, 2026-11-17, 1,467 replay checks bit-identical, replay discipline adopted permanently); DRILL-055 "Cobalt-Trellis" added as the planned row (<= 3 m 08 s binding target, 3 m 04 s stretch, freeze vote 2026-11-21, live week of 2026-11-23).
- About page updated to the post-M4/WP-114/WP-116 state.
- Fictional-simulation labeling preserved on every view and inside every export format.

## WP-110 - Phase 2 M4 (2026-11-16)

- Regulator-ready exports on the compliance matrix and drills register: PDF (jsPDF, lazy-loaded, with the classification banner, sealed-corpus metadata including the frozen Merkle root, wrapped table rendering, and the fictional-simulation disclaimer), CSV (RFC-style quoting with a formula-injection guard for =, +, -, @, tab prefixes), and JSON (meta + columns + records + disclaimer).
- Role-gated exports: supervisor exports carry bands and outcomes only; engineer and educational exports add the full notes from the sealed corpus, mirroring the on-screen progressive disclosure.
- New src/lib/export.ts (dataset builders + downloaders) and src/components/ExportMenu.tsx (accessible dropdown: aria-haspopup/aria-expanded, Escape-to-close, click-outside close).
- OPA-Rego promotion gate policy compliance/promotion/promotion-gates.rego (package gien.promotion, PROMO-R1..R11, deny-by-default): work-package declaration, sealed-corpus + frozen-Merkle-root linkage, WP-096 evidence digests, band invariants, the honesty model (root_recomputable must stay false), and a college-adjudication gate on advisory-to-enforced profile promotions (keeps the WP-108 ANSM profile advisory until adjudication completes). Mapping README under compliance/promotion/.
- Drills page now receives the active role so its export menu matches the compliance page.
- Fictional-simulation labeling preserved on every new view and inside every export format.

## WP-108 - Phase 2 M3 (2026-11-16)

- Compliance matrix page and table: 17 regimes rendered from the WP-096 OSCAL seed catalog (OSCAL-SEED-GIEN-WEBAPP-1.0.0) with OSCAL 1.1.2 validation status and OPA-Rego gate status per regime, catalog rev 1165 steady-state; values from the sealed GIEN-DOSSIER-2026-320 corpus. ANSM enters as the first domain-specific profile beyond finance (advisory), backed by compliance/ansm/ (deny-by-default Rego policy + mapping README).
- Supervisory Digital Twin drills register page and table: DRILL-050..054 with convergence vs. binding/stretch targets and replay determinism; new RAGStressTest register class added (adversarial retrieval drills, bit-identical replay required).
- Shared band/threshold module: webapp/src/data/bands.json is the single machine-readable threshold source; src/lib/bands.ts provides typed computeBand() over it; telemetry/gsri_monitor.py consumes the same JSON so the webapp, the Python monitors, and the dossier template share one definition.
- Dashboard links to the compliance matrix and drills register; About page updated to the M3 state; role-based progressive disclosure preserved (supervisor sees bands/outcomes; engineer and educational see notes).
- Fictional-simulation labeling preserved on every new view.

## WP-106 - Phase 2 M2 (2026-11-14)

- Evidence drawers on every systemic-risk index tile, payloads conforming to the WP-096 evidence-drawer JSON Schema (webapp/phase1/evidence-drawer.schema.json); in-app contract validation with honest PASS/deviation reporting.
- Evidence payloads for the 12 contract indices from the sealed GIEN-DOSSIER-2026-318 values; the evidence quote age tile intentionally has no drawer (its index id is outside the WP-096 enum).
- Merkle inspector: in-browser SHA-384 leaf recomputation and binary-tree root derivation, with an honest verdict - the static fixture carries the sealed archive root but not the WORM leaf set, so the root comparison reports MISMATCH-by-design until ledger access exists (verification.root_recomputable = false in every payload).
- Fixture upgraded to GIEN-DOSSIER-2026-318 (WP-104, PR #258, merged 1cce4695); dossier-2026-316 retained as archive.
- Role-based progressive disclosure preserved: drawer digests unsealed only for the Governance Engineer role; Escape-to-close and aria labeling on the drawer.

## WP-102 - Phase 2 M1 (2026-11-12)

- Static shell: router, classification banner, theme toggle (light/dark), toast-free minimal notification strip, footer disclaimer on every view.
- BriefingViewer renders the three-tag dossier corpus: GIEN-DOSSIER-2026-316 fixture (sealed values: Merkle root, PQC signature blocks, indices, domains, drills, regimes).
- Role-based progressive disclosure: Supervisor/Regulator (summary + bands), Governance Engineer (full telemetry + hashes), Educational (definitions inline).
- Systemic-risk telemetry table with GREEN/AMBER/RED band badges (12 indices + evidence quote age).
- Vite dev server reliability: pinned plugin versions; host flag documented for containerized dev; build verified target es2020.
