# GIEN Governance Web Application

Regulator-ready supervisory web application for the fictional GIEN planetary governance mesh and Omni-Sentinel Enterprise AI Governance Stack.

**Classification banner (every page):** TOP SECRET // SUPERVISORY EYES ONLY
**Footer (every view):** fictional-simulation disclaimer.

## Stack

React 18 + TypeScript, Vite, Tailwind CSS, React Router, Lucide React, Web Crypto (SHA-384), jsPDF (lazy-loaded for PDF exports). OPA/Rego gate hooks live under compliance/ (evaluated in CI, not in the browser).

## Phase 2 milestones

- **M1 (WP-102):** static shell + briefing viewer; dossier-2026-316 as the first sealed fixture; role-based progressive disclosure (Supervisor/Regulator, Governance Engineer, Educational); systemic-risk telemetry table with GREEN/AMBER/RED bands.
- **M2 (WP-106):** evidence drawers on every index tile validating against the WP-096 evidence-drawer JSON Schema (webapp/phase1/evidence-drawer.schema.json) + Merkle inspector (in-browser SHA-384 leaf recomputation, honest root-recomputability semantics); fixture upgraded to dossier-2026-318.
- **M3 (WP-108):** compliance matrix from the WP-096 OSCAL seed catalog (17 regimes, OSCAL/OPA status, catalog rev 1165) + Supervisory Digital Twin drills register; shared band/threshold module (src/data/bands.json + src/lib/bands.ts, consumed by telemetry/gsri_monitor.py); ANSM domain profile under compliance/ansm/.
- **M4 (WP-110):** regulator-ready exports (PDF via jsPDF / CSV / JSON, role-gated) on the compliance matrix and drills register + OPA-Rego promotion gates (compliance/promotion/promotion-gates.rego, PROMO-R1..R11) per the WP-091 evidence contract.
- **CI trust + knowledge backbone (WP-114):** determinism lint (no Math.random) with crypto helpers, Playwright watermark and bands-bound p(doom) invariants, reproducible build gate, accessible Sparkline, checksum-pinned OPA bundle script (fail-closed), OSCAL diff focus, GLOSSARY.md, CONSTITUTION.md, compliance crosswalk + schema + validator; see docs/ci-trust-backbone.md.
- **WP-116 (this delivery):** ANSM profile promoted advisory -> enforced in the compliance matrix (PROMO-R11 college adjudication, 2026-11-19, 5/5, zero denies); Dashboard fixture upgraded to dossier-2026-321 (dossier-2026-318 retained as archive); drills register updated (R-2026-321 executed/CONTAINED; DRILL-055 Cobalt-Trellis planned, freeze vote 2026-11-21, live week of 2026-11-23).

## Run

    npm install
    npm run dev      # Vite dev server
    npm run build    # production build (SSG-friendly static output)

## Exports (M4)

The compliance matrix and drills register pages carry an Export menu (PDF / CSV / JSON). Every export is a rendering of the sealed dossier corpus, carries the sealed Merkle root and the fictional-simulation disclaimer, and is not itself evidence. Supervisor exports contain bands and outcomes only; engineer and educational exports add the full notes, mirroring the on-screen role gating. CSV fields with formula-injection prefixes (=, +, -, @, tab) are guarded.

## Promotion gates (M4)

compliance/promotion/promotion-gates.rego (package gien.promotion) is a deny-by-default OPA policy evaluated against a change descriptor: work-package declaration, sealed-corpus + frozen-Merkle-root linkage, WP-096 evidence digests, band invariants, the honesty model (root_recomputable must remain false), and a college-adjudication requirement for advisory-to-enforced profile promotions. The ANSM profile cleared that gate on 2026-11-19 (PROMO-R11, 5/5) and is now enforced. See compliance/promotion/README.md for the input contract and opa eval usage.

## Data source of truth

All rendered values derive from the latest sealed dossier lineage (currently the GIEN-DOSSIER-2026-321 Dashboard fixture in src/data/; dossier-2026-318 and dossier-2026-316 are retained as archives; the compliance matrix, drills register, and briefing corpus carry the sealed dossier-316 -> -321 values with the ANSM profile enforced). The app never contradicts the current dossier; it is a rendering layer over the daily dossier corpus.

## Shared band thresholds

webapp/src/data/bands.json is the single machine-readable threshold source. The webapp consumes it through src/lib/bands.ts (typed computeBand); the Python telemetry monitor (telemetry/gsri_monitor.py) consumes the same file, so the webapp, the monitors, and the dossier template share one definition.

## Evidence honesty model

Evidence payloads validate against the WP-096 schema in-app. The per-artefact WORM leaf digests are not part of the static daily corpus, so every payload declares root_recomputable: false and the Merkle inspector reports a root MISMATCH as the expected static-demo outcome rather than claiming verification it cannot perform. The promotion gate (PROMO-R9) enforces the same honesty invariant in CI.

*Fictional-simulation disclaimer: GIEN, Omni-Sentinel, CFE-1.0, Protocol SGR-028 and all indices, drills, filings, signatures, and Merkle roots shown are simulated artefacts and do not describe real systems.*
