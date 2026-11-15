# GIEN Governance Web Application

Regulator-ready supervisory web application for the fictional GIEN planetary governance mesh and Omni-Sentinel Enterprise AI Governance Stack.

**Classification banner (every page):** TOP SECRET // SUPERVISORY EYES ONLY
**Footer (every view):** fictional-simulation disclaimer.

## Stack

React 18 + TypeScript, Vite, Tailwind CSS, React Router, Lucide React, Web Crypto (SHA-384). (Recharts/D3, jsPDF, Fuse.js, OPA/Rego hooks land in M3-M4.)

## Phase 2 milestones

- **M1 (WP-102):** static shell + briefing viewer; dossier-2026-316 as the first sealed fixture; role-based progressive disclosure (Supervisor/Regulator, Governance Engineer, Educational); systemic-risk telemetry table with GREEN/AMBER/RED bands.
- **M2 (this delivery, WP-106):** evidence drawers on every index tile validating against the WP-096 evidence-drawer JSON Schema (webapp/phase1/evidence-drawer.schema.json) + Merkle inspector (in-browser SHA-384 leaf recomputation, honest root-recomputability semantics); fixture upgraded to dossier-2026-318.
- **M3:** compliance matrix rendered from the WP-096 OSCAL seed catalog + drills register.
- **M4:** exports (jsPDF/CSV/JSON) + promotion hardening (OPA-Rego gates per WP-091).

## Run

    npm install
    npm run dev      # Vite dev server
    npm run build    # production build (SSG-friendly static output)

## Data source of truth

All rendered values derive from the latest sealed dossier (currently the GIEN-DOSSIER-2026-318 fixture in src/data/; the dossier-2026-316 fixture is retained as archive). The app never contradicts the current dossier; it is a rendering layer over the daily dossier corpus.

## Evidence honesty model

Evidence payloads validate against the WP-096 schema in-app. The per-artefact WORM leaf digests are not part of the static daily corpus, so every payload declares root_recomputable: false and the Merkle inspector reports a root MISMATCH as the expected static-demo outcome rather than claiming verification it cannot perform.

*Fictional-simulation disclaimer: GIEN, Omni-Sentinel, CFE-1.0, Protocol SGR-028 and all indices, drills, filings, signatures, and Merkle roots shown are simulated artefacts and do not describe real systems.*
