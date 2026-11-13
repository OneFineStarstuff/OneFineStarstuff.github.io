# GIEN Governance Web Application

Regulator-ready supervisory web application for the fictional GIEN planetary governance mesh and Omni-Sentinel Enterprise AI Governance Stack.

**Classification banner (every page):** TOP SECRET // SUPERVISORY EYES ONLY
**Footer (every view):** fictional-simulation disclaimer.

## Stack

React 18 + TypeScript, Vite, Tailwind CSS, React Router, Lucide React. (Recharts/D3, jsPDF, Fuse.js, OPA/Rego hooks land in M2-M4.)

## Phase 2 milestones

- **M1 (this delivery, WP-102):** static shell + briefing viewer; dossier-2026-316 as the first sealed fixture; role-based progressive disclosure (Supervisor/Regulator, Governance Engineer, Educational); systemic-risk telemetry table with GREEN/AMBER/RED bands.
- **M2:** live telemetry + evidence drawers validating against the WP-096 evidence-drawer JSON Schema + Merkle inspector.
- **M3:** compliance matrix rendered from the WP-096 OSCAL seed catalog + drills register.
- **M4:** exports (jsPDF/CSV/JSON) + promotion hardening (OPA-Rego gates per WP-091).

## Run

    npm install
    npm run dev      # Vite dev server
    npm run build    # production build (SSG-friendly static output)

## Data source of truth

All rendered values derive from the latest sealed dossier (currently GIEN-DOSSIER-2026-2026-316 fixture in src/data/). The app never contradicts the current dossier; it is a rendering layer over the daily dossier corpus.

*Fictional-simulation disclaimer: GIEN, Omni-Sentinel, CFE-1.0, Protocol SGR-028 and all indices, drills, filings, signatures, and Merkle roots shown are simulated artefacts and do not describe real systems.*
