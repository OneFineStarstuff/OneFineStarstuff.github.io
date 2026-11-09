# Governance Webapp — Phase 1 Foundation (Briefing Template, Evidence Model, Research Pack)

**Work package:** WP-096 · **Status:** Phase 1 complete · **Design authority:** WP-083 Edition 3 (ratified) · **CI foundation:** WP-087 P1–P2 (delivered, green)

Phase 1 of the regulator-ready AI governance and systemic-risk supervisory web application, per the design brief of 2026-11-07. Phase 1 delivers the non-code foundation: the evidence model that makes every displayed number traceable to a sealed artifact, the daily briefing template, and the regulatory research pack with a machine-readable crosswalk seed.

## Contents

| File | Role |
| --- | --- |
| `01_evidence_model.md` | Evidence chain pattern, 12-index band table, evidence-drawer contract |
| `02_briefing_template.md` | The \<title>/\<abstract>/\<content> briefing schema and labelling standard |
| `03_regulatory_research_pack.md` | Six real-regime one-pagers + the fictional treaty layer |
| `evidence-drawer.schema.json` | JSON Schema (draft 2020-12) for the evidence-drawer payload |
| `oscal_crosswalk_seed.json` | OSCAL 1.1.2-flavored control seed with regime mappings |

## Success test

A cold reader can reconstruct any briefing number's provenance from this pack alone: index → band → contributing OSCAL control → sealed artifact → Merkle root. CI validation of the JSON files is a drop-in for the existing validate-governance-artifacts gate.

## Next phase

Phase 2 (M1–M4 per the design brief): static shell + briefing viewer; telemetry + evidence drawers + Merkle inspector; compliance matrix + drills; exports + promotion hardening. M1 builds directly against this foundation and the delivered Governance Telemetry API (WP-089 / PR #216) with contract verification and promotion gates (WP-091 / PR #226).

---
*Fictional simulation notice. The GIEN mesh, its indices, drills, filings, and Merkle roots are simulated artefacts. Real-framework summaries are informational and are not legal advice.*
