# OneFineStarstuff.github.io — GIEN Governance Mesh & Omni-Sentinel Stack

The governance and delivery repository for the **GIEN** planetary governance mesh (Phase VI-δ → Epoch I–II → Ω-GAR) and the **Omni-Sentinel** enterprise AI governance stack (Sentinel v2.4, Omni-Sentinel v4.0, Unified Supervisory Control Plane v3.0).

> **Fictional simulation notice.** GIEN and Omni-Sentinel are a governance simulation. All telemetry, drills, filings, and indices in this corpus are simulated data.

## What lives here

- **Daily supervisory dossiers** — one `GIEN_Daily_Dossier_YYYY-MM-DD.md` per day at repo root, in the canonical 10-section supervisory package format (header block + dashboard checklist, corpus index, perturbations and drills, PQC signature blocks, submission readiness certificate, transmission manifest). Latest: [GIEN_Daily_Dossier_2026-11-04.md](GIEN_Daily_Dossier_2026-11-04.md)
- **Governance platform SPA** — `gien-platform/`, a runnable regulator-ready supervisory dashboard (React 18 + TypeScript + Vite; CI-verified via the path-scoped `gien-platform-ci.yml` workflow)
- **Schema-first Governance Telemetry API** — `api/` with an OpenAPI 3.1 schema of record and a drift gate (WP-087 control C1)
- **Governance artifacts** — OSCAL 1.1.2 catalogs, OPA/Rego release gates, TLA+ containment specs, Circom G-SRI circuits, and the PQC WORM logger
- **Architecture and implementation guidance** — webapp design editions (WP-064 → WP-083), the regulator-defensible CI/CD pipeline design (WP-087), and the feature implementation plan (WP-072)

## Delivery convention

Work ships as numbered work packages (`WP-nnn`) via PRs from the `genspark_ai_developer` branch into `main`; the prior day's PR is merged before the next dispatch. Daily dossiers are additionally exported to Drive (docx + pdf) with a Notion closing summary.

## Compliance crosswalk

EU AI Act · NIST AI RMF 1.0 / AI 600-1 · ISO/IEC 42001 · Basel III/IV · SR 11-7 · SR 26-2 · DORA · NIS2 · GDPR · MAS/HKMA FEAT · FCA SMCR & Consumer Duty · HKMA Fintech 2030 AI² · SEC Rule 17a-4 · FCRA/ECOA · ICGC/GASO · Interstellar AI Governance Accord · Galactic Treaty Framework (the last two, plus CFE-1.0 and Protocol SGR-028, are fictional treaty instruments of the simulation).

## License

MIT — see [LICENSE](LICENSE).
