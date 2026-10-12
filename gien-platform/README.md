# GIEN Governance Platform

A React 18 + TypeScript + Vite prototype for the fictional GIEN planetary / multiversal governance mesh. The app is isolated in \`gien-platform/\` so the repository's existing root site is not replaced.

## Run locally

~~~bash
cd gien-platform
npm install
npm run dev
~~~

## Production build

~~~bash
npm run test:evidence
npm run build
npm run smoke
npm run preview
~~~

## Included workspaces

- \`/dashboard\` — daily supervisory brief, operational accordion, transmission checklist and filing metadata.
- \`/risk-indices\` — 12 thresholded demo indicators, SVG sparklines / radar / node graph, risk filters, agent inventory and detail drawer.
- \`/compliance\` — 20-framework simulated control matrix, domain / framework / status / risk filters, gap toggles, cell detail drawer, Rego sample and JSON export.
- \`/governance-stacks\` — Sentinel v2.4, Omni-Sentinel v4.0, SCP v3.0, mesh sketch, cycle timeline, compute-mode toggle and domain drill-down.
- \`/control-domains\` — searchable CD-01 through CD-10 catalogue and detail drawers.
- \`/cryptographic-integrity\` — illustrative PQC ledger, algorithm inventory, zkML / proof pipeline, TEE / TPM attestation and paginated audit samples.
- \`/digital-twin\` — selectable panels 13–15, stress assumptions, sample replay results and drill register.
- \`/scenario-planner\` — six scenario types, configurable inputs, stateful local runs, scenario history and text report export.
- \`/constitutional\` — 24 fictional invariants, TLA+ teaching snippets, treaty catalogue and epoch timeline.
- `/evidence-validation` — source-to-claim queue, structural source checks, freshness gating, manual reviewer attestations, findings, and JSON evidence export.
- \`/submission-packages\` — multi-step package setup, section selection, preview, JSON export, print styling and simulated transmission / archive dialogs.
- \`/long-horizon\` — Phase VI-δ through XIII, Ω-GAR, beacon planning, codex prerequisites, EPITAPH / INVOCATION documents and Infinity Pillars.

## Architecture

- React 18, TypeScript, React Router, Tailwind CSS, Lucide React and Vite.
- Shared \`GovernanceContext\` carries role selection, phase, evaluation window and illustrative alert count.
- Reusable components include status badges, metric cards, expandable sections, drawers, progress bars, SVG sparklines, radar charts, node graphs, timelines, code blocks and tagged documents.
- No external APIs are called. All scenario calculations, values, timestamps and hash strings are local simulation fixtures.

## Supervisory and technical documentation

The following files are normative design references for this prototype, not evidence of a deployed supervisory service:

- [Daily Supervisory Dossier — 12 October 2026](docs/daily-supervisory-dossier-2026-10-12.md): evidence-qualified daily report, control domains, risk indices, Panels 13–15, submission/sealing requirements, and Phase XI/XII forward view.
- [Technical Architecture and 2026–2035 Roadmap](docs/technical-architecture-roadmap-2026-2035.md): zero-trust boundaries, TEE attestation, PQC/WORM, zkML pipeline, StaR-MoE controls, TLA+ invariants and DevSecOps release gates.
- [Regulatory Crosswalk and OSCAL 1.1.2 Assessment Design](docs/regulatory-crosswalk-oscal-opa.md): 25-framework mapping starter, applicability/status semantics, control evidence model, OSCAL structure and OPA/Rego example.
- [Phase XI–XII and Ω-GAR Forward Dossier](docs/phase-xi-xii-omega-gar-forward-dossier.md): future-phase governance, Eternal Corpus, independent beacon design, cryptographic lineage, invariant controls and successor-epoch gates.
- [Enterprise AI Safety and Governance Roadmap, 2026–2100+](docs/enterprise-ai-safety-and-governance-roadmap-2026-2100.md): enterprise RAG safety, alignment and adversarial evaluation, attestation and cryptographic evidence controls, Phase XV pause/fabrication prohibition, Guardian milestone evidence gates, OpenAI Platform integration
  considerations, and long-horizon
  succession architecture.
- [Supervisory Briefing Platform Reference Architecture, 2026–2100+](docs/supervisory-briefing-platform-reference-architecture-2026-2100.md): daily report cadence, risk indicator contracts, GIEN controls, attestation and PQC evidence, RAG/AGI safety, IASOS API, OSCAL/OPA mappings, DRILL-042–047, Guardian readiness, UX modules, release gates and
  Phase XV pause.
- [GIEN Governance Research Plan and Supervisory Reference Architecture — October 2026](docs/governance-research-plan-and-reference-architecture-2026-10.md): official regulatory/standards register, audience and framework recommendation, React/Vite decision, reference architecture, RAG/CCaaS safety, telemetry contracts, OSCAL/OPA, PQC evidence,
  APIs, accessible visualizations
  and implementation roadmap.
- [OpenAI Platform Integration Research — October 2026](docs/openai-platform-integration-research-2026-10.md): Responses API, Structured Outputs, tool calling/MCP, server-side TypeScript architecture, secrets and GitHub Actions workload identity federation, data-retention boundaries, human approval, evals lifecycle, and phased release acceptance
  criteria.

## Evidence and deployment boundaries

 **This application is a prototype, not a certified supervisory system.** Demonstration values are not live telemetry, empirically calibrated risk estimates, legal determinations, compliance findings, regulatory approvals, or independent assurance. Displayed hashes are fabricated strings, PQC signatures are not generated or verified, and
attestation / OSCAL / TLA+ verification
has not been executed.

The package export is an untrusted demo artefact. The “simulate transmission” and “simulate archive” controls only explain hypothetical protocol steps; they do not contact endpoints or write to immutable storage. Browser print is provided for a print / PDF workflow, and the JSON export is machine-readable demonstration data.

Before operational use, connect authenticated authoritative data sources, define data provenance and freshness, implement schema validation and cryptographic verification, enforce server-side authorization, add independent testing, and document applicable legal and supervisory review. Never ship credentials or private keys in client-side code.

## CI

 The GitHub Actions workflow `.github/workflows/gien-platform-ci.yml` runs on Node.js 24, installs dependencies, runs the deterministic no-network evidence regression suite, performs the TypeScript/Vite production build, and smoke-tests the production preview. The smoke test checks built JavaScript/CSS assets, expected application markers, and SPA
route fallback including
`/evidence-validation`. A passing job must be observed in Actions; workflow configuration alone is not proof of runtime correctness.


## Additional integration research

- [Multi-Platform Integration Research (October 2026)](docs/multi-platform-integration-research-2026-10.md) — provider capabilities, API/partner gates, trust boundaries, phased rollout, and acceptance criteria.


- [GIEN Master Deep Research: AI Governance, Safety, and Systemic Risk — October 2026](docs/master-deep-research-ai-governance-systemic-risk-2026-10.md) — current safety research, regulatory status, financial systemic risk, CD-01–CD-10 mapping, evidence integrity, metric validation and phased rollout.
- [Thinking and Deep Research Governance — October 2026](docs/thinking-and-deep-research-governance-2026-10.md) — reasoning versus deep-research workflows, model lifecycle, source-to-claim evidence, tool/data controls, evaluation framework and release gates. The 12 October refresh documents the older Deep Research model-ID shutdown notice, the
  Evals platform's published 31
  October read-only / 30 November shutdown dates, MCP approvals, citation validation, and NIST critical-infrastructure concept-note status.
- [Deep Multi-Platform Integration Research (October 2026)](docs/deep-integration-research-2026-10.md) — control-plane architecture and provider-specific security, event handling, evidence provenance, acceptance criteria, and rollout plan.
- [Focused GitHub Integration Research (October 2026)](docs/GitHub-integration-research-2026-10.md) — GitHub App permissions, Actions hardening, OIDC, evidence provenance, and acceptance criteria.
- [OpenAI Evals Migration Inventory and Cutover Plan — 12 October 2026](docs/openai-evals-migration-inventory-2026-10-12.md) — export register, owner assignments, the 31 October read-only and 30 November 2026 shutdown milestones, Promptfoo parity checks, and explicit inventory status boundaries.
- [Structured Evals Migration Inventory Template](data/openai-evals-migration-inventory.template.json) — fillable machine-readable inventory; the record template defaults to NOT_INVENTORIED; instantiate one record per category from verified evidence.
- [Source-to-Claim Validation Workspace](src/pages/EvidenceValidationPage.tsx) and [deterministic validator](src/evidence/claim-validation.mjs) — prototype UI, evidence contract, manual-review gate, and regression tests in `scripts/claim-validation.test.mjs`.
