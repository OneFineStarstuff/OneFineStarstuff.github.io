<title>GIEN Governance Console — Repository Implementation Gap Assessment</title>

<abstract>
Assessment date: 17 October 2026. Target: a modular, regulator-ready evidence-management and supervisory console for the fictional GIEN Phase VI-δ / Omni-Sentinel architecture. This assessment distinguishes the repository's actual application surfaces from the requested product and sets a safe implementation target. It is a source-tree review, not a production penetration test or legal opinion.
</abstract>

<content>

## 1. Executive decision

**Create the GIEN console as a separate application under `gien-console/`. Do not repurpose `frontend/`, `backend/`, or `rag-agentic-dashboard/` as though they were already the GIEN product.**

The repository contains several distinct application surfaces:

- `frontend/` — Vite + React + TypeScript application whose manifest and page names identify it as **The Turning Wheel**. It already uses React Router, Tailwind CSS, Lucide React, and Vitest, but its product and routes are unrelated to GIEN. Rebranding this project would create cross-product regression risk.
- `backend/` — the matching Turning Wheel backend and API. Its package metadata identifies the product as Turning Wheel, not a GIEN governance service.
- `next-app/` — a small Next.js application named “AGI/ASI Interface MVP.” The root page links to chat; its package manifest does not evidence the full D3/Recharts/voice/OPA/OSCAL submission console.
- `rag-agentic-dashboard/` — a separate Node/Express/WebSocket utility with many generated governance-blueprint scripts. Its package test command intentionally exits with “no test specified,” so it is not yet a verified modular console foundation.
- `src/dashboard/` — a small Python dashboard area with metrics, logging and data-fetching files; it does not constitute the requested React application.

The current `netlify.toml` builds `next-app/` and publishes `.next`. Keep that deployment unchanged while the GIEN console is built and validated independently. Changing the deployment base or mixing code from these product areas should require a separate migration decision.

## 2. Target directory layout

Create a stand-alone app with clear feature and trust boundaries:

```text
gien-console/
  index.html
  package.json
  package-lock.json
  tsconfig.json
  vite.config.ts
  tailwind.config.ts
  postcss.config.js
  src/
    main.tsx
    app/
      App.tsx
      router.tsx
      providers/
        ToastProvider.tsx
        ThemeProvider.tsx
      layout/
    features/
      dashboard/
      risk-telemetry/
      compliance-matrix/
      rag-data-audit/
      alert-history/
      prompt-architect/
      voice-commander/
      governance-stacks/
      digital-twin/
      submission-packages/
      workflow-recommendations/
    components/
      evidence/
      charts/
      tables/
      status/
    services/
      api-client.ts
      telemetry.ts
      evidence.ts
      policy.ts
    schemas/
      telemetry.ts
      evidence.ts
      exports.ts
    data/
      demo-telemetry.ts
    styles/
    test/
  tests/
  policies/
    README.md
```

Keep client components responsible for presentation and user interaction only. Authentication, tenant scoping, policy enforcement, cryptographic verification and intervention execution must be enforced by trusted service boundaries.

## 3. Dependency plan

Use a deliberate, version-pinned dependency set, with a committed lockfile and a reproducible CI build. The intended stack remains React, TypeScript, Vite, Tailwind CSS, React Router and Lucide React.

- **Charts:** Recharts for KPI and time-series charts; D3.js for custom fairness heatmaps, timelines and dependency graphs.
- **Dossier utilities:** jsPDF for controlled exports, Fuse.js for authorized metadata search, and a maintained diff viewer for comparing approved versions.
- **Voice:** browser Web Speech API as an optional input method with an accessible keyboard/touch fallback. Recognition is not authentication.
- **Policy:** OPA/Rego at the backend policy boundary. The browser must not be the final authorization point.
- **Quality:** Vitest, React Testing Library, TypeScript checks, ESLint, accessibility checks, dependency audit and a production build.

Do not install these dependencies into the Turning Wheel package to satisfy the GIEN requirement. Establish a separate `gien-console/package.json` and lockfile. Before selecting an exact diff-viewer package or upgrading major dependencies, verify maintenance status, peer dependencies, license and vulnerability advisories.

## 4. First vertical slice

Build the smallest complete slice that validates architecture end-to-end:

1. **Application shell:** role-aware navigation, route-level loading/error states, high-contrast light/dark theme and global notifications.
2. **Evidence-qualified overview:** visible environment banner; freshness timestamp; 24-hour UTC window; live/demo/replay/evidence-pending legend; KPI cards with source references and methods.
3. **Risk telemetry register:** all requested GIEN indices represented by schema-defined observations. Start with explicitly synthetic fixture records labelled **DEMONSTRATION DATA**; no invented live-looking risk state.
4. **Alert history:** severity, owner, status, UTC timestamp and immutable event ID; export tests for CSV formula injection, row authorization and JSON schema.
5. **Compliance matrix:** jurisdiction/instrument, applicability, requirement/control link, evidence reference, finding, accountable owner and next review. “Not assessed” must not map to “compliant.”
6. **Evidence bundle:** deterministic JSON manifest, schema version, record counts, digest and report timestamp. A digest does not establish truth of source records.

Only add voice, generative workflow recommendations, production stops, proof-verification claims and hardware attestation badges after the backend contracts and security tests exist.

## 5. API contracts for the first slice

Initial versioned, authenticated endpoints:

- `GET /api/v1/systems` — scoped system/model registry.
- `GET /api/v1/telemetry/metrics?from=&to=` — validated UTC window, pagination, source status and provenance.
- `GET /api/v1/alerts` — tenant/role-scoped alert list.
- `POST /api/v1/alerts/{id}/acknowledgements` — idempotent, actor-attributed change.
- `GET /api/v1/controls` — obligation/control/evidence mapping with versioned framework metadata.
- `POST /api/v1/dossiers` — freeze an authorized evidence snapshot and produce a versioned manifest.
- `POST /api/v1/interventions/stop` — reserved for a separately reviewed server-side intervention controller; do not expose a fake stop action in the demo.

Each response should include a request/correlation ID. Mutation endpoints need an idempotency key, authorization-negative tests and immutable audit records. No secrets or authorization tokens belong in Vite environment variables prefixed with `VITE_`.

## 6. Evidence semantics and governance

Every metric or control finding must identify its system scope, definition, method/version, observation time, evaluation window, source/evidence reference, freshness, limitations and reviewer. Use explicit states such as `LIVE`, `SYNTHETIC`, `REPLAY`, `EXTERNAL_ATTESTED` and `EVIDENCE_PENDING`.

Treat all GIEN index names, proposed thresholds, CFE-1.0, Protocol SGR-028 and planetary/treaty constructs as project-defined. Do not present fictional treaty controls as public legal instruments, and do not claim that a framework crosswalk establishes compliance. AAP-1 exports should atomize assurance claims and link each to its evidence, method, scope, limitation, reviewer, issue date and expiry.

## 7. Current regulatory and standards tracking

- The European Commission's current AI Act page says the Act became applicable on 2 August 2026, subject to exceptions. The current timeline lists 2 December 2027 for certain Annex III high-risk use cases and 2 August 2028 for high-risk AI embedded in regulated products following the AI Omnibus changes. Recheck applicability against the authoritative law for the specific system.
- NIST states AI RMF 1.0 is being revised and reports an April 2026 concept note for a Trustworthy AI in Critical Infrastructure Profile. Keep crosswalks versioned and avoid hardcoding the current framework as immutable.
- OSCAL 1.2.3 was released on 6 August 2026. Preserve OSCAL 1.1.2 compatibility where explicitly required by existing artifacts, but document target versions and run an explicit schema migration assessment before any upgrade.

Primary sources:
- [European Commission — AI Act timeline](https://digital-strategy.ec.europa.eu/en/policies/regulatory-framework-ai)
- [NIST — AI Risk Management Framework and revision status](https://www.nist.gov/itl/ai-risk-management-framework)
- [NIST — OSCAL release notes](https://pages.nist.gov/OSCAL/about/news/)
- [NIST — FIPS 203 / ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)
- [NIST — FIPS 204 / ML-DSA](https://csrc.nist.gov/pubs/fips/204/final)
- [NIST — FIPS 205 / SLH-DSA](https://csrc.nist.gov/pubs/fips/205/final)
- [OPA — policy management](https://www.openpolicyagent.org/docs/management-introduction)

## 8. Release gates

Do not move the console into the existing production path until all of the following hold:

- clean installation from the committed lockfile;
- successful lint, type-check, unit/integration tests and optimized build;
- security and accessibility checks on critical views;
- authorization-negative tests across roles and tenants;
- proof that CSV/JSON/PDF exports preserve provenance and do not leak unauthorized data;
- synthetic/live source separation proven through automated tests;
- failure handling and recovery evidence for data sources, APIs and audit writes;
- privacy/legal review for each in-scope processing purpose;
- a reviewed migration and rollback plan that does not replace the current Netlify target prematurely.

### Immediate next action

Keep PR #166 focused on evidence qualification and workflow repairs. Once required CI checks can produce an actionable result, create a separate implementation PR for `gien-console/` as a new Vite application. This avoids merging an unvalidated application scaffold into a documentation/CI remediation change.

</content>
