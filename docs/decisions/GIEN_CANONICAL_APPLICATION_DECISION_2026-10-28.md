# Canonical GIEN application and first-slice decision

**Decision date:** 2026-10-28  
**Decision status:** Engineering working decision; production promotion remains blocked.

## Decision

Use `gien-platform/` as the canonical **engineering target for the first evidence-integrity slice**. It is already the main-branch React 18 + TypeScript + Vite + Tailwind + React Router application and includes risk telemetry, compliance matrix, RAG audit, role/layer presentation, and dossier export routes. The first slice hardens those routes rather than introducing another parallel dashboard.

This decision does **not** reassign the current deployment target. The repository's existing configured target remains `next-app/` pending a separate verified promotion decision. Do not change host configuration, production routes, DNS, or deployment defaults as part of this patch.

## Repository boundaries

- `gien-platform/`: engineering target for immediate P0 evidence-contract and UI-semantics work.
- `next-app/`: existing configured deployment target; live deployment health and feature equivalence must be verified separately.
- `gien-console/` / draft PR #169: separate prototype candidate. Do not merge or port in parallel until dependency, route, export and ownership differences are reviewed.
- `frontend/` and `backend/`: not assumed to be the GIEN product backend without explicit repository evidence and an ownership decision.

## First slice in branch `gien/evidence-contract-p0`

- Add typed evidence provenance and assessment states to risk-index and framework fixture records.
- Mark all 12 seeded risk records as synthetic and `NOT_ASSESSED`.
- Remove unsupported coverage counts, OSCAL-presence booleans, OPA totals and assessment dates from all 18 framework records.
- Display a global warning explaining synthetic fixtures, missing live evidence, presentation-only roles and simulation-only emergency stop.
- Replace stale daily-window dates with a UTC cutoff helper ending at the most recent completed 09:00 UTC.
- Make risk and compliance CSV exports carry status and provenance fields; guard CSV text cells against spreadsheet formula injection.
- Make dossier exports state their evidence limitations and unsigned/browser-local nature; escape exported markup.
- Add regression checks for reporting-window calculation and unsupported fixture-assessment states.

## Explicitly not delivered yet

The React frontend does not provide a verified authenticated metric service,
OIDC/SSO enforcement, tenant-aware server authorization, or durable
server-side audit event persistence. It also lacks a runtime intervention
controller, signed export manifests, and independent export verification.
This branch must not be described as a completed end-to-end authenticated
vertical slice; those systems remain backend integration gates.

## Promotion gates

1. CI build and evidence-contract tests pass on the branch.
2. A backend proves a source-authenticated metric read with evidence ID, source/version, exact UTC window and freshness.
3. The API authorizes the resource and writes a durable audit event before confirming privileged mutations.
4. Export manifest binds the report to the evidence snapshot and schema version; a verifier checks digest/signature and source lineage.
5. An integration test proves authenticated read → lineage display → durable audit event → signed/verified export.
6. Current deployment target and rollback procedure are verified before production promotion.

Until these gates pass, operational risk ratings, legal applicability and compliance outcomes remain `NOT ASSESSED`.
