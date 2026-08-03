# Capacity-aware Governance Roadmap (Phases 1a–4)

This roadmap staggers infrastructure risk and surfaces governance value early.

## Phase 1a — Docs & Contracts
- Unified data contract (risks, events, dependencies) in JSON/YAML
- Readiness checklist to gate infra choices

## Phase 1b — Mocked Dynamic Risk + Light Telemetry
- /api/risk/scores mock endpoint; pulse indicators on /risk
- Periodic polling first; swap to streaming later

## Phase 1c — Governance Workflow Bootstrapping
- /api/governance/events (create/list) with hash-chained audit
- Bind ritual markers to workflows; RBAC skeleton

## Phase 2 — Drift Pilot + Milestone Triggers
- Baseline profiles + tunable thresholds
- Milestone triggers for non-linear development

## Phase 3 — Enterprise Integration
- Auth/RBAC across /risk and APIs
- OpenTelemetry + product analytics
- Data residency/masking controls

## Phase 4 — Adaptive Oversight
- Competency-linked access
- Incident “Decisive mode” with authority paths
- Governance charter updates & retrospectives
