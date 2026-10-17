# GIEN Governance Console — First Vertical Slice

This is an isolated Vite + React + TypeScript implementation for the fictional GIEN supervisory console. It is intentionally separate from the existing `frontend/`, `backend/` and `next-app/` projects.

## Included in this first slice

- Evidence-qualified dashboard with persistent `DEMONSTRATION DATA` labeling.
- Risk-index register and a Recharts time-series visualization.
- D3-rendered fairness heatmap using synthetic example data.
- Compliance matrix that keeps `NOT ASSESSED` distinct from a compliance conclusion.
- Alert history with JSON/CSV export and CSV-formula escaping.
- RAG provenance and submission-package readiness views with evidence gaps exposed.
- Theme toggle, route navigation, toast notification provider and responsive layouts.
- Unit tests for telemetry classification and export-safety helpers.

## Run locally

This initial draft does not yet commit a generated npm lockfile. Use `npm install` to resolve dependencies for local evaluation, followed by:

```bash
npm run typecheck
npm test
npm run build
npm run dev
```

**Lockfile is a merge gate:** generate and review `package-lock.json` from this manifest, then switch CI to `npm ci` before considering a merge or deployment. This draft is not production-ready.

## Security and evidence boundaries

- All telemetry in this slice is synthetic; no live data connector is configured.
- The UI does not authorize regulatory decisions or make a legal-conformity determination.
- Client-side CSV/JSON export is a demonstration utility and is not an immutable or server-audited export.
- No emergency-stop action is exposed until an authenticated backend intervention controller can verify runtime acknowledgement.
- OPA/Rego enforcement, server-side role checks, authenticated evidence storage, and externally verified TEE/zk-proof evidence are future integration gates, not implemented capabilities.
