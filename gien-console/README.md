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

The repository currently does not commit the generated `package-lock.json`. The validation workflow creates a lockfile when one is absent, installs from the resolved lock, runs the production dependency audit, unit tests, TypeScript check and production build, then uploads the exact lockfile as a workflow artifact. The repository's branch rules rejected the workflow's attempted direct commit because the branch requires signed commits, successful deployment checks and changes through the protected-branch process.

For reproducibility, review the [validated lockfile artifact](https://github.com/OneFineStarstuff/OneFineStarstuff.github.io/actions/runs/39097480486/artifacts/12125625413), add it at `gien-console/package-lock.json`, and commit it through the repository's approved signed-commit workflow. Once committed, CI uses that exact file with `npm ci` rather than regenerating it.

Local evaluation commands:

```bash
npm ci
npm run typecheck
npm test
npm run build
npm run dev
```

**Lockfile remains a merge gate until the signed commit is in the PR and the committed file is validated.** This draft is not production-ready.

## Versioning

This is an additive, separately scoped application. The intended semantic-version classification for this feature is minor (`+semver: minor`); it is not a release or deployment approval. The console remains a draft until the reviewed lockfile is committed and the quality/security checks are cleared.

## Security and evidence boundaries

- All telemetry in this slice is synthetic; no live data connector is configured.
- The UI does not authorize regulatory decisions or make a legal-conformity determination.
- Client-side CSV/JSON export is a demonstration utility and is not an immutable or server-audited export.
- No emergency-stop action is exposed until an authenticated backend intervention controller can verify runtime acknowledgement.
- OPA/Rego enforcement, server-side role checks, authenticated evidence storage, and externally verified TEE/zk-proof evidence are future integration gates, not implemented capabilities.
