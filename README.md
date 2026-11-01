# GIEN / Omni-Sentinel AI Governance Project

<abstract>
Architecture and evidence-management resources for a fictional GIEN Phase VI-δ supervisory mesh and Omni-Sentinel governance stack. The repository is a software and documentation project; its existence and passing repository checks do not establish production deployment, regulatory compliance, independent assurance, or live system safety.
</abstract>

<content>

## Project status — 16 October 2026

**Evidence-qualified / implementation in progress.** The architecture blueprint is documented, but this repository snapshot does not establish connected live telemetry, verified hardware attestation, valid production zkML proofs, independently verified post-quantum audit ledgers, a complete operational GIEN dashboard, regulatory approval, or independent assurance.

Historical reports in this repository contain aspirational or illustrative claims. Do not treat their risk values, “verified” labels, containment statements, compliance percentages, audit seals, or economic projections as current facts unless each claim is linked to source evidence, scope, time window, method, reviewer, and verification result.
The daily brief records unavailable evidence as **EVIDENCE-PENDING**; it does not fill gaps with invented values.

## Core documents

- [GIEN Governance Webapp Implementation Blueprint (2026–2035)](docs/specifications/GIEN_GOVERNANCE_WEBAPP_IMPLEMENTATION_BLUEPRINT_2026_2035.md) — proposed system architecture, React module boundaries, APIs, evidence contract, privacy and security controls, RAG lineage, exports, emergency-stop semantics, and delivery gates.
- [Repository Implementation Gap Assessment — 17 October 2026](docs/specifications/GIEN_REPOSITORY_IMPLEMENTATION_GAP_ASSESSMENT_2026-10-17.md) — explains why the existing Turning Wheel and Next.js surfaces should remain isolated, and defines a dedicated `gien-console/` implementation path.
- [GIEN Daily Supervisory Brief — 16 October 2026](docs/reports/GIEN_DAILY_SUPERVISORY_BRIEF_2026-10-16.md) — evidence-qualified status for the 24-hour evaluation window ending at 09:00 UTC and a separate repository CI addendum.
- [Dashboard Security Review](next-app/DASHBOARD_SECURITY_REVIEW.md) — current review material for the existing application.
- [GitHub Actions Startup-Failure Triage — 17 October 2026](docs/operations/GITHUB_ACTIONS_STARTUP_FAILURE_TRIAGE_2026-10-17.md) — run IDs, verified observations, remaining uncertainty, and a support-ready incident summary.

## Implementation reality

The configured Netlify build uses `next-app` and its `next build` command. That application currently uses Next.js, React, and Zustand; its package manifest does **not** show the full requested Vite/D3/Recharts/voice/export/OPA-integrated interface.
The Vite-based stack in the blueprint is therefore a target architecture, not a claim about the currently deployed runtime. Do not switch the production build base or migrate frameworks without a separately reviewed implementation and tested deployment plan.

## Evidence status contract

Every displayed observation should have a source status:

| Status | Meaning |
|---|---|
| `LIVE` | Retrieved from a named, authenticated source within the stated freshness window |
| `SYNTHETIC` | Generated example or test data; show **DEMONSTRATION DATA** prominently |
| `REPLAY` | Reproduced from a named scenario or frozen evidence set |
| `EXTERNAL_ATTESTED` | A named external verifier or authority provided verifiable evidence; identify its scope |
| `EVIDENCE_PENDING` | Missing, stale, inaccessible, or unverified evidence; do not infer a zero value or healthy state |

For each claim, retain the system/model scope, definition, unit, exact UTC window, source reference, data freshness, method/version, limitation, policy version, reviewer and review time. A hash proves consistency of bytes against a commitment; it does not prove that the source was truthful or that a control is effective.

## Governance and legal posture

This is a decision-support and evidence-management project, not a regulator endorsement. Regulatory applicability must be assessed by jurisdiction, business activity, system role, risk classification, and effective date.
A control-to-framework crosswalk is a mapping aid, not proof of legal compliance. GIEN-specific labels, indices, CFE-1.0, Protocol SGR-028, ICGC/GASO, Interstellar AI Governance Accord, and Galactic Treaty Framework are project-defined or fictional unless separately grounded in an authoritative source.

Important external references:
- [European Commission — AI Act and application timeline](https://digital-strategy.ec.europa.eu/en/policies/regulatory-framework-ai)
- [NIST AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework)
- [NIST AI 600-1 — Generative AI Profile](https://doi.org/10.6028/NIST.AI.600-1)
- [ISO/IEC 42001:2023](https://www.iso.org/standard/42001.html)
- [NIST FIPS 203 — ML-KEM key encapsulation](https://csrc.nist.gov/pubs/fips/203/final)
- [NIST FIPS 204 — ML-DSA signatures](https://csrc.nist.gov/pubs/fips/204/final)
- [NIST FIPS 205 — SLH-DSA signatures](https://csrc.nist.gov/pubs/fips/205/final)
- [NIST OSCAL v1.1.2 reference](https://pages.nist.gov/OSCAL-Reference/models/v1.1.2/)
- [Open Policy Agent — policy management and decision logs](https://www.openpolicyagent.org/docs/management-introduction)
- [SEC — electronic recordkeeping requirements under Rule 17a-4](https://www.sec.gov/investment/amendments-electronic-recordkeeping-requirements-broker-dealers)

## CI interpretation

Repository CI checks validate only the code, documentation, or artifacts covered by each workflow. On the latest observed main-branch snapshot described in the 16 October dossier, several checks passed, while Governance Docs Lint and Python CI reported `startup_failure` with no jobs exposed by the API.
Those results do not reveal the root cause and must not be reported as successful tests or as code defects without further evidence.

## Dependency security follow-up

One observed `npm ci` run for `next-app/` reported 24 npm audit findings (4 moderate, 17 high and 3 critical). This is dependency-tree advisory output, not proof that every finding is production-reachable or exploitable.
[Issue #168](https://github.com/OneFineStarstuff/OneFineStarstuff.github.io/issues/168) tracks collection of the full JSON audit report, production-versus-development dependency classification and reviewed remediation. Do not apply `npm audit fix --force` without a compatibility assessment.

</content>
