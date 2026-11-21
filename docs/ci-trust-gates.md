# CI trust gates (WP-119, wave P0 of the EU AI Act / DORA compliance plan)

Wakes the dormant WP-114 backbone scripts into enforceable CI gates. The plan of record is the
2026-11-21 compliance-mapping report (canvas: ci-trust-compliance-plan).

## Gate table

| Gate | Method | Maps to (EU AI Act) | Maps to (DORA) | Owner | Exit criteria |
| --- | --- | --- | --- | --- | --- |
| determinism | scripts/determinism_scan.sh + lint/eslint.gien.cjs (A1) | Art. 15 (robustness) | Art. 6 + CDR (EU) 2024/1774 change management | governance-engineers | 0 hits of Math.random in webapp/src |
| crosswalk | scripts/validate_crosswalk.mjs (B7) | Art. 9/17 evidence | Art. 6 framework documentation | governance-engineers | CROSSWALK VALID; yaml+ajv pinned majors in workflow |
| oscal-diff | scripts/oscal_diff.mjs (A7) | Annex IV documentation currency | Art. 6(4)-(5) monitoring | governance-engineers | exit 0; exit 2 (drift) keeps the gate red |
| reproducible-build | scripts/reproducible-build.sh (A4) | Art. 15 (cybersecurity) | CDR (EU) 2024/1774 change management | governance-engineers | prints REPRODUCIBLE: <hash>; two builds hash-identical |
| e2e trust invariants | tests/e2e/watermark.spec.ts (A2), pdoom.spec.ts (A3) | Art. 50 transparency (live since 2026-08-02) | Art. 10 protection | webapp-lane | banner + disclaimer on every view; p(doom) bound to bands.json |
| opa-pin-proposal | workflow_dispatch verifier (A6 companion) | supply-chain integrity (both) | CDR (EU) 2024/1774 cryptography/change control | security + governance-engineers | pin file filled only via quorum-approved PR; unverified bytes never execute |

## Quorum rules (Honor the Quorum)

- The OPA pin file and any gate threshold change require a PR with TWO approvals (engineering quorum).
- The workflow_dispatch pin job verifies the proposed checksum against the official OPA download and approves nothing itself; humans approve the PR.
- Action references in workflows are pinned to immutable SHAs by the neutral PR #218 lane before production use.

## Status

- WP-114 delivered the scripts fail-closed; WP-119 wires them. The Vercel deploy/deploy-netlify failures remain owned by the neutral PR #166 CI-repair workstream.
- Fictional governance simulation artefact; the gate wiring itself is real YAML and shell, the governance universe is simulated.
