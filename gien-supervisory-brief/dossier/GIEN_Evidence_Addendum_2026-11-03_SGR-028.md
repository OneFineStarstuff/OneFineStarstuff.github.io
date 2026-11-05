<title>GIEN Evidence Addendum — Window 2026-11-02T09:00:00Z → 2026-11-03T09:00:00Z — Filing SGR-028-CFE-2026-07-001</title>
<abstract>
Evidence-oriented companion to the daily dossier for the same evaluation window: authoritative
sources collected, repository CI and deployment records, audit-log extracts, telemetry snapshot,
OSCAL assessment-results diff, and policy-simulation outputs, with prioritized recommendations and
evidence pointers. Posture ELEVATED (two watch indices easing). All GIEN data fictional/simulated.
</abstract>
<content>

## 1. Sources collected (24h)
EUR-Lex Reg. (EU) 2024/1689 consolidated text (Annex IV checked against filing pack); NIST AI RMF 1.0
and AI 600-1; NIST OSCAL 1.1.2 SSP and assessment-results models; ISO/IEC 42001:2023; BIS Basel
framework index; FIPS 203/204/205 (Aug 2024). No change to any instrument affecting this window;
SR 26-2 re-confirmed as a fictional instrument in the catalogue.

## 2. CI and deployment records
- Run `gien-ci#4821` — tsc clean, build 2.3 s, manifest guard pass, placeholder guard pass.
- Run `gien-ci#4822` — SBOM CycloneDX, 0 CRITICAL, 3 HIGH (2 accepted with expiry 2026-11-17).
- Provenance `slsa-v1` verified; image digest `sha256:8f21...c4de`; cosign keyless signature present.
- Argo CD sync `gien-prod/402` — healthy, 0 drift; rollout 5→25→100% with no SLO burn.
- Freeze-window check: 07:12 UTC deploy blocked by policy, released 10:04 UTC. Correct behaviour.

## 3. Audit log extract
`EMERGENCY_STOP_TEST` 02:15 UTC (drill, no state change); `POLICY_DENY` x91 at admission;
`KEY_ROTATION vkFMv2→vkFMv3` 86% complete; `ATTESTATION_TIMEOUT` 1 node, remediated 380 ms;
`ACCESS_REVIEW` 0 exceptions; `BREAK_GLASS` unused, 0 activations.

## 4. Telemetry snapshot
S_sys 0.19 · G-SRI 0.23 · C-SRI 0.32 (ELEVATED) · CGR-I 0.14 · CCR-I 0.11 · G-SRI-VII 0.32 ·
A-SRI 0.47 (ELEVATED) · P-SRI 0.08 · p(doom) 0.0003 [SIMULATION] · p(doom)_kernel 0.00004
[SIMULATION] · Δ_drift 0.021 · Δ_OSCAL 0.006. Both watch indices improved 0.01 on the prior window.

## 5. Evidence aggregation
Ledger INTACT, block #14,929,388, ML-DSA-65; 19.5 M entries; Merkle root anchored 08:15 UTC.
Attestation 99.3% of 8,020 nodes, coherence 0.9996. ZK: 15.2 M zkML, 12.9 M SNARK, 2.25 M STARK,
505 k SnarkPack, failure 0.0010%, verifier liveness 100%.

## 6. OSCAL diff (assessment-results)
`eu-ai-act / CD-06.2` PARTIAL → COMPLIANT (DPIA evidence pack accepted) — 1 gap retired.
`sr-26-2 / CD-02.1` PARTIAL → PARTIAL (inventory reconciliation, 2 shards outstanding, due 2026-11-06).
`dora / CD-09` COMPLIANT → COMPLIANT (evidence refreshed, no status change).
Net: 1 improvement, 0 regressions, framework totals EU AI Act 93%, SR 26-2 91%.

## 7. Policy simulation outputs
`PQC-TRANSFER-GUARD` — baseline ALLOW / proposed DENY (correct: unsigned transport rejected).
`AGENT-DELEGATION-LIMIT` — depth 9 DENY, depth 4 ALLOW; matches SR-12.
`DPIA-EVIDENCE-GATE` — missing-evidence case DENY, present-evidence ALLOW; no false blocks in 40 cases.

## 8. Findings and priorities
P1 (this week): close SR 26-2 inventory reconciliation; complete FIPS 205 rollout (96%).
P2 (30 days): push A-SRI containment under 90 s; retire the two accepted HIGH CVEs.
P3 (quarter): certify DRILL-047 lessons into playbooks; rehearse treaty-level break-glass.

## 9. Evidence pointers
`bundle.json` root `0x4a91...7c2e` (Rekor UUID recorded); WORM block #14,929,388; OSCAL bundle
`oscal-assessment-2026-11-03.json`; simulation transcript `sim-2026-11-03.jsonl`; CI run logs
`gien-ci#4821`/`#4822`.
</content>
