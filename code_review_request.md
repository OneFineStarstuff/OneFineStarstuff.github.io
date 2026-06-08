# Code Review Request: MAS FEAT and HKMA Ethics Remediation

## Changes
1. **MAS FEAT Compliance:**
   - Created `next-app/lib/ai/fairness.ts` to calculate Demographic Parity metrics.
   - Updated `next-app/lib/ai/orchestrator.ts` to integrate fairness checks for depth-layer (MoE expert) responses.
2. **HKMA Ethics Compliance:**
   - Created `next-app/lib/ai/interpretability.ts` to generate Contextual Attribution Envelopes (CAE).
   - Integrated CAE generation into the `Orchestrator`.
3. **Maturity Uplift:**
   - Updated `next-app/data/maturity.json` to include 'Ethics & Fairness Compliance' with a score of 3.
4. **Verification:**
   - Created vitest unit tests in `next-app/__tests__/governance_remediation.test.ts`.
   - Verified that all governance checks pass using `tools/run_gsifi_governance_checks.py`.

Please review the implementation and provide feedback.
