# Advanced Rehearsal Artifacts: Regulatory AI Governance Demos

This document contains advanced planning tools to ensure the highest level of readiness for high-stakes regulatory demonstrations of the Supervisory Control Plane (SCP).

## 1. Imagined Regulator Perspective (Role-Play)
To prepare, the team must inhabit the mindset of the regulatory technical auditor:

- **What they care about:** "Can this institution hide a critical model failure or a policy violation from us?"
- **Their suspicion:** "The ZK proof looks valid, but is the *witness* data being fed into the circuit honest?"
- **The verification path:** "I want to see the PQC signature on the raw event envelope in the enclave, then see how it matches the public Merkle root."
- **The "Gotcha" question:** "If I revoke the policy token at 2:00 PM, exactly how many milliseconds until the model stops responding?"

## 2. Regulator Journey Map (90-Minute Demo)
| Time | Phase | Regulator Experience | Team Objective |
| :--- | :--- | :--- | :--- |
| 0-15m | **Context** | "Why are we here? Does this map to my regulations?" | Anchor the demo in the Compliance Mapping Matrix. |
| 15-45m | **Operations** | "Is this real? Show me the live telemetry and enclaves." | Demonstrate the SCP Core + GSM in the dev cluster. |
| 45-75m | **Verification** | "The math part. How do I verify this independently?" | Live Verifier Node CLI session and ZK proof check. |
| 75-90m | **Assurance** | "I feel confident. The evidence is solid and I have my packet." | Ceremonial handoff and confirmation of follow-up. |

## 3. Rehearsal Scorecard (Internal)
| Category | Criteria | Score (1-5) | Observer Notes |
| :--- | :--- | :---: | :--- |
| **Technical** | Tool latency under 500ms? | | |
| **Narrative** | Explicit mapping to EU AI Act? | | |
| **Verification** | Verifier Node CLI clear and legible? | | |
| **Drills** | Fallback recording ready and synced? | | |
| **Engagement** | FAQ answered without hesitation? | | |
