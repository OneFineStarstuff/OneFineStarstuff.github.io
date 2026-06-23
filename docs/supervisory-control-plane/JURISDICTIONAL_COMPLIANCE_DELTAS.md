# Jurisdictional Compliance Deltas & Enforcement

The Unified SCP manages multi-jurisdictional AI governance by tracking "Deltas" in regulatory rules and enforcing them through the OPA/Rego and ZK layers.

## 1. Governance via Delta Profiles
The SCP Core utilizes **Jurisdiction Profiles** to manage varying requirements:

| Rule Category | EU AI Act (Annex IV) | HKMA Fintech 2030 | MAS FEAT (Singapore) |
| :--- | :--- | :--- | :--- |
| **Fairness** | Demographic Parity Gap < 0.05 | Explainability focus. | Human-in-the-loop audit. |
| **Logging** | Detailed GPAI event logs. | Transactional traceability. | Performance drift logs. |
| **Containment** | Art. 14 Human Override. | Algorithmic stability. | Operational resilience focus. |

## 2. Rule Tracking & Versioning
- **Regulatory Bulletins:** The SCP GIEN Agent monitors signed supervisory bulletins from global regulators.
- **Policy Delta Injection:** When a rule changes (e.g., a new fairness threshold in the EU), the institution injects a **Policy Delta** into its OPA/Rego bundle.
- **Verification:** The **GSM Transition Validity Circuit** is updated to include the new public input (the hash of the updated jurisdictional profile).

## 3. Enforcement of Compliance Deltas
The **Autonomous Compliance Router (ACR)** dynamically selects the enforcement path based on the transaction's jurisdiction:
1. **Selection:** `IF location == "EU" USE profile_eu_v24.rego`.
2. **Verification:** The Decision Trace includes a metadata tag for the active profile.
3. **Audit:** The Regulator Verifier Node CLI supports a `--jurisdiction` flag to verify proofs against the specific local rules.

## 4. Conflict Resolution
In cases where jurisdictional rules conflict, the SCP defaults to the **"AI Constitution" (Global Baseline)**, which is designed to satisfy the union of the most restrictive global requirements.
