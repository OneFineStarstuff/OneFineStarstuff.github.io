# **Enterprise AI Governance Artifact 4 of 4**

**Document ID:** `OS-ARTIFACT-EAG-004-V1.0`
**Classification:** Internal // Technical Specification

# **Model Health & AI Safety Risk Categorization Framework**

---

## **1.0 Purpose: Proactive, Differentiated Governance**

This framework provides a standardized, enterprise-wide methodology for assessing and categorizing the risk of AI/ML models *before* they are deployed. Its purpose is twofold:

1.  To ensure that the level of governance, oversight, and automated containment applied to a model is directly proportional to its potential risk.
2.  To operationalize our "Safety First" and "Compliance by Design" principles by embedding risk assessment directly into the MLOps lifecycle.

This is not a one-size-fits-all approach. It is a differentiated framework that allows for rapid innovation on low-risk applications while imposing rigorous, verifiable controls on high-risk ones.

---

## **2.0 Risk Dimensions**

Every new model or major version update must be assessed along four key dimensions:

*   **1. Impact of Decision (ID):** The potential consequence of a single erroneous decision by the model.
    *   **ID-4 (Catastrophic):** Direct threat to human life or safety; severe, irreversible environmental damage.
    *   **ID-3 (Severe):** Major financial loss; critical infrastructure failure; severe reputational damage.
    *   **ID-2 (Moderate):** Moderate financial loss; regulatory non-compliance; negative customer impact.
    *   **ID-1 (Low):** Minor internal process disruption; minimal financial or reputational impact.

*   **2. Level of Autonomy (LA):** The degree of human oversight in the model's decision-making process.
    *   **LA-4 (Fully Autonomous):** Operates without any human-in-the-loop for decision execution.
    *   **LA-3 (Human on the Loop):** Can act autonomously, but a human has the ability to intervene and override.
    *   **LA-2 (Human in the Loop):** Provides recommendations, but a human must approve every action.
    *   **LA-1 (Human-Led):** Provides analysis or information to support a human-led decision.

*   **3. Data & PII Sensitivity (DS):** The sensitivity of the data the model processes.
    *   **DS-3 (Highly Sensitive):** Processes special categories of data (GDPR Article 9), financial account data, or is subject to strict data residency laws.
    *   **DS-2 (PII):** Processes Personal Identifiable Information (PII).
    *   **DS-1 (Non-PII):** Processes only anonymized, aggregated, or public data.

*   **4. Operational Scope (OS):** The scale and context of the model's deployment.
    *   **OS-3 (External / Public-Facing):** Accessible by or directly impacts customers or the public.
    *   **OS-2 (Enterprise-Wide):** Used across multiple business units internally.
    *   **OS-1 (Limited / Departmental):** Used by a single team or for a specific, limited internal use case.

---

## **3.0 Risk Tier Calculation & Governance Requirements**

The final Risk Tier is determined by the highest rating on any dimension. The assigned tier dictates the minimum required governance controls.

| Tier        | Determining Factor                                    | Omni-Sentinel Integration                  | Minimum Containment Level (from `DEVSECOPS_CONTAINMENT_RISK_ANALYSIS.md`) | AIGC Approval |
| ----------- | ----------------------------------------------------- | ------------------------------------------ | ----------------------------------------------------------------------- | ------------- |
| **T1: CRITICAL** | `ID-4` or `LA-4` in a `OS-3` context                | **Mandatory:** Full ZKP & ASA Monitoring   | `CL-3` (Terminate) or `CL-4` (Lockdown)                                   | Required      |
| **T2: HIGH**    | `ID-3` or `LA-3` in a `OS-2/3` context or `DS-3`      | **Mandatory:** Full ZKP & ASA Monitoring   | `CL-2` (Freeze)                                                         | Required      |
| **T3: MEDIUM**  | `ID-2` or `DS-2`                                      | **Mandatory:** Policy Violation Monitoring | `CL-1` (Isolate)                                                        | Not Required  |
| **T4: LOW**     | All dimensions are `*-1`                               | Optional / Logging Only                    | None required by default                                                | Not Required  |

---

## **4.0 Process Integration**

1.  **Assessment:** The Risk Tier assessment must be completed within the MLOps pipeline as a mandatory quality gate before a model can be promoted to a staging environment.
2.  **Registration:** The model, its version, and its final T1-T4 Risk Tier are immutably registered in the central Model Registry.
3.  **Automated Configuration:** The Omni-Sentinel Supervisory Control Plane (SCP) automatically ingests this registration data. It then configures and enforces the corresponding required governance controls (ZKP attestation, ASA monitoring, containment protocols) for that specific model version.

---

## **5.0 Conclusion**

This framework closes the loop between policy and execution. It provides a clear, consistent, and auditable process for translating abstract risk into concrete, automated, and verifiable technical controls. By integrating risk assessment directly into the development lifecycle, we ensure that safety and governance are not obstacles to innovation, but enablers of it. **The future of AI is not just intelligent; it is verifiably safe.**
