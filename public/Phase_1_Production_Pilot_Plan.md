# Phase 1 Production Pilot Plan: SCP Live Monitoring

**Document ID:** `PILOT-P1-PLAN-2026-09-25`
**Status:** Proposed for Supervisory & Internal Review
**Classification:** Confidential

---

## **1. Executive Summary**

Following the successful completion of all sandbox validation objectives, this document outlines the plan for the first live production pilot of the Supervisory Control Plane (SCP). The pilot's primary goal is to demonstrate the SCP's value and performance in a real-world environment with zero operational risk.

The SCP will be deployed in a **monitor-and-log** capacity against a non-critical, high-volume production AI model. It will observe, record, and generate all governance evidence as if it were in full control, but it will not perform any automated containment actions. This allows us to gather invaluable baseline data and prove the system's real-world efficacy before moving to an active enforcement model.

---

## **2. Pilot Objectives**

1.  **Validate Real-World Performance:** Measure the latency and computational overhead of the SCP on a production-scale workload.
2.  **Gather Baseline Governance Data:** Collect 3 months of continuous, verifiable governance data from a live production AI system.
3.  **Test Alerting and Reporting:** Confirm that all alerting, reporting, and dashboarding functions operate as expected with a real data feed.
4.  **Build Supervisory Confidence:** Provide the supervisory team with read-only access to the live SCP dashboard, fostering familiarity and trust in the system.

---

## **3. Scope & Target System**

*   **Pilot System:** The Supervisory Control Plane (SCP) v2.4
*   **Target AI Model:** **Customer Service Intent Classification Model (CS-Intent v3.1)**
    *   **Function:** A deep learning model that routes incoming customer chat messages to the correct support department (e.g., Billing, Technical Support, General Inquiry).
    *   **Risk Profile:** Low. An incorrect classification results in a minor delay and is corrected by a human agent. The model does not process PII and has no financial or compliance impact.
    *   **Volume:** High. Approximately 1.2 million inferences per day, providing a rich source of data.

---

## **4. Safety Protocol: Monitor-and-Log Mode**

This is the core safety feature of the pilot. The SCP will be fully integrated with the CS-Intent model, but its enforcement capabilities will be disabled.

*   **MONITOR:** The Constitutional Guardrail Runtime Monitor will receive all data and `MoEComplianceProof`s from the model.
*   **LOG:** The monitor will validate the proofs and log the results to the immutable WORM storage. It will generate all `PolicyDecisionLog-v1` and `GovernanceStateAttestation-v1` evidence objects.
*   **ALERT:** If the monitor detects a policy violation or a compliance proof failure, it will:
    1.  Log the event with a `severity: WARNING` tag.
    2.  Update the SCP dashboard with a **YELLOW** status for the component.
    3.  Send an alert to the engineering team.
*   **DO NOT CONTAIN:** The monitor **will not** block the transaction or take any action to reroute traffic. The production system will continue to operate without interruption.

This architecture ensures **zero impact on the production environment** while still providing a complete, verifiable record of all governance events.

---

## **5. Timeline & Milestones**

*   **Phase 1 (October 2026): Deployment & Calibration**
    *   **Week 1:** Deploy SCP in monitor-and-log mode to the production environment.
    *   **Weeks 2-4:** Calibrate alerting thresholds and confirm data integrity. Resolve any performance bottlenecks.

*   **Phase 2 (November 2026 - January 2027): Baseline Data Collection**
    *   The SCP will run continuously for three full months.
    *   Monthly checkpoint calls will be held to review the live data and compare it to the sandbox results.

*   **Phase 3 (February 2027): Pilot Review & Decision**
    *   A comprehensive report will be generated summarizing the pilot's findings.
    *   A formal review will be held with all stakeholders to make a go/no-go decision on proceeding to a **Phase 2 Pilot (Active Containment)**.

---

## **6. Success Criteria**

The pilot will be considered a success if the following criteria are met:

1.  **Zero Production Incidents:** The pilot causes no downtime or performance degradation in the target CS-Intent model.
2.  **High-Fidelity Evidence:** The SCP successfully logs a complete and verifiable governance record for >99.99% of all transactions.
3.  **Accurate Alerting:** The SCP correctly identifies and alerts on all intentionally introduced test anomalies, with a false positive rate of less than 0.01%.
4.  **Positive Supervisory Feedback:** The supervisory team confirms the utility of the live dashboard and the clarity of the generated reports.
