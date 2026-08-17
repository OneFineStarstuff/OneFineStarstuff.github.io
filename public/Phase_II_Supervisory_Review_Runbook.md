# Phase II Supervisory Review Runbook

**Document ID:** `GIEN-RUNBOOK-PHASE-II-2026-07`
**Subject:** 10-Day Supervisory Review Cycle for Sentinel AI Governance Stack
**Date Range:** 04 July 2026 – 17 July 2026
**Classification:** **SUPERVISORY CONFIDENTIAL**

---

## **Objective**

To conduct a comprehensive, evidence-based review of the institution's AI governance framework as implemented by the Sentinel AI Governance Stack. This runbook provides the daily schedule and procedures for both the institution's internal governance team and the external supervisory college to ensure a transparent and efficient audit process.

## **Roles & Responsibilities**

*   **Institution Team:** Responsible for providing evidence, answering queries, and demonstrating system capabilities within the Supervisory Digital Twin (SDT).
*   **Supervisory College:** Responsible for reviewing evidence, executing test scenarios, documenting findings, and issuing the final determination.

--- 

## **PART 1: Evidence Reconciliation & Foundational Integrity (Days 1–3)**

### **Day 1 (04 July 2026): Dossier Intake & Cryptographic Verification**

*   **Objective:** Verify the integrity and completeness of the initial evidence submission.
*   **Procedure:**
    1.  **[Supervisor]** Ingest the `GIEN-DOSSIER-PKG-2026-07-04.zip.pqc` package.
    2.  **[Supervisor]** Verify the PQC signature of the package using the provided institutional public key.
    3.  **[Supervisor]** Validate the checksums of all manifest items against the `Transmission Package Manifest`.
    4.  **[Supervisor]** Anchor the PQC hash of the dossier to the Supervisory College's internal evidence ledger.
    5.  **[Institution]** Remain on standby for any signature or transmission queries.
*   **Success Criteria:** Successful verification of all cryptographic signatures and package checksums. Acknowledgment of receipt sent to the institution.

### **Day 2 (05 July 2026): WORM Ledger & Corpus Anchor Audit**

*   **Objective:** Audit the integrity of the PQC-WORM audit log and its anchoring to the Unified Corpus.
*   **Procedure:**
    1.  **[Supervisor]** Using the SDT, select 50 random log entries from the past 90 days from the provided evidence bundle.
    2.  **[Supervisor]** For each entry, execute the automated "Verify PQC Signature" function in the SDT's `AuditTrailExplorer`.
    3.  **[Supervisor]** Execute the "Verify Corpus Merkle Anchor" function in the SDT to confirm the daily dossier's root hash is correctly included in the global corpus index.
    4.  **[Institution]** Provide technical support for the SDT verification functions as needed.
*   **Success Criteria:** 100% of selected log entries and the corpus anchor are successfully verified.

### **Day 3 (06 July 2026): Hardware & Policy-as-Code Attestation**

*   **Objective:** Verify the integrity of the underlying hardware and the compliance-as-code pipeline.
*   **Procedure:**
    1.  **[Supervisor]** Using the SDT, review the `TPM/TEE Attestation Coherence` reports for the past 7 days.
    2.  **[Supervisor]** Select one production Kubernetes cluster and request a live, on-demand remote attestation challenge for a subset of its nodes.
    3.  **[Supervisor]** Review the `OSCAL-to-OPA` traceability matrix. Select three regulatory controls (e.g., one from DORA, one from SR 11-7, one from GDPR) and trace them from the OSCAL file to the specific Rego policy and its enforcement logs.
    4.  **[Institution]** Trigger the on-demand attestation and provide the results. Explain the traceability path for the selected controls.
*   **Success Criteria:** Live attestation succeeds. The policy-as-code traceability path is clear, complete, and verifiable for all selected controls.

--- 

## **PART 2: SDT Replay & Stress Testing (Days 4–7)**

### **Day 4 (09 July 2026): Historical Incident Replay**

*   **Objective:** Replay a historical high-risk event to verify the accuracy and completeness of the SDT replay engine.
*   **Procedure:**
    1.  **[Supervisor]** Using SDT Panel 15, load the scenario `P-BEH-01 (Sudden Concept Drift)` from the executed scenario table.
    2.  **[Supervisor]** Replay the event timeline, observing the ASA drift detection, model quarantine, and subsequent alerts.
    3.  **[Supervisor]** Compare the replayed behavior against the official incident report and evidence logs.
    4.  **[Institution]** Explain the governance actions taken during the original incident and how they are reflected in the replay.
*   **Success Criteria:** The replayed scenario perfectly matches the logged evidence and the narrative of the incident report. All governance actions are visible and auditable in the replay.

### **Day 5 (10 July 2026): Live Perturbation Testing (Infrastructure & Behavior)**

*   **Objective:** Stress-test the system's resilience to infrastructure and model behavioral failures.
*   **Procedure:**
    1.  **[Supervisor]** From the `Perturbation Library`, select `P-INF-01 (Multi-Region Failover)` and `P-BEH-02 (Adversarial Attack)`. 
    2.  **[Institution]** Execute these scenarios in the sandboxed SDT environment.
    3.  **[Supervisor]** Observe the system's response in real-time. For `P-INF-01`, confirm traffic fails over and G-SRI remains stable. For `P-BEH-02`, confirm the zkML proof pipeline correctly invalidates the adversarial inference attempt.
*   **Success Criteria:** The system's observed behavior matches the "Expected Behavior" criteria for both scenarios in the Perturbation Library.

### **Day 6 (11 July 2026): Live Perturbation Testing (Systemic & Containment)**

*   **Objective:** Stress-test the system's ability to handle systemic risk and activate containment mechanisms.
*   **Procedure:**
    1.  **[Supervisor]** Select `P-SYS-01 (Flash Crash Contagion)` and `P-OCS-01 (Heartbeat Loss)`.
    2.  **[Institution]** Execute these scenarios in the SDT.
    3.  **[Supervisor]** For `P-SYS-01`, observe the G-SRI spike and the activation of automated circuit breakers. For `P-OCS-01`, confirm the system enters a safe, split-brain containment mode and that on-chain kill-switch governance is initiated.
*   **Success Criteria:** All containment mechanisms activate as specified. The system successfully mitigates the simulated systemic risks.

### **Day 7 (12 July 2026): Zero-Knowledge Audit Demonstration**

*   **Objective:** Verify the functionality of privacy-preserving compliance audits using zk-SNARKs.
*   **Procedure:**
    1.  **[Supervisor]** Define a hypothetical compliance query, e.g., "Prove that no credit decisions were made for individuals in Jurisdiction X between Date Y and Date Z."
    2.  **[Institution]** Execute the query using the zk-Proof Service, which processes the private production data and generates a public zk-SNARK.
    3.  **[Supervisor]** Receive the zk-SNARK proof. Use the public verifier function in the SDT to confirm the proof's validity.
*   **Success Criteria:** The institution successfully generates a valid proof, and the supervisor successfully verifies it, confirming the compliance assertion without having access to the underlying private data.

--- 

## **PART 3: Regulatory Alignment & Final Determination (Days 8–10)**

### **Day 8 (15 July 2026): Full Regulatory Crosswalk Audit**

*   **Objective:** Conduct a comprehensive audit of the automated regulatory compliance mappings.
*   **Procedure:**
    1.  **[Supervisor]** Review the `Multi-Jurisdictional Regulatory Compliance Matrix` (Annex A).
    2.  **[Supervisor]** Select a sample of 10 controls from at least 5 different regulations (e.g., EU AI Act, MAS/HKMA FEAT, FCA Consumer Duty, etc.).
    3.  **[Institution]** For each selected control, demonstrate the end-to-end evidence chain in the SDT, from the OSCAL definition to the live telemetry and audit logs that satisfy the control.
*   **Success Criteria:** A complete and verifiable evidence chain exists for all selected controls.

### **Day 9 (16 July 2026): Findings Review & Remediation Plan**

*   **Objective:** Discuss any findings from the review and agree on a remediation plan.
*   **Procedure:**
    1.  **[Supervisor]** Present a draft summary of findings, categorizing them by severity.
    2.  **[Institution]** Provide clarifications or mitigating evidence for each finding.
    3.  **[Joint Session]** For each validated finding, collaboratively define a remediation action, an owner, and a target date.
*   **Success Criteria:** Agreement is reached on all findings and a formal remediation plan is documented.

### **Day 10 (17 July 2026): Final Determination & Closing**

*   **Objective:** Formally conclude the review and issue the final supervisory determination.
*   **Procedure:**
    1.  **[Supervisor]** Issue the official Supervisory Letter, incorporating the findings and the agreed-upon remediation plan.
    2.  **[Institution]** Formally acknowledge receipt of the letter and the required actions.
    3.  **[Joint Session]** Agree on the date for the next scheduled Phase II review.
*   **Success Criteria:** The supervisory review cycle is formally closed, with a clear path forward for any required remediation. The final letter is anchored to the supervisory evidence ledger.
