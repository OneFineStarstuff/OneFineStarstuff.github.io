# GIMM-Based Supervisory Review Protocol (GSRP)

**Version:** 1.0
**Objective:** To provide a structured protocol for supervisory teams to use the Governance Integrity Maturity Model (GIMM) for assessing the AI governance capabilities of regulated institutions.

---

## Phase 1: Scoping & Preparation (Pre-Examination)

1.  **Identify Target Systems:** In collaboration with the institution, identify the 1-3 most critical AI systems that will be the focus of the review. The choice should be based on systemicity, risk level (per EU AI Act), and business impact.

2.  **Initial Documentation Request (IDR):** Issue an IDR to the institution requesting, at a minimum:
    *   The institution's self-assessment against the GIMM for the target system(s).
    *   Core AI Governance Policy documents.
    *   System architecture diagrams for the target systems.
    *   NIST AI RMF / ISO 42001 alignment matrices, if available.

3.  **Review Team Composition:** Assemble a review team with expertise in:
    *   AI/ML Model Risk (SR 11-7).
    *   Cybersecurity and IT Infrastructure (DORA/NIS2).
    *   Supervisory Examination Practices.
    *   (Optional, for high-maturity exams) Cryptography or specialized SupTech.

---

## Phase 2: Examination Fieldwork (On-Site or Virtual)

*The goal of fieldwork is to validate the institution's self-assessment and gather evidence.*

### **Step 1: Kick-off Meeting**
*   **Objective:** Confirm the scope, timeline, and expectations with the institution's AI leadership.
*   **Key Question:** "Please walk us through your self-assessment. What were the key debates and where were the biggest gaps you identified?"

### **Step 2: Domain-Specific Deep Dives**
*   The review team will conduct sessions for each of the 6 GIMM domains. The line of questioning will be adapted based on the self-assessed maturity level.

*   **Example for Domain 4: Evidence & Attestation**

    *   **If Self-Assessed at GIMM Level 2 (Managed):**
        *   **Request:** "Please provide the full evidence package for the last internal audit of [Target System]."
        *   **Inquiry:** "Walk us through the process of compiling this package. How long did it take? How do you ensure the evidence is complete and wasn't tampered with?"

    *   **If Self-Assessed at GIMM Level 3 (Automated):**
        *   **Request:** "Show us the dashboard or system you use to automatically collect governance evidence. Demonstrate how an auditor would be granted access and use the system."
        *   **Inquiry:** "What events trigger evidence collection? How is the integrity of the collection pipeline itself monitored?"

    *   **If Self-Assessed at GIMM Level 4 (Assured):**
        *   **Request:** "Please generate a Governance-State Hash for the [Target System] in our presence. Separately, provide us with the 'golden hash' from your policy-as-code repository."
        *   **Action:** The supervisory team will use a government-provided, open-source tool to verify that the two hashes match.
        *   **Inquiry:** "Walk us through the process of a 'golden hash' update. What is the change control and approval process? How do you handle a hash mismatch alert? Show us the playbook."

### **Step 3: Technical Validation & Sampling**
*   This involves moving from 'talking about it' to 'proving it'.
    *   **For Level 2/3:** Select a sample of controls and ask for evidence to be generated on the spot.
    *   **For Level 4/5:** Conduct the GSA verification as described above. May also involve requesting a demonstration of TEE/vTPM attestation reports.

---

## Phase 3: Synthesis & Reporting (Post-Examination)

1.  **Maturity Scoring:** The supervisory team will convene to finalize the GIMM scores for the institution across all 6 domains. The score should be based on *validated evidence*, not just the self-assessment.

2.  **Drafting the Supervisory Letter:** The findings will be communicated in a formal supervisory letter, which will include:
    *   An executive summary of the findings.
    *   A "GIMM Scorecard" - a radar chart or table showing the self-assessed vs. supervisor-validated scores across the 6 domains.
    *   **Findings & Required Actions:** Clearly articulated weaknesses or gaps, mapped to their GIMM domain.
    *   **Recommendations:** Suggestions for improvement, especially for advancing to the next level of maturity.

3.  **Industry Benchmarking:** Anonymized and aggregated findings from GSRP reviews will be used to create industry-wide benchmarks for AI governance maturity, which can be shared publicly to help elevate the entire sector.
