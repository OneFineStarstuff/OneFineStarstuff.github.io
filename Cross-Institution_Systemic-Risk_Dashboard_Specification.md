# Cross-Institution Systemic-Risk Dashboard Specification

**Document ID:** `CIS-DASH-SPEC-2026-06-27-v1.0`
**Status:** Finalized for Development
**Parent Documents:** `WSR-SGS-2026-W26`, `GIES-2026-06-27-v1.0`
**Classification:** Supervisory Confidential

---

## **1. Overview & Purpose**

This document specifies the design and functional requirements for the Cross-Institution Systemic-Risk (CIS) Dashboard. The CIS Dashboard is the primary supervisory interface for monitoring the health, stability, and compliance of the entire federated Omni-Sentinel Mesh. It provides a real-time, aggregated view of the Governance State Attestations and systemic risk telemetry from all participating G-SIFI and Fortune 500 institutions.

The dashboard's design directly implements **GIES Invariant 4.2 (Supervisory Equivalence)**, ensuring that supervisors are interacting with a verifiable, high-fidelity representation of the live ecosystem, not a delayed or approximated summary.

---

## **2. Dashboard Modules & Layout**

The dashboard will consist of a main overview screen with several drill-down modules.

### **Module 1: Global Systemic Risk Index (G-SRI) & GIEN Threat Level**

*   **Visualization:** A prominent, color-coded dial/gauge at the top center of the screen displaying the real-time, mesh-wide G-SRI. A smaller, adjacent indicator will show the current GIEN Threat Level.
*   **Data Source:** Aggregated G-SRI telemetry from all participating nodes' Supervisory Digital Twins (SDTs).
*   **Functionality:**
    *   Displays current G-SRI score (e.g., 4.98).
    *   Color-coded based on severity (Green/Amber/Red).
    *   Shows 24-hour and 7-day trend lines.
    *   Drill-down capability to view the G-SRI contribution from each institution.

### **Module 2: Federated Node Health & Compliance Status**

*   **Visualization:** A geographic map displaying the status of all federated nodes (participating institutions). Each node is represented by a dot.
*   **Data Source:** The master Governance State Attestation from each node's SDT.
*   **Functionality:**
    *   **Green Dot:** All invariants hold. Node is fully compliant and attested.
    *   **Amber Dot:** A non-critical invariant has a warning (e.g., latency approaching threshold), or a policy update is pending.
    *   **Red Dot:** A critical invariant has been breached (triggering automated containment), or the node has failed to provide a valid attestation.
    *   Hovering over a dot shows the institution's name, current G-SRI, and the timestamp of the last successful attestation.
    *   Clicking a dot drills down into that institution's specific supervisory view.

### **Module 3: Live Governance Incident Exchange Network (GIEN) Feed**

*   **Visualization:** A scrolling, real-time feed, similar to a news ticker.
*   **Data Source:** The live SIP v3.0 broadcast channel from the GIEN Hub.
*   **Functionality:**
    *   Displays all broadcasted threat signals in real-time.
    *   Each entry includes a timestamp, threat type (e.g., `Novel_Adversarial_Attack_Type_A`), severity, and the number of nodes that have acknowledged the signal.
    *   Entries are color-coded by severity.
    *   Clicking an entry provides a detailed, anonymized summary of the threat signature.

### **Module 4: Constitutional Invariant Adherence Matrix**

*   **Visualization:** A simple, clean matrix (table).
*   **Data Source:** Aggregated compliance data from all SDTs.
*   **Functionality:**
    *   Rows represent the 8 core GIES constitutional invariants.
    *   Columns represent key timeframes (Live, 24h, 7d, 30d).
    *   Each cell contains a percentage indicating the adherence rate for that invariant across the entire mesh for that timeframe (should always be 100%).
    *   Any cell dropping below 100% would immediately turn red and trigger a high-priority alert, as this would indicate a fundamental failure of the ecosystem's core principles.

### **Module 5: Regulatory Compliance Crosswalk (Automated)**

*   **Visualization:** A selectable, filterable table.
*   **Data Source:** The automated OSCAL-to-evidence mappings from all SDTs.
*   **Functionality:**
    *   Allows a supervisor to select a specific regulation (e.g., DORA, EU AI Act).
    *   The table then populates with the relevant articles/controls from that regulation.
    *   Each row shows the control, its current compliance status (✅ Pass / ❌ Fail), and a link to the latest aggregated evidence package (e.g., a zip file of all relevant proofs and log hashes from all institutions for that control).
    *   This module is the primary tool for conducting automated, continuous, cross-institutional audits.
