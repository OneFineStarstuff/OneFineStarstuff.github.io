# SCP Compliance Mapping Matrix

This document maps the Unified AI Supervisory Control Plane (SCP) architectural components to key regulatory requirements across EU AI Act, Basel SR 11-7, and DORA.

| SCP Component | Capability | EU AI Act (Art. 11, 12, 53) | Basel SR 11-7 / SR 26-2 | DORA (ICT Resilience) |
| :--- | :--- | :--- | :--- | :--- |
| **SCP Core + GSM** | Formally verified model state transitions. | **Art. 12:** Automatic logging of events. | **SR 11-7:** Model lifecycle governance & change control. | **Art. 6:** ICT Risk Management Framework. |
| **ZK Prover Pipeline** | Privacy-preserving compliance proofs. | **Art. 11:** Technical documentation for high-risk systems. | **SR 11-7:** Independent validation of model logic. | **Art. 17:** ICT Incident-related reporting. |
| **PQC-WORM Audit Plane** | Indelible, post-quantum audit trail. | **Art. 12:** Traceability and forensic accountability. | **SR 26-2:** Operational risk management & evidence integrity. | **Art. 12:** Backup policies & recovery procedures. |
| **GIEN / SIP v3.0** | Federated risk gossip and collective defense. | **Art. 53:** GPAI coordination and information sharing. | **SR 26-2:** Third-party risk & systemic contagion monitoring. | **Art. 31:** Information sharing arrangements. |
| **Regulator Verifier Node** | Independent verification without data access. | **Annex IV:** Regulator access to documentation and logs. | **SR 11-7:** External audit and supervisory review support. | **Art. 24:** Digital operational resilience testing. |
| **OmegaActual Kill-Switch** | Hardware-rooted autonomous containment. | **Art. 14:** Human oversight and technical override. | **SR 26-2:** Incident response & rapid containment. | **Art. 11:** Response and recovery planning. |

## Detailed Mapping Notes

### EU AI Act Alignment
- **Art. 12 (Logging):** The PQC-WORM Audit Plane ensures that all Decision Traces are indelible and searchable by regulators via the Verifier Node.
- **GPAI Obligations:** SIP v3.0 enables the required transparency for systemic-risk GPAI models without leaking proprietary weights.

### Basel SR 11-7 / SR 26-2 Alignment
- **Independent Validation:** ZK proofs allow third-party auditors to verify that the model's "inner loop" logic (e.g., fairness constraints) matches the approved specification.
- **Model Risk Governance:** The GSM transition logic ensures that no model can be promoted to "PROD" without a verified ZK proof of compliance.

### DORA (Digital Operational Resilience Act)
- **ICT Resilience:** The TEE-based SCP Core provides a high-availability, tamper-proof command-and-control system for critical financial AI functions.
- **Incident Reporting:** The Merkle log provides a cryptographically verifiable timeline for root-cause analysis during mandatory ICT incident reporting.
