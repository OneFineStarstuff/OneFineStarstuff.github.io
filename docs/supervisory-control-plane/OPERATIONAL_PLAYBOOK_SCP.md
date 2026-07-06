# Operational Playbook: Running the Supervisory Control Plane

This playbook defines the daily DevSecOps-grade procedures for operating the Unified AI Supervisory Control Plane (SCP).

## 1. Daily Verification Layer (GAI-SOC)
- **09:00 UTC:** Automated sanity check of the PQC-WORM Audit Plane.
- **09:15 UTC:** Verification of the last 24h Merkle roots against institutional public keys.
- **10:00 UTC:** Production of the **Daily DevSecOps Telemetry Report** for the Regulator Verifier Node.
- **Continuous:** Monitoring of G-SRI thresholds and containment heartbeats.

## 2. Model Lifecycle Management (GSM Transitions)
Promotion of a model from STAGING to PROD requires:
1. **ZK-Compliance:** Successful generation and verification of the fairness/privacy proof.
2. **G-SRI Check:** Confirmation that the new deployment will not push the G-SRI above 65.
3. **Supervisory Quorum:** Dual-sig authorization from the AI Safety Officer (ASO) and Lead ethics Auditor.

## 3. Incident Response and Containment
Upon a G-SRI breach or anomaly detection:
- **Phase A (Detection):** Sidecar captures the entropy spike ({sh}$).
- **Phase B (Isolation):** SCP Core triggers GSM state transition to **QUARANTINE**.
- **Phase C (Evidence):** All decision traces from the incident window are notarized to the Merkle log with "Legal Hold" tags.
- **Phase D (Recovery):** HUMAN-ONLY restoration process following root-cause analysis and regulator briefing.

## 4. Federated Defense (GIEN Participation)
- **Gossip:** Continuous exchange of Merkle roots with peer institutions via SIP v3.0.
- **Equivocation Monitoring:** Weekly consistency audit across global roots to ensure no "split-brain" states exist in the mesh.
- **Collective Drills:** Quarterly participation in sector-wide "Red Dawn" simulations.
