# ASI Containment Incident Response Playbook (IR-P-01)

## 1. Severity Matrix
| Level | Trigger | Action |
| :--- | :--- | :--- |
| **SEV-0** | Containment Breach (Inference detected outside TEE) | Global Cluster NMI + Key Zeroization |
| **SEV-1** | ASA Cluster Desync (> 2 monitors offline) | Stop new inference; drain current sessions |
| **SEV-2** | Semantic Drift > 20% over 5-min window | Shift to Tier-1 Capability Cap |

## 2. Recovery Protocols (Post-Zeroization)
1.  **Forensic Capture:** Dump GAI-SOC memory buffers to PQC WORM.
2.  **Invariant Analysis:** Update TLA+ specifications to cover the breach vector.
3.  **Weight Restoration:** Re-synthesize weights from jurisdictional shards ONLY after regulator zk-clearance.
