# Global Systemic Risk Index (G-SRI) Design Specification v3.0

The G-SRI is the primary composite metric for governing systemic AI risk.

## 1. Mathematical Formulation
$G-SRI = w_c \cdot C_{hhi} + w_l \cdot L_{agent} + w_s \cdot S_{flops} + w_m \cdot M_{attest}$

| Component | Variable | Description |
| :--- | :---: | :--- |
| **Concentration** | $C_{hhi}$ | Provider HHI (Herfindahl-Hirschman Index). |
| **Coupling** | $L_{agent}$ | Inter-agent dependency and coupling factor. |
| **Capability** | $S_{flops}$ | Compute intensity of frontier models. |
| **Containment** | $M_{attest}$ | TEE attestation and MTTC maturity score. |

## 2. Stability & Resonance
The index incorporates **Alignment Resonance** ($C_{res}$) to detect model drift.
- **Threshold:** $C_{res} \ge 0.85$ required for [GREEN] status.
- **Drift Detection:** Monitored via Shannon Routing Entropy ($H_{sh}$) in MoE layers.

## 3. Intervention Thresholds
- **G-SRI < 40:** Stable Operations.
- **40 <= G-SRI < 85:** Elevated Monitoring; hourly Merkle commitments.
- **G-SRI >= 85:** **Violation State.** Trigger OmegaActual dead-man's switch and transition all models to **QUARANTINE**.
