# Global Systemic Risk Index (G-SRI) Design Specification

The G-SRI is the primary composite metric used by the Supervisory Control Plane (SCP) to monitor and govern systemic AI risk within G-SIFI environments.

## 1. Mathematical Components
The G-SRI is a weighted sum of four primary risk vectors ($):

8568G-SRI = \sum (w_i \cdot V_i)8568

| Vector ($) | Parameter | Description |
| :--- | :---: | :--- |
| **Concentration** | {hhi}$ | Herfindahl-Hirschman Index of decision volume across model providers. |
| **Coupling** | {agent}$ | Degree of cross-institutional agent interoperability and dependency. |
| **Capability** | {flops}$ | Compute intensity and capability score of active frontier models. |
| **Containment** | {attest}$ | Maturity of hardware-rooted attestation and MTTC performance. |

## 2. Thresholds and Intervention Logic
The SCP Core monitors the G-SRI in real-time via the PQC-WORM telemetry stream.

- **Level 1 (G-SRI < 40): [STABLE]** Normal operation.
- **Level 2 (40 <= G-SRI < 65): [ELEVATED]** Trigger automatic GAI-SOC alert; increase STH anchoring frequency to hourly.
- **Level 3 (65 <= G-SRI < 85): [CRITICAL]** Block new model promotions (GSM DEV -> STAGING); require Board Risk Committee review.
- **Level 4 (G-SRI >= 85): [VIOLATION]** Trigger **OmegaActual Kill-Switch**; transition all production models to **QUARANTINE** state within < 1000ms.

## 3. Cognitive Resonance ({res}$)
A sub-metric of G-SRI that monitors model alignment drift.
- **Target:** {res} \ge 0.85$.
- **Trigger:** If resonance drops below 0.70 for > 5 minutes, the **Autonomous Compliance Router (ACR)** throttles ingress tokens ({token}$) to stabilize the routing layer.

## 4. Federated Aggregation
Via **SIP v3.0**, institutions share an anonymized, ZK-proven G-SRI component. This allows the Global Intelligence Enforcement Network (GIEN) to calculate a **Market-Wide Systemic Risk Index** without exposing proprietary institutional data.
