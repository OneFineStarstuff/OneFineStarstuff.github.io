# Governance State Machine (GSM) Logic Design

The GSM is a formal model of the AI lifecycle, ensuring that models only operate in sanctioned environments.

## 1. States
- **DEV (0):** Experimental development; minimal telemetry required.
- **STAGING (1):** High-fidelity testing; mandatory ZK-Compliance generation.
- **PROD (2):** Live institutional workload; active PQC-WORM logging and G-SRI monitoring.
- **QUARANTINE (3):** Immediate containment; compute throttled; no actuation allowed.

## 2. Valid Transitions
| From | To | Condition |
| :--- | :--- | :--- |
| **DEV** | **STAGING** | Unit tests pass + Security Zone B initialized. |
| **STAGING** | **PROD** | ZK-Proof verified + G-SRI < 65 + Supervisory Quorum. |
| **PROD** | **QUARANTINE** | **AUTONOMOUS:** G-SRI >= 85 OR Anomaly Detected OR Token Revoked. |
| **QUARANTINE** | **DEV** | **MANUAL:** Full root-cause audit + Board Approval. |

## 3. Implementation
The transition logic is implemented in `GSM_Transition_Circuit.circom` to provide mathematical proof of state adherence to external regulators.
