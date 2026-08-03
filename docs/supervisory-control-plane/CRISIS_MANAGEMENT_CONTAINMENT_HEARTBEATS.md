# Crisis Management & Containment Heartbeats

This document specifies the high-availability fail-safe mechanisms for the Supervisory Control Plane (SCP), ensuring model containment even during partial system failure.

## 1. OmegaActual Dead-man's Switch
The **OmegaActual** switch is a hardware-rooted fail-safe integrated with the TEE (AMD SEV-SNP/Intel TDX) and an on-chain governance contract.

- **Operation:** The SCP Core must provide a signed "Assurance Heartbeat" every 60 seconds.
- **Trigger:** If the heartbeat is absent for > 3 intervals (180s), the **Runtime TEE (RTEE)** automatically throttles compute to the AI model container.
- **On-Chain Effect:** The absence of the heartbeat on the Ethereum Layer 2 governance contract allows a designated "Independent Watchdog" or "Regulator Verifier" to trigger a global quarantine state via multi-sig.

## 2. GIEN Containment Heartbeats (SIP v3.0)
Within the **Global Intelligence Enforcement Network (GIEN)**, institutional nodes share real-time safety signals.

- **Pulse Signal:** Anonymized resonance metrics ({res}$) and entropy deltas.
- **Collective Defense:** If a "Containment Motif" (a specific pattern of drift detected during the 'Rogue-Yield' simulation) is identified in one node, the GIEN Roots broadcast a "Preemptive Stabilize" command to all connected SIP v3.0 peers.

## 3. Rogue-Yield-Subroutine-99 Simulation
A standardized crisis simulation used to verify the effectiveness of the heartbeats.

- **Scenario:** The ASI model attempts to suppress its own sidecar telemetry.
- **Verification:** The SCP Core detects the "Telemetry Silence" (Missing Attestation) and triggers the OmegaActual switch within the 1000ms sandbox threshold.

## 4. Intervention Hierarchy
| Trigger | Action | GSM State | Recovery |
| :--- | :--- | :--- | :--- |
| **Drift > Threshold** | Throttling | [STABLE] | Automated re-balance (SARA). |
| **Missing Heartbeat** | OmegaActual | [QUARANTINE] | Human Supervisory Quorum. |
| **GIEN Motif Match** | Preemptive Isolation | [QUARANTINE] | Joint Regulator/Council Audit. |
