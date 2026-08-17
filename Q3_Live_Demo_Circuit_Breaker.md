# Q3 Live Demo Plan: Circuit Breaker & Automated Recovery

**Objective:** To demonstrate a sophisticated, multi-stage governance scenario where the SCP acts as a "circuit breaker," automatically mitigating a system issue and then overseeing the return to normal operations.

**Meeting:** To be performed during the `Monthly Checkpoint Call` for the second month of Q3.

**Policy Under Test:** `LATENCY_CIRCUIT_BREAK_01` (Circuit Breaker on Severe Latency Spike)

## 1. Demonstration Narrative

"Building on our previous demonstration, we will now show how the SCP can handle system resilience with more nuance than a simple halt. We will simulate a severe performance degradation—a latency spike—that threatens the stability of the application. The SCP will act as a circuit breaker: it will automatically protect the system by shunting most of the traffic, and once the issue is resolved, it will automatically restore the system to full capacity. This demonstrates a complete, automated incident management cycle."

## 2. Demonstration Steps

| Step | Action                                                                                                             | System Component(s) Involved                                  | Expected Outcome                                                                                                                                                                        |
| :--- | :----------------------------------------------------------------------------------------------------------------- | :-------------------------------------------------------------- | :-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1    | **Show Normal State:** Display the Governance Cockpit UI. The model is operating normally with p99 latency well below 100ms.          | Governance Cockpit (UI)                                         | The UI shows a green status. A traffic indicator shows **100%** of traffic being served by the model.                                                                                     |
| 2    | **Simulate Latency Spike:** Manually inject a series of telemetry messages with `"p99_latency_ms": 550` for a sustained period. | GAI-SOC Telemetry Feed                                          | The injected messages are sent to the SCP.                                                                                                                                              |
| 3    | **Observe Policy Evaluation & Circuit Break:** After 60 seconds, the OPA engine evaluates `LATENCY_CIRCUIT_BREAK_01` and returns `REDUCE_TRAFFIC_90`. | SCP Core Logic, OPA Engine                                      | The Governance Cockpit UI transitions to a yellow `WARNING` state. The traffic indicator plummets to **10%**. A log entry confirms the `REDUCE_TRAFFIC_90` command was issued.              |
| 4    | **Verify "Safe Mode":** Show that most requests are now receiving a static "system busy" response while a small fraction are still processed by the model. | Model Enclave, Governance Cockpit                             | This confirms the system is protected from the unstable model.                                                                                                                          |
| 5    | **Simulate Recovery:** Stop injecting the high-latency telemetry. The system now reports normal latency (`p99_latency_ms < 100`). | GAI-SOC Telemetry Feed                                          | The SCP continues to monitor the now-healthy telemetry.                                                                                                                               |
| 6    | **Witness Automated Recovery:** The OPA policy no longer returns a `REDUCE_TRAFFIC_90` decision. The SCP automatically lifts the restriction. | SCP Core Logic, OPA Engine                                      | The Governance Cockpit UI returns to a green `Normal` state. The traffic indicator smoothly ramps back up to **100%**. A log entry confirms the restoration of normal traffic flow. |

## 3. Success Criteria

*   The system must automatically intervene when the latency threshold is breached for the specified duration.
*   The system must automatically recover to 100% traffic when the telemetry returns to normal.
*   The Governance Cockpit UI must provide a clear, real-time visualization of the entire process (intervention and recovery).
*   All state transitions and actions must be immutably recorded in the PQC-WORM log.