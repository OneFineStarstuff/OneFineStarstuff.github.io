# **Omni-Sentinel: A Framework for Verifiable AI Governance**

> "We are leading the transition from *reviewing processes* to *verifying outcomes*."

Omni-Sentinel is a prototype system designed to ensure that the operational state of an AI agent ecosystem conforms to its intended governance posture. It achieves this through a continuous feedback loop of monitoring, attestation, and, when necessary, autonomous containment.

This repository contains the two core components of the Omni-Sentinel stack:

1.  **`scp` (Supervisory Control Plane):** The central decision-making and enforcement hub.
2.  **`asa` (Autonomous Supervisory Agent):** The on-the-ground monitoring and attestation agent.

---

## **Architectural Overview**

The Omni-Sentinel stack operates on a simple but powerful feedback loop:

1.  **Monitor:** The `asa` continuously performs health checks on a target AI agent. 
2.  **Alert:** If the `asa` detects a deviation from the expected state, it sends a structured alert to the `scp`.
3.  **Act:** The `scp` receives the alert and, based on a predefined risk-response matrix, executes a containment protocol.

This verifiable, automated loop provides a level of assurance that is not achievable through traditional, manual audit processes.

---

## **Getting Started**

With Docker and Docker Compose installed, you can run the entire Omni-Sentinel stack with a single command.

**Run the Stack:**

```bash
docker-compose up --build
```

This command will:
1.  Build the container images for both the `scp` and `asa` services.
2.  Start both services in a networked environment.
3.  The `asa` will begin monitoring and will eventually send an alert to the `scp`.

**Expected Output:**

You will see logs from both services in your terminal. Eventually, the `asa` will log a `HEALTH CHECK FAILED` message. Simultaneously, the `scp` will log an `ALERT RECEIVED` message, followed by the initiation of the containment protocol.

This demonstrates the complete, end-to-end flow of the Omni-Sentinel system.

---

## **The Philosophy: The Future is Verifiable**

The foundational principle of Omni-Sentinel is to move beyond traditional process-based audits and towards a future of **verifiable governance**. 

Instead of trusting that systems are compliant, we cryptographically verify their state in near real-time. This provides an unprecedented level of assurance, shifting the focus from trust to cryptographic proof.

**The future is verifiable. Let's get to work.**
