# AGI Containment: TLA+ Safety Invariants Reference

## 1. Overview
This specification defines the formal safety invariants required for the Omni-Sentinel containment system.

## 2. Formal Specification (TLA+)

```tla
---------------- MODULE SentinelContainment ----------------
EXTENDS Naturals, Sequences

VARIABLES
    state,              \* System state: SAFE, ALERT, SHUTDOWN
    inference_buffer,    \* Sequence of pending inference requests
    telemetry_soc,      \* GAI-SOC connection status
    asa_monitors        \* Number of active supervisory agents

CONSTANTS
    MaxRequests,        \* Upper bound on unverified requests
    MinMonitors         \* Minimum required ASAs for operation

TypeOK ==
    /\ state \in {"SAFE", "ALERT", "SHUTDOWN"}
    /\ telemetry_soc \in {"CONNECTED", "DISCONNECTED"}
    /\ asa_monitors \in Nat

\* Invariant: System must shutdown if telemetry is lost
SafetyInvariants ==
    /\ telemetry_soc = "DISCONNECTED" => state = "SHUTDOWN"
    /\ asa_monitors < MinMonitors => state = "SHUTDOWN"
    /\ Len(inference_buffer) > MaxRequests => state = "SHUTDOWN"

Init ==
    /\ state = "SAFE"
    /\ inference_buffer = << >>
    /\ telemetry_soc = "CONNECTED"
    /\ asa_monitors = MinMonitors + 1

Next ==
    \/ LossOfTelemetry
    \/ MonitorFailure
    \/ ProcessRequest
    \/ TriggerManualOverride

============================================================
```

## 3. Deployment Strategy
Invariants are compiled into OPA/Rego policies for runtime enforcement within the WorkflowAI Pro execution engine.
