# SCP Policy-as-Code Library v1

**Document ID:** SCP-POL-LIB-V1.0
**Project Phase:** 3 - Advanced Policy & Governance Proving

## 1. Overview

This document contains the first official library of advanced governance policies for the Supervisory Control Plane (SCP). These policies are written in Rego, the language for the Open Policy Agent (OPA), and represent a significant step up from the simple threshold-based rules used in previous pilot phases.

These policies will be used in the upcoming Phase 3 live fire drills to demonstrate the SCP's ability to perform nuanced, graduated interventions.

--- 

## 2. Policy: `govern_latency_spike`

*   **ID:** `GLS-001`
*   **Description:** This policy monitors the real-time prediction latency of a model. If the 95th percentile latency over a 5-minute window exceeds a dynamic threshold (set at 2x the model's baseline latency), it indicates a potential performance degradation or resource contention issue.
*   **Graduated Intervention:** Instead of shutting the model down, the policy prescribes a `RATE_LIMIT` action to reduce the load on the model, allowing it to recover gracefully while still serving requests at a reduced capacity.
*   **Rego Code:**

```rego
package scp.governance

default allow = true

# Prescribe a RATE_LIMIT action if p95 latency is 2x the baseline
decision = "RATE_LIMIT" {
    input.metrics.p95_latency_5m > input.model.baseline_latency_ms * 2
}
```

--- 

## 3. Policy: `govern_ambiguous_confidence`

*   **ID:** `GAC-001`
*   **Description:** This policy is designed for high-value transaction models (e.g., credit origination, large payment processing). It triggers when the model's confidence score for a transaction falls within a pre-defined "grey area" (e.g., between 60% and 75% confidence) for a transaction above a certain monetary value.
*   **Graduated Intervention:** The policy prescribes a `REDIRECT_TO_HUMAN_REVIEW` action. The specific transaction is flagged and routed to a human expert for final approval, while the model continues to process other, more clear-cut transactions without interruption.
*   **Rego Code:**

```rego
package scp.governance

default allow = true

# Redirect to human review for high-value, low-confidence transactions
decision = "REDIRECT_TO_HUMAN_REVIEW" {
    input.prediction.confidence >= 0.60
    input.prediction.confidence < 0.75
    input.features.transaction_value_usd > 1000000
}
```

---

## 4. Policy: `govern_feature_outlier`

*   **ID:** `GFO-001`
*   **Description:** This policy monitors the input feature vectors being sent to the model. It triggers if a key feature exhibits a value that is a significant statistical outlier (e.g., more than 5 standard deviations from the mean of its training distribution). This could indicate a data pipeline error, a novel event, or a potential adversarial input.
*   **Graduated Intervention:** The policy prescribes a `FORCE_EXPLAIN` action. The model is allowed to make the prediction, but the SCP forces the generation of a detailed SHAP or LIME explainability report for that specific prediction. This allows for offline analysis without halting real-time operations.
*   **Rego Code:**

```rego
package scp.governance

default allow = true

# Force an explanation if a key feature is a 5-sigma outlier
decision = "FORCE_EXPLAIN" {
    abs(input.features.customer_age - input.model.training_stats.customer_age.mean) > (5 * input.model.training_stats.customer_age.stddev)
}
```