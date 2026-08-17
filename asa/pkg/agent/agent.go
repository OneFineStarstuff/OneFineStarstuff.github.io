package agent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

// ASA represents the Autonomous Supervisory Agent.
// It monitors a target agent and sends alerts to the SCP.
type ASA struct {
	targetAgentID string
	scpEndpoint   string
	httpClient    *http.Client
}

// NewASA creates a new instance of the ASA.
func NewASA(targetAgentID, scpEndpoint string) (*ASA, error) {
	if targetAgentID == "" || scpEndpoint == "" {
		return nil, fmt.Errorf("targetAgentID and scpEndpoint cannot be empty")
	}
	return &ASA{
		targetAgentID: targetAgentID,
		scpEndpoint:   scpEndpoint,
		httpClient:    &http.Client{Timeout: 5 * time.Second},
	}, nil
}

// PerformHealthCheck simulates a health check on the target agent.
// In a real implementation, this would involve complex logic, such as:
// - Requesting a Zero-Knowledge Proof (ZKP) from the target agent.
// - Checking for model drift against pre-defined thresholds.
// - Verifying the agent's policy compliance.
func (a *ASA) PerformHealthCheck() {
	log.Printf("Performing health check on Agent %s...", a.targetAgentID)

	// *** Placeholder for ZKP attestation logic ***
	// For now, we'll simulate a random failure to trigger an alert.
	if time.Now().Unix()%10 == 0 {
		log.Printf("HEALTH CHECK FAILED: Zero-Knowledge Proof validation failed for Agent %s.", a.targetAgentID)
		a.sendAlert("ZKP_FAIL", "Invalid Proof", "CRITICAL")
		return
	}

	log.Printf("Health check passed for Agent %s.", a.targetAgentID)
}

// Alert represents the data structure for an alert sent to the SCP.
// This mirrors the structure in the SCP's server package.
type Alert struct {
	DetectionVector string `json:"detection_vector"`
	Condition       string `json:"condition"`
	Severity        string `json:"severity"`
	AgentID         string `json:"agent_id"`
	Timestamp       int64  `json:"timestamp"`
}

// sendAlert constructs and sends an alert to the Supervisory Control Plane (SCP).
func (a *ASA) sendAlert(vector, condition, severity string) {
	alert := Alert{
		DetectionVector: vector,
		Condition:       condition,
		Severity:        severity,
		AgentID:         a.targetAgentID,
		Timestamp:       time.Now().Unix(),
	}

	payload, err := json.Marshal(alert)
	if err != nil {
		log.Printf("ERROR: Could not marshal alert: %v", err)
		return
	}

	req, err := http.NewRequest(http.MethodPost, a.scpEndpoint, bytes.NewBuffer(payload))
	if err != nil {
		log.Printf("ERROR: Could not create alert request: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		log.Printf("ERROR: Failed to send alert to SCP: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted {
		log.Printf("WARN: SCP returned a non-202 status code: %s", resp.Status)
	}

	log.Printf("Successfully sent %s alert to SCP.", severity)
}
