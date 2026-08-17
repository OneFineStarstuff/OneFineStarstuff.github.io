package agent

import (
	"testing"
)

func TestNewASA(t *testing.T) {
	agentID := "test-agent"
	scpEndpoint := "http://fake-scp:8080"

	asa, err := NewASA(agentID, scpEndpoint)
	if err != nil {
		t.Fatalf("Failed to create ASA: %v", err)
	}

	if asa.AgentID != agentID {
		t.Errorf("Expected AgentID to be %s, but got %s", agentID, asa.AgentID)
	}

	if asa.SCPEndpoint != scpEndpoint {
		t.Errorf("Expected SCPEndpoint to be %s, but got %s", scpEndpoint, asa.SCPEndpoint)
	}
}

func TestPerformHealthCheck(t *testing.T) {
	// Note: This is a basic test to ensure the function executes without panicking.
	// A more advanced test would involve a mock HTTP server to verify the request.
	agentID := "test-agent-for-health-check"
	// Use a non-routable address to ensure the HTTP request fails quickly.
	scpEndpoint := "http://127.0.0.1:9999/test"

	asa, _ := NewASA(agentID, scpEndpoint)

	// We expect this to run without panicking. The function logs errors, but doesn't crash.
	asa.PerformHealthCheck()
}
