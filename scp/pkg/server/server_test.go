package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAlertHandler(t *testing.T) {
	// Create a new server instance, which initializes the router.
	server := NewServer(":8080")

	// Define a sample alert payload.
	alert := Alert{
		AgentID:   "test-agent-001",
		Timestamp: "2024-01-01T12:00:00Z",
		Severity:  "critical",
		Message:   "Simulated health check failure for testing.",
	}
	payload, _ := json.Marshal(alert)

	// Create a new HTTP request to the /alert endpoint.
	req, err := http.NewRequest("POST", "/alert", bytes.NewBuffer(payload))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Record the response using httptest.
	rr := httptest.NewRecorder()

	// Serve the request using the server's router.
	server.router.ServeHTTP(rr, req)

	// Check if the status code is what we expect (202 Accepted).
	if status := rr.Code; status != http.StatusAccepted {
		t.Errorf("Handler returned wrong status code: got %v want %v",
			status, http.StatusAccepted)
	}

	// Check if the response body is what we expect.
	expected := `{"status":"alert received"}`
	if rr.Body.String() != expected {
		t.Errorf("Handler returned unexpected body: got %v want %v",
			rr.Body.String(), expected)
	}
}
