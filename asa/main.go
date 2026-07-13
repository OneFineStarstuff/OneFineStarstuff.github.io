package main

import (
	"log"
	"os"
	"time"

	"asa/pkg/agent" // Import the new agent package
)

func main() {
	log.Println("Initializing Autonomous Supervisory Agent (ASA)...")

	// In a real implementation, the target agent ID would be dynamically configured.
	targetAgentID := "model-g-451-ver-1.2"

	// Use an environment variable for the SCP endpoint, with a default for local dev
	scpEndpoint := os.Getenv("SCP_ENDPOINT")
	if scpEndpoint == "" {
		scpEndpoint = "http://localhost:8080/alert"
	}

	// Create a new instance of the ASA
	asa, err := agent.NewASA(targetAgentID, scpEndpoint)
	if err != nil {
		log.Fatalf("FATAL: Could not create ASA: %v", err)
	}

	log.Printf("ASA is now monitoring Agent: %s, with SCP endpoint: %s", targetAgentID, scpEndpoint)

	// Start the ASA's main monitoring loop.
	for {
		asa.PerformHealthCheck()
		time.Sleep(15 * time.Second) // Wait 15 seconds before the next check
	}
}
