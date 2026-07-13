package main

import (
	"fmt"
	"log"
	"net/http"

	"scp/pkg/server" // Import the new server package
)

func main() {
	// Create a new instance of the SCPServer from our server package
	scpServer := server.NewSCPServer()

	// Basic handler to confirm the server is running
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Supervisory Control Plane (SCP) is online and awaiting instructions.")
	})

	// Wire the AlertHandler from our SCPServer to the /alert endpoint
	http.HandleFunc("/alert", scpServer.AlertHandler)

	// Start the SCP's main HTTP server
	log.Println("Starting Supervisory Control Plane (SCP) on port 8080...")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatalf("FATAL: Could not start SCP server: %v", err)
	}
}
