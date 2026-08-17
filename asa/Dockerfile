# Stage 1: Build the Go binary
FROM golang:1.21-alpine AS builder

# Set the working directory inside the container
WORKDIR /app

# Copy the Go module files and download dependencies
COPY go.mod .
RUN go mod download

# Copy the rest of the application source code
COPY . .

# Run unit tests
RUN go test ./pkg/agent

# Build the Go application
# -o /asa-agent creates the binary named 'asa-agent' in the root directory
# CGO_ENABLED=0 is a best practice for creating static binaries
RUN CGO_ENABLED=0 go build -o /asa-agent ./main.go

# Stage 2: Create the final, minimal image
FROM alpine:latest

# Copy the binary from the builder stage
COPY --from=builder /asa-agent /asa-agent

# Command to run the executable
ENTRYPOINT ["/asa-agent"]
