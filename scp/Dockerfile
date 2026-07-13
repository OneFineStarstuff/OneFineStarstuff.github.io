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
RUN go test ./pkg/server

# Build the Go application
# -o /scp-server creates the binary named 'scp-server' in the root directory
# CGO_ENABLED=0 is a best practice for creating static binaries
RUN CGO_ENABLED=0 go build -o /scp-server ./main.go

# Stage 2: Create the final, minimal image
FROM alpine:latest

# Copy the binary from the builder stage
COPY --from=builder /scp-server /scp-server

# Expose port 8080 to the outside world
EXPOSE 8080

# Command to run the executable
ENTRYPOINT ["/scp-server"]
