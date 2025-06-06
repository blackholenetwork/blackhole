# Production Dockerfile for Blackhole Network
FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git make gcc musl-dev

# Set working directory
WORKDIR /app

# Copy go mod files first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-w -s -X github.com/blackholenetwork/internal/version.Version=$(git describe --tags --always) \
    -X github.com/blackholenetwork/internal/version.BuildTime=$(date -u +%Y%m%d-%H%M%S)" \
    -a -installsuffix cgo \
    -o blackhole ./cmd/blackhole

# Final stage - minimal image
FROM scratch

# Import from builder
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy the binary
COPY --from=builder /app/blackhole /blackhole

# Copy default configuration
COPY --from=builder /app/config/default.yaml /config/blackhole.yaml

# Create data directory
VOLUME ["/data", "/config"]

# Expose ports
EXPOSE 8080 4001 5001 9090

# Run as non-root user
USER 1000:1000

# Set the entrypoint
ENTRYPOINT ["/blackhole"]

# Default command arguments
CMD ["--config", "/config/blackhole.yaml", "--data-dir", "/data"]