# =============================================================================
# go-safeinput Dockerfile
# Multi-stage build for minimal production image
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1: Build
# -----------------------------------------------------------------------------
FROM golang:1.24-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Set working directory
WORKDIR /app

# Copy go mod files first for better caching
COPY go.mod go.sum* ./

# Download dependencies (if any)
RUN go mod download

# Copy source code
COPY . .

# Run tests
RUN go test -v -race -coverprofile=coverage.out $(go list ./... | grep -v /cmd/)

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags='-w -s -extldflags "-static"' \
    -o /app/bin/safeinput \
    ./cmd/safeinput

# -----------------------------------------------------------------------------
# Stage 2: Security Scanner
# -----------------------------------------------------------------------------
FROM golang:1.24-alpine AS security

RUN apk add --no-cache git

WORKDIR /app
COPY --from=builder /app /app

# Install security tools
RUN go install github.com/securego/gosec/v2/cmd/gosec@latest && \
    go install golang.org/x/vuln/cmd/govulncheck@latest

# Run security scans
RUN gosec -fmt=json -out=/app/gosec-report.json ./... || true
RUN govulncheck ./... || true

# -----------------------------------------------------------------------------
# Stage 3: Production
# -----------------------------------------------------------------------------
FROM scratch AS production

# Import from builder
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /app/bin/safeinput /safeinput

# Run as non-root user
USER 65534:65534

ENTRYPOINT ["/safeinput"]

# -----------------------------------------------------------------------------
# Stage 4: Development
# -----------------------------------------------------------------------------
FROM golang:1.24-alpine AS development

RUN apk add --no-cache git make bash curl

# Install development tools
RUN go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest && \
    go install github.com/securego/gosec/v2/cmd/gosec@latest && \
    go install golang.org/x/vuln/cmd/govulncheck@latest && \
    go install github.com/go-delve/delve/cmd/dlv@latest

WORKDIR /app
COPY . .

CMD ["go", "test", "-v", "./..."]
