# go-safeinput Makefile
# =====================

.PHONY: all test lint security clean help

# Variables
GO_VERSION := 1.23
COVERAGE_THRESHOLD := 90

# Default target
all: lint test

# Run tests with coverage
test:
	@echo "==> Running tests..."
	go test -v -race -coverprofile=coverage.out -covermode=atomic ./...
	@echo "==> Coverage report:"
	@go tool cover -func=coverage.out | tail -1
	@COVERAGE=$$(go tool cover -func=coverage.out | grep total | awk '{print $$3}' | sed 's/%//'); \
	if [ $$(echo "$$COVERAGE < $(COVERAGE_THRESHOLD)" | bc -l) -eq 1 ]; then \
		echo "FAIL: Coverage $$COVERAGE% is below $(COVERAGE_THRESHOLD)% threshold"; \
		exit 1; \
	fi; \
	echo "PASS: Coverage $$COVERAGE% meets $(COVERAGE_THRESHOLD)% threshold"

# Run linter
lint:
	@echo "==> Running linter..."
	golangci-lint run --timeout=5m ./...

# Run security checks
security:
	@echo "==> Running security checks..."
	gosec ./...
	govulncheck ./...

# Generate coverage HTML report
coverage-html: test
	@echo "==> Generating HTML coverage report..."
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

# Format code
fmt:
	@echo "==> Formatting code..."
	gofmt -w .
	goimports -w .

# Tidy dependencies
tidy:
	@echo "==> Tidying dependencies..."
	go mod tidy

# Clean build artifacts
clean:
	@echo "==> Cleaning..."
	rm -rf coverage.out coverage.html

# Install development tools
tools:
	@echo "==> Installing development tools..."
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.62.0
	go install github.com/securego/gosec/v2/cmd/gosec@latest
	go install golang.org/x/vuln/cmd/govulncheck@latest
	go install golang.org/x/tools/cmd/goimports@latest

# Show help
help:
	@echo "go-safeinput Makefile"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  all           Run lint and test (default)"
	@echo "  test          Run tests with coverage"
	@echo "  lint          Run golangci-lint"
	@echo "  security      Run security scanners (gosec, govulncheck)"
	@echo "  coverage-html Generate HTML coverage report"
	@echo "  fmt           Format code"
	@echo "  tidy          Tidy go.mod"
	@echo "  clean         Clean build artifacts"
	@echo "  tools         Install development tools"
	@echo "  help          Show this help"
