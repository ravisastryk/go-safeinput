# go-safeinput

Universal input sanitization for Go applications - MITRE CWE Top 25 coverage.

| Badge | Status |
|-------|--------|
| CI | ![CI](https://github.com/ravisastryk/go-safeinput/actions/workflows/ci.yml/badge.svg) |
| Go Report | [![Go Report Card](https://goreportcard.com/badge/github.com/ravisastryk/go-safeinput)](https://goreportcard.com/report/github.com/ravisastryk/go-safeinput) |
| Coverage | [![codecov](https://codecov.io/gh/ravisastryk/go-safeinput/branch/main/graph/badge.svg)](https://codecov.io/gh/ravisastryk/go-safeinput) |
| Docs | [![Go Reference](https://pkg.go.dev/badge/github.com/ravisastryk/go-safeinput.svg)](https://pkg.go.dev/github.com/ravisastryk/go-safeinput) |
| License | MIT |

## Features

- CWE-79: Cross-site Scripting (XSS) prevention
- CWE-89: SQL Injection prevention
- CWE-22: Path Traversal prevention
- CWE-78: OS Command Injection prevention
- Zero external dependencies - uses only Go standard library
- Greater than 90% test coverage
- Docker support with multi-stage builds
- Security scanning with gosec, govulncheck, CodeQL

## Requirements

- Go 1.24 or higher
- Docker (optional)

## Installation

```bash
go get github.com/ravisastryk/go-safeinput
```

## Quick Start

```go
package main

import (
    "fmt"
    "github.com/ravisastryk/go-safeinput"
)

func main() {
    s := safeinput.Default()
    
    // XSS Prevention
    safe, _ := s.Sanitize("<script>alert('xss')</script>Hi", safeinput.HTMLBody)
    fmt.Println(safe) // Output: Hi
    
    // Path Traversal Prevention
    _, err := s.Sanitize("../../etc/passwd", safeinput.FilePath)
    fmt.Println(err) // Output: path traversal detected
    
    // SQL Injection Prevention
    _, err = s.Sanitize("users; DROP TABLE--", safeinput.SQLIdentifier)
    fmt.Println(err) // Output: invalid SQL identifier
}
```

## Development

```bash
# Run tests
make test

# Run linter
make lint

# Run security checks
make security

# Build Docker image
make docker
```

## License

MIT License - see LICENSE for details.

---

Author: Ravi Sastry Kadali (https://github.com/ravisastryk)
