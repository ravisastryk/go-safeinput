# go-safeinput

[![CI](https://github.com/ravisastryk/go-safeinput/actions/workflows/ci.yml/badge.svg)](https://github.com/ravisastryk/go-safeinput/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/ravisastryk/go-safeinput)](https://goreportcard.com/report/github.com/ravisastryk/go-safeinput)
[![codecov](https://codecov.io/gh/ravisastryk/go-safeinput/branch/main/graph/badge.svg)](https://codecov.io/gh/ravisastryk/go-safeinput)
[![Go Reference](https://pkg.go.dev/badge/github.com/ravisastryk/go-safeinput.svg)](https://pkg.go.dev/github.com/ravisastryk/go-safeinput)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Universal input sanitization library for Go applications with **MITRE CWE Top 25** coverage. Zero external dependencies, production-ready, and easy to integrate.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage](#usage)
  - [HTML Sanitization (XSS Prevention)](#html-sanitization-xss-prevention)
  - [SQL Injection Prevention](#sql-injection-prevention)
  - [Path Traversal Prevention](#path-traversal-prevention)
  - [Shell Command Injection Prevention](#shell-command-injection-prevention)
- [Supported Contexts](#supported-contexts)
- [Requirements](#requirements)
- [Development](#development)
- [Contributing](#contributing)
- [License](#license)

## Features

- **CWE-79**: Cross-site Scripting (XSS) prevention for HTML contexts
- **CWE-89**: SQL Injection prevention for identifiers and values
- **CWE-22**: Path Traversal prevention for file system operations
- **CWE-78**: OS Command Injection prevention for shell arguments
- **Zero dependencies**: Uses only the Go standard library
- **High test coverage**: Greater than 90% test coverage
- **Production-ready**: Thoroughly tested with race detection
- **Simple API**: Easy to integrate into existing applications
- **Well-documented**: Comprehensive documentation and examples

## Installation

```bash
go get github.com/ravisastryk/go-safeinput
```

## Quick Start

```go
package main

import (
    "fmt"
    "log"

    "github.com/ravisastryk/go-safeinput"
)

func main() {
    // Create a sanitizer with default settings
    s := safeinput.Default()

    // Sanitize HTML to prevent XSS
    userInput := "<script>alert('xss')</script>Hello World!"
    safe, err := s.Sanitize(userInput, safeinput.HTMLBody)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println(safe) // Output: Hello World!
}
```

## Usage

### HTML Sanitization (XSS Prevention)

Protect against Cross-Site Scripting attacks by sanitizing HTML content:

```go
s := safeinput.Default()

// Sanitize HTML body content
input := "<script>alert('xss')</script><p>Safe content</p>"
safe, err := s.Sanitize(input, safeinput.HTMLBody)
if err != nil {
    log.Fatal(err)
}
fmt.Println(safe) // Output: <p>Safe content</p>

// Sanitize HTML attributes
attrInput := "value\" onclick=\"alert('xss')\""
safeAttr, err := s.Sanitize(attrInput, safeinput.HTMLAttr)
if err != nil {
    log.Fatal(err)
}
fmt.Println(safeAttr) // Output: value
```

### SQL Injection Prevention

Validate SQL identifiers and values to prevent SQL injection attacks:

```go
s := safeinput.Default()

// Validate SQL identifiers (table names, column names)
tableName := "users"
safe, err := s.Sanitize(tableName, safeinput.SQLIdentifier)
if err != nil {
    log.Fatal(err)
}
fmt.Println(safe) // Output: users

// Reject malicious SQL
malicious := "users; DROP TABLE users--"
_, err = s.Sanitize(malicious, safeinput.SQLIdentifier)
if err != nil {
    fmt.Println(err) // Output: invalid SQL identifier
}

// Validate SQL values
value := "John's"
safeValue, err := s.Sanitize(value, safeinput.SQLValue)
if err != nil {
    log.Fatal(err)
}
fmt.Println(safeValue) // Output: John''s (properly escaped)
```

### Path Traversal Prevention

Prevent path traversal attacks when working with file paths:

```go
s := safeinput.Default()

// Validate safe file paths
safePath := "uploads/avatar.png"
validated, err := s.Sanitize(safePath, safeinput.FilePath)
if err != nil {
    log.Fatal(err)
}
fmt.Println(validated) // Output: uploads/avatar.png

// Reject path traversal attempts
maliciousPath := "../../etc/passwd"
_, err = s.Sanitize(maliciousPath, safeinput.FilePath)
if err != nil {
    fmt.Println(err) // Output: path traversal detected
}

// Reject absolute paths (if not allowed)
absolutePath := "/etc/passwd"
_, err = s.Sanitize(absolutePath, safeinput.FilePath)
if err != nil {
    fmt.Println(err) // Output: absolute paths not allowed
}
```

### Shell Command Injection Prevention

Sanitize shell arguments to prevent command injection:

```go
s := safeinput.Default()

// Sanitize shell arguments
arg := "filename.txt"
safe, err := s.Sanitize(arg, safeinput.ShellArg)
if err != nil {
    log.Fatal(err)
}
fmt.Println(safe) // Output: filename.txt

// Reject dangerous shell characters
malicious := "file; rm -rf /"
_, err = s.Sanitize(malicious, safeinput.ShellArg)
if err != nil {
    fmt.Println(err) // Output: dangerous shell characters detected
}
```

## Supported Contexts

The library supports the following sanitization contexts:

| Context | Description | Use Case |
|---------|-------------|----------|
| `HTMLBody` | HTML body content | Sanitizing user-generated HTML content |
| `HTMLAttr` | HTML attribute values | Sanitizing values for HTML attributes |
| `SQLIdentifier` | SQL identifiers | Table names, column names, database names |
| `SQLValue` | SQL string values | User input in SQL queries (use with parameterized queries) |
| `FilePath` | File system paths | File uploads, file operations |
| `ShellArg` | Shell command arguments | Executing system commands with user input |

## Requirements

- **Go**: 1.23 or higher
- **Dependencies**: None (uses only Go standard library)

## Development

### Setup

```bash
# Clone the repository
git clone https://github.com/ravisastryk/go-safeinput.git
cd go-safeinput

# Install development tools
make tools
```

### Running Tests

```bash
# Run all tests with coverage
make test

# Run tests with race detection
go test -race ./...

# Generate HTML coverage report
make coverage-html
```

### Code Quality

```bash
# Run linter
make lint

# Format code
make fmt

# Run security checks
make security

# Run all checks (lint + test)
make all
```

### Available Make Targets

| Target | Description |
|--------|-------------|
| `make all` | Run lint and test (default) |
| `make test` | Run tests with coverage verification (90% threshold) |
| `make lint` | Run golangci-lint |
| `make security` | Run security scanners (gosec, govulncheck) |
| `make fmt` | Format code with gofmt and goimports |
| `make tidy` | Tidy go.mod |
| `make coverage-html` | Generate HTML coverage report |
| `make tools` | Install development tools |
| `make clean` | Clean build artifacts |

## Contributing

Contributions are welcome! Please read our [Contributing Guidelines](CONTRIBUTING.md) and [Code of Conduct](CODE_OF_CONDUCT.md) before submitting pull requests.

### Key Guidelines

- Maintain 90%+ test coverage
- Pass all linter checks
- No external dependencies
- Follow Go best practices
- Include tests for new features

## License

MIT License - see [LICENSE](LICENSE) for details.
