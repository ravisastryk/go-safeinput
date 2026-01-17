# go-safeinput

[![CI](https://github.com/ravisastryk/go-safeinput/actions/workflows/ci.yml/badge.svg)](https://github.com/ravisastryk/go-safeinput/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/ravisastryk/go-safeinput)](https://goreportcard.com/report/github.com/ravisastryk/go-safeinput)
[![codecov](https://codecov.io/gh/ravisastryk/go-safeinput/branch/main/graph/badge.svg)](https://codecov.io/gh/ravisastryk/go-safeinput)
[![Go Reference](https://pkg.go.dev/badge/github.com/ravisastryk/go-safeinput.svg)](https://pkg.go.dev/github.com/ravisastryk/go-safeinput)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

### 🔴 CWE-502 Deserialization Vulnerability Impact

![CWE-502 Instances](https://img.shields.io/badge/CWE--502_vulnerable-169392-critical?style=for-the-badge)
![Stars Affected](https://img.shields.io/badge/stars_affected-27125-blue?style=for-the-badge)

**169392 vulnerable code instances** found across the Go ecosystem (updated weekly)

---

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
  - [Safe Deserialization (CWE-502 Prevention)](#safe-deserialization-cwe-502-prevention)
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
- **CWE-502**: Deserialization of Untrusted Data prevention (JSON, YAML, XML, Gob)
- **Zero dependencies**: Uses only the Go standard library (plus gopkg.in/yaml.v3 for YAML support)
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

### Safe Deserialization (CWE-502 Prevention)

The `safedeserialize` package prevents deserialization vulnerabilities by blocking dangerous patterns and enforcing security constraints:

```go
import "github.com/ravisastryk/go-safeinput/safedeserialize"

type User struct {
    ID    int    `json:"id"`
    Name  string `json:"name"`
    Email string `json:"email"`
}

// Basic usage - safe by default
var user User
err := safedeserialize.JSON(data, &user)
if err != nil {
    log.Fatal(err)
}

// With custom security options
err = safedeserialize.JSON(data, &user,
    safedeserialize.WithMaxSize(1<<16),      // 64KB max
    safedeserialize.WithMaxDepth(16),        // Max 16 levels deep
    safedeserialize.WithStrictMode(true),    // Reject unknown fields
)
```

#### Security Features

**1. Blocks Dangerous Types**

The library automatically rejects deserialization into `interface{}`, `map[string]interface{}`, and `[]interface{}` types which are common attack vectors:

```go
// BLOCKED - Returns ErrInterfaceTarget
var data interface{}
err := safedeserialize.JSON(input, &data)

// BLOCKED - Returns ErrMapInterface
var m map[string]interface{}
err := safedeserialize.JSON(input, &m)

// SAFE - Use concrete types
var user User
err := safedeserialize.JSON(input, &user)
```

**2. Enforces Size Limits**

Prevents denial-of-service attacks from oversized payloads:

```go
// Default: 1MB max
// Custom: 64KB max
err := safedeserialize.JSON(data, &user,
    safedeserialize.WithMaxSize(1<<16),
)
// Returns ErrDataTooLarge if exceeded
```

**3. Limits Nesting Depth**

Prevents stack exhaustion attacks from deeply nested structures:

```go
// Default: 32 levels
// Custom: 10 levels
err := safedeserialize.JSON(data, &user,
    safedeserialize.WithMaxDepth(10),
)
// Returns ErrMaxDepthExceeded if exceeded
```

**4. Type Whitelisting**

Restrict deserialization to explicitly allowed types:

```go
registry := safedeserialize.NewTypeRegistry()
registry.Register(User{})
registry.Register(Config{})

err := safedeserialize.JSON(data, &user, registry.Option())
// Returns ErrTypeNotAllowed for other types
```

**5. Strict Parsing Mode**

Enabled by default - rejects unknown fields to prevent unexpected data:

```go
// Strict mode enabled (default)
err := safedeserialize.JSON(data, &user)
// Returns error if JSON contains fields not in User struct

// Disable if needed (not recommended)
err := safedeserialize.JSON(data, &user,
    safedeserialize.WithStrictMode(false),
)
```

#### Supported Formats

| Format | Functions | Use Case |
|--------|-----------|----------|
| JSON | `JSON()`, `JSONReader()` | REST APIs, config files |
| YAML | `YAML()`, `YAMLReader()` | Configuration files |
| XML | `XML()`, `XMLReader()` | Legacy systems, SOAP |
| Gob | `Gob()`, `GobReader()` | Go-to-Go communication |

#### HTTP Handler Example

```go
import "github.com/ravisastryk/go-safeinput/safedeserialize"

func CreateUserHandler(w http.ResponseWriter, r *http.Request) {
    var req CreateUserRequest

    // Safe deserialization with size limit
    err := safedeserialize.JSONReader(r.Body, &req,
        safedeserialize.WithMaxSize(1<<16), // 64KB max
    )
    if err != nil {
        http.Error(w, "Invalid request", http.StatusBadRequest)
        return
    }

    // Process validated request...
}
```

#### Configuration File Loading

```go
func LoadConfig(path string) (*Config, error) {
    data, err := os.ReadFile(path)
    if err != nil {
        return nil, err
    }

    var config Config
    err = safedeserialize.YAML(data, &config,
        safedeserialize.WithMaxSize(1<<16),
        safedeserialize.WithStrictMode(true),
    )
    if err != nil {
        return nil, fmt.Errorf("invalid config: %w", err)
    }

    return &config, nil
}
```

#### Reusable Decoder

For better performance when deserializing multiple payloads with the same options:

```go
decoder := safedeserialize.NewDecoder(
    safedeserialize.WithMaxSize(1<<20),
    safedeserialize.WithStrictMode(true),
)

// Reuse for multiple operations
decoder.JSON(data1, &obj1)
decoder.JSON(data2, &obj2)
decoder.YAML(data3, &obj3)
```

#### Default Security Settings

| Setting | Default Value | Description |
|---------|---------------|-------------|
| MaxSize | 1MB (1 << 20) | Maximum input data size |
| MaxDepth | 32 | Maximum nesting depth |
| StrictMode | true | Reject unknown fields |
| AllowMapStringInterface | false | Block map[string]interface{} |
| AllowSliceInterface | false | Block []interface{} |

#### Common Errors

```go
var (
    ErrDataTooLarge     // Input exceeds MaxSize
    ErrNilTarget        // Target pointer is nil
    ErrNotPointer       // Target is not a pointer
    ErrInterfaceTarget  // Target is interface{}
    ErrMapInterface     // Target is map[string]interface{}
    ErrSliceInterface   // Target is []interface{}
    ErrTypeNotAllowed   // Type not in whitelist
    ErrMaxDepthExceeded // Nesting too deep
    ErrEmptyData        // Input is empty
)
```

#### Why CWE-502 Matters

Deserialization of untrusted data (CWE-502) can lead to:

- **Remote Code Execution (RCE)**: Arbitrary code execution on the server
- **Denial of Service (DoS)**: Resource exhaustion from malicious payloads
- **Authentication Bypass**: Manipulating serialized session data
- **Data Corruption**: Injecting malicious object states

Common vulnerable patterns:

```go
// DANGEROUS - Allows arbitrary structures
var data interface{}
json.Unmarshal(untrustedInput, &data)

// DANGEROUS - No size limit
body, _ := io.ReadAll(r.Body)
json.Unmarshal(body, &config)

// DANGEROUS - Deep nesting can crash stack
type Nested struct {
    Next *Nested `json:"next"`
}
```

For complete documentation, see the [safedeserialize package README](safedeserialize/README.md).

## Supported Contexts

### Input Sanitization Contexts

The library supports the following sanitization contexts:

| Context | Description | CWE | Use Case |
|---------|-------------|-----|----------|
| `HTMLBody` | HTML body content | CWE-79 | Sanitizing user-generated HTML content |
| `HTMLAttr` | HTML attribute values | CWE-79 | Sanitizing values for HTML attributes |
| `SQLIdentifier` | SQL identifiers | CWE-89 | Table names, column names, database names |
| `SQLValue` | SQL string values | CWE-89 | User input in SQL queries (use with parameterized queries) |
| `FilePath` | File system paths | CWE-22 | File uploads, file operations |
| `ShellArg` | Shell command arguments | CWE-78 | Executing system commands with user input |

### Safe Deserialization Formats

The `safedeserialize` package supports the following formats:

| Format | Package Functions | CWE | Use Case |
|--------|------------------|-----|----------|
| JSON | `JSON()`, `JSONReader()` | CWE-502 | REST APIs, web services, config files |
| YAML | `YAML()`, `YAMLReader()` | CWE-502 | Configuration files, Kubernetes configs |
| XML | `XML()`, `XMLReader()` | CWE-502 | Legacy systems, SOAP APIs |
| Gob | `Gob()`, `GobReader()` | CWE-502 | Go-to-Go communication, internal services |

## Requirements

- **Go**: 1.23 or higher
- **Dependencies**:
  - Core package: None (uses only Go standard library)
  - Safe deserialization: `gopkg.in/yaml.v3` (for YAML support)

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
