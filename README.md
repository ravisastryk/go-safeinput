# go-safeinput

[![CI](https://github.com/ravisastryk/go-safeinput/actions/workflows/ci.yml/badge.svg)](https://github.com/ravisastryk/go-safeinput/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/ravisastryk/go-safeinput)](https://goreportcard.com/report/github.com/ravisastryk/go-safeinput)
[![codecov](https://codecov.io/gh/ravisastryk/go-safeinput/branch/main/graph/badge.svg)](https://codecov.io/gh/ravisastryk/go-safeinput)
[![Go Reference](https://pkg.go.dev/badge/github.com/ravisastryk/go-safeinput.svg)](https://pkg.go.dev/github.com/ravisastryk/go-safeinput)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

### 🔴 Vulnerability Impact Analysis

**MITRE CWE Top 25 coverage** — Real-time ecosystem scan (updated weekly)

| CWE | Vulnerability | Instances | Severity |
|-----|--------------|-----------|----------|
| ![CWE-502](https://img.shields.io/badge/CWE--502-212168-critical?style=flat-square) | Deserialization of Untrusted Data | **166240** | 🔴 CRITICAL |
| ![CWE-79](https://img.shields.io/badge/CWE--79-58788-red?style=flat-square) | Cross-site Scripting (XSS) | **46156** | 🟠 HIGH |
| ![CWE-89](https://img.shields.io/badge/CWE--89-66944-critical?style=flat-square) | SQL Injection | **54904** | 🔴 CRITICAL |
| ![CWE-22](https://img.shields.io/badge/CWE--22-6000-red?style=flat-square) | Path Traversal | **46156** | 🟠 HIGH |
| ![CWE-78](https://img.shields.io/badge/CWE--78-0-critical?style=flat-square) | OS Command Injection | **69164** | 🔴 CRITICAL |

**Total Impact:** ![Total Vulnerable](https://img.shields.io/badge/total_vulnerable-343900-critical?style=for-the-badge) ![Stars Affected](https://img.shields.io/badge/stars_affected-225259-blue?style=for-the-badge)

---

Universal input sanitization library for Go with **MITRE CWE Top 25** coverage. Zero external dependencies, production-ready, easy to integrate.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [Safe Deserialization (CWE-502)](#safe-deserialization-cwe-502)
- [Agentic AI Support](#agentic-ai-support)
- [Supported Contexts](#supported-contexts)
- [Requirements](#requirements)
- [Development](#development)
- [Contributing](#contributing)
- [License](#license)

## Features

- **CWE-79**: XSS prevention for HTML contexts
- **CWE-89**: SQL Injection prevention for identifiers and values
- **CWE-22**: Path Traversal prevention
- **CWE-78**: OS Command Injection prevention
- **CWE-502**: Safe deserialization with size, depth, and type limits
- **Agentic AI**: AST-based static analysis, HTTP middleware, and safe JSON decoder
- **Zero dependencies**: Standard library only (plus `gopkg.in/yaml.v3` for YAML)
- **90%+ test coverage**, race-detector clean

## Installation

```bash
go get github.com/ravisastryk/go-safeinput
```

## Quick Start

```go
s := safeinput.Default()

safe, err := s.Sanitize("<script>alert('xss')</script>Hello", safeinput.HTMLBody)
// safe == "Hello", script tag stripped
```

## Usage

```go
s := safeinput.Default()

// XSS — strip tags from HTML body or attribute
s.Sanitize(input, safeinput.HTMLBody)
s.Sanitize(input, safeinput.HTMLAttr)

// SQL — validate identifiers; reject injection attempts
s.Sanitize(tableName, safeinput.SQLIdentifier)
s.Sanitize(value,     safeinput.SQLValue)       // escapes single quotes

// Path traversal — reject ".." and absolute paths
s.Sanitize(path, safeinput.FilePath)

// Shell injection — reject dangerous shell characters
s.Sanitize(arg, safeinput.ShellArg)
```

## Safe Deserialization (CWE-502)

### `safedecode` — bounded JSON decoding (new)

```go
import "github.com/ravisastryk/go-safeinput/safedecode"

dec := safedecode.NewDecoder(r.Body, safedecode.Config{
    MaxBytes:     64 << 10, // 64 KB
    MaxDepth:     10,
    MaxKeys:      200,
    AllowedTypes: []reflect.Type{reflect.TypeOf(MyRequest{})},
})
var req MyRequest
if err := dec.Decode(&req); err != nil {
    http.Error(w, "invalid payload", http.StatusBadRequest)
    return
}
```

### `safedeserialize` — multi-format (JSON / YAML / XML / Gob)

```go
import "github.com/ravisastryk/go-safeinput/safedeserialize"

var user User
err := safedeserialize.JSON(data, &user,
    safedeserialize.WithMaxSize(1<<16),   // 64 KB
    safedeserialize.WithMaxDepth(16),
    safedeserialize.WithStrictMode(true), // reject unknown fields
)
```

Dangerous targets (`interface{}`, `map[string]interface{}`, `[]interface{}`) are blocked automatically.

## Agentic AI Support

Three packages for detection, prevention, and safe decoding in CI pipelines and production services.

### Analyzer — Static Detection

`github.com/ravisastryk/go-safeinput/analyzer`

AST-based scanner that finds HTTP handlers reading user input without sanitization. Each finding
includes a CWE identifier, severity, confidence score, and a ready-to-paste fix snippet.

```go
findings, err := analyzer.Default().AnalyzeFile("handler.go", src)
for _, f := range findings {
    fmt.Printf("%s line %d — %s\n%s\n", f.CWE, f.Line, f.Suggestion, f.FixCode)
}
```

Run across a source tree from CI or the command line:

```bash
go run ./cmd/analyzer -dir . -fmt json > findings.json
```

GitHub Actions emits inline `::warning` annotations on PR diffs automatically.

### Middleware — Auto-Sanitization

`github.com/ravisastryk/go-safeinput/middleware`

Drop-in `http.Handler` wrapper that sanitizes every query parameter and form field before the
wrapped handler runs. Per-parameter context routing selects the right sanitization strategy.

```go
sanitize := func(v string, ctx middleware.Context) (string, error) {
    return safeinput.Default().Sanitize(v, safeinput.Context(ctx))
}

http.ListenAndServe(":8080", middleware.New(mux, sanitize,
    middleware.WithContext("file", middleware.FilePath),
    middleware.WithContext("q",    middleware.SQLIdentifier),
))
```

### CI Integration

The `agentic-fix` job runs automatically on every PR:

1. Tests `analyzer`, `middleware`, and `safedecode`
2. Runs the analyzer and posts findings as inline PR annotations
3. Uploads `agentic-findings.json` as a downloadable artifact

Remove `-exit-zero` from the `Run Agentic Analyzer` step in [ci.yml](.github/workflows/ci.yml)
to make the job a hard gate that blocks merges when unsanitized input is found.

## Supported Contexts

| Context | CWE | Use Case |
|---------|-----|----------|
| `HTMLBody` | CWE-79 | User-generated HTML content |
| `HTMLAttr` | CWE-79 | HTML attribute values |
| `SQLIdentifier` | CWE-89 | Table/column names |
| `SQLValue` | CWE-89 | User input in SQL queries |
| `FilePath` | CWE-22 | File uploads, file operations |
| `ShellArg` | CWE-78 | Shell command arguments |

## Requirements

- Go 1.23+
- Core package: no external dependencies
- YAML support: `gopkg.in/yaml.v3`

## Development

```bash
make test          # run tests (90% coverage threshold)
make lint          # golangci-lint
make security      # gosec + govulncheck
make fmt           # gofmt + goimports
make all           # lint + test
make coverage-html # HTML coverage report
make tools         # install dev tools
```

## Contributing

- Maintain 90%+ test coverage
- Pass all linter checks
- No external dependencies in the core package
- Follow Go best practices and include tests for new features

See [CONTRIBUTING.md](CONTRIBUTING.md) and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## License

MIT License — see [LICENSE](LICENSE) for details.
