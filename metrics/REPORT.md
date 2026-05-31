# Go Ecosystem Vulnerability Impact Report

**Generated:** 2026-05-31 00:58 UTC
**Scanner:** [go-safeinput](https://github.com/ravisastryk/go-safeinput)
**Coverage:** MITRE CWE Top 25 vulnerabilities

## Executive Summary

| Metric | Value |
|--------|-------|
| **Total Vulnerable Instances** | **444888** |
| Total Stars Affected | 273079 |
| Total Forks Affected | 25137 |
| CWEs Analyzed | 5 |

## Vulnerability Breakdown by CWE

| CWE | Vulnerability Type | Instances | Severity |
|-----|-------------------|-----------|----------|
| **CWE-502** | Deserialization of Untrusted Data | **226584** | CRITICAL |
| **CWE-79** | Cross-site Scripting (XSS) | **45052** | HIGH |
| **CWE-89** | SQL Injection | **66768** | CRITICAL |
| **CWE-22** | Path Traversal | **13320** | HIGH |
| **CWE-78** | OS Command Injection | **93164** | CRITICAL |

## Detailed Pattern Analysis

### CWE-502: Deserialization of Untrusted Data

- **CWE-502: JSON deserialization into interface{}**: 147520 instances
- **CWE-502: YAML deserialization into interface{}**: 5832 instances
- **CWE-502: JSON decoder into interface{}**: 61120 instances
- **CWE-502: XML deserialization into interface{}**: 3560 instances
- **CWE-502: Using yaml.v2 (vulnerable to custom tags)**: 8552 instances

### CWE-79: Cross-site Scripting (XSS)

- **CWE-79: Potential XSS via HTML template rendering**: 9332 instances
- **CWE-79: Direct write to ResponseWriter (potential XSS)**: 32704 instances
- **CWE-79: Using template.JS (bypasses escaping)**: 3016 instances

### CWE-89: SQL Injection

- **CWE-89: SQL query with string concatenation**: 8640 instances
- **CWE-89: SQL exec with string concatenation**: 30880 instances
- **CWE-89: Raw SQL with string interpolation**: 27248 instances

### CWE-22: Path Traversal

- **CWE-22: filepath.Join with user input**: 5952 instances
- **CWE-22: os.Open with user-controlled path**: 1384 instances
- **CWE-22: File read with constructed path**: 5984 instances

### CWE-78: OS Command Injection

- **CWE-78: exec.Command with user input**: 1292 instances
- **CWE-78: exec.Command with string formatting**: 47744 instances
- **CWE-78: Shell command execution**: 44128 instances

## Fix with go-safeinput

### CWE-502: Safe Deserialization
```go
import "github.com/ravisastryk/go-safeinput/safedeserialize"

var user User
err := safedeserialize.JSON(data, &user)
```

### CWE-79: HTML Sanitization
```go
import "github.com/ravisastryk/go-safeinput/html"

safe := html.Sanitize(userInput, html.ContextBody)
```

### CWE-89: SQL Identifier Sanitization
```go
import "github.com/ravisastryk/go-safeinput/sql"

safeID, err := sql.SanitizeIdentifier(userTable)
```

### CWE-22: Path Sanitization
```go
import "github.com/ravisastryk/go-safeinput/path"

safePath, err := path.Sanitize(userPath)
```

### CWE-78: Shell Argument Sanitization
```go
import "github.com/ravisastryk/go-safeinput"

safeArg, err := safeinput.Sanitize(userArg, safeinput.ContextShellArg)
```

## MITRE CWE References

- [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
- [CWE-79: Cross-site Scripting](https://cwe.mitre.org/data/definitions/79.html)
- [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
- [CWE-22: Path Traversal](https://cwe.mitre.org/data/definitions/22.html)
- [CWE-78: OS Command Injection](https://cwe.mitre.org/data/definitions/78.html)
