# Go Ecosystem Vulnerability Impact Report

**Generated:** 2026-02-01 00:38 UTC
**Scanner:** [go-safeinput](https://github.com/ravisastryk/go-safeinput)
**Coverage:** MITRE CWE Top 25 vulnerabilities

## Executive Summary

| Metric | Value |
|--------|-------|
| **Total Vulnerable Instances** | **341524** |
| Total Stars Affected | 91634 |
| Total Forks Affected | 10126 |
| CWEs Analyzed | 5 |

## Vulnerability Breakdown by CWE

| CWE | Vulnerability Type | Instances | Severity |
|-----|-------------------|-----------|----------|
| **CWE-502** | Deserialization of Untrusted Data | **165088** | CRITICAL |
| **CWE-79** | Cross-site Scripting (XSS) | **46340** | HIGH |
| **CWE-89** | SQL Injection | **48584** | CRITICAL |
| **CWE-22** | Path Traversal | **11408** | HIGH |
| **CWE-78** | OS Command Injection | **70104** | CRITICAL |

## Detailed Pattern Analysis

### CWE-502: Deserialization of Untrusted Data

- **CWE-502: JSON deserialization into interface{}**: 92672 instances
- **CWE-502: YAML deserialization into interface{}**: 5872 instances
- **CWE-502: JSON decoder into interface{}**: 53248 instances
- **CWE-502: XML deserialization into interface{}**: 3472 instances
- **CWE-502: Using yaml.v2 (vulnerable to custom tags)**: 9824 instances

### CWE-79: Cross-site Scripting (XSS)

- **CWE-79: Potential XSS via HTML template rendering**: 10468 instances
- **CWE-79: Direct write to ResponseWriter (potential XSS)**: 33408 instances
- **CWE-79: Using template.JS (bypasses escaping)**: 2464 instances

### CWE-89: SQL Injection

- **CWE-89: SQL query with string concatenation**: 7896 instances
- **CWE-89: SQL exec with string concatenation**: 22784 instances
- **CWE-89: Raw SQL with string interpolation**: 17904 instances

### CWE-22: Path Traversal

- **CWE-22: filepath.Join with user input**: 3376 instances
- **CWE-22: os.Open with user-controlled path**: 952 instances
- **CWE-22: File read with constructed path**: 7080 instances

### CWE-78: OS Command Injection

- **CWE-78: exec.Command with user input**: 920 instances
- **CWE-78: exec.Command with string formatting**: 37632 instances
- **CWE-78: Shell command execution**: 31552 instances

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
