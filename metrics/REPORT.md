# Go Ecosystem Vulnerability Impact Report

**Generated:** 2026-01-25 00:31 UTC
**Scanner:** [go-safeinput](https://github.com/ravisastryk/go-safeinput)
**Coverage:** MITRE CWE Top 25 vulnerabilities

## Executive Summary

| Metric | Value |
|--------|-------|
| **Total Vulnerable Instances** | **342024** |
| Total Stars Affected | 84626 |
| Total Forks Affected | 8433 |
| CWEs Analyzed | 5 |

## Vulnerability Breakdown by CWE

| CWE | Vulnerability Type | Instances | Severity |
|-----|-------------------|-----------|----------|
| **CWE-502** | Deserialization of Untrusted Data | **157544** | CRITICAL |
| **CWE-79** | Cross-site Scripting (XSS) | **46492** | HIGH |
| **CWE-89** | SQL Injection | **53944** | CRITICAL |
| **CWE-22** | Path Traversal | **12792** | HIGH |
| **CWE-78** | OS Command Injection | **71252** | CRITICAL |

## Detailed Pattern Analysis

### CWE-502: Deserialization of Untrusted Data

- **CWE-502: JSON deserialization into interface{}**: 82944 instances
- **CWE-502: YAML deserialization into interface{}**: 5448 instances
- **CWE-502: JSON decoder into interface{}**: 53760 instances
- **CWE-502: XML deserialization into interface{}**: 3456 instances
- **CWE-502: Using yaml.v2 (vulnerable to custom tags)**: 11936 instances

### CWE-79: Cross-site Scripting (XSS)

- **CWE-79: Potential XSS via HTML template rendering**: 10764 instances
- **CWE-79: Direct write to ResponseWriter (potential XSS)**: 33408 instances
- **CWE-79: Using template.JS (bypasses escaping)**: 2320 instances

### CWE-89: SQL Injection

- **CWE-89: SQL query with string concatenation**: 8184 instances
- **CWE-89: SQL exec with string concatenation**: 27776 instances
- **CWE-89: Raw SQL with string interpolation**: 17984 instances

### CWE-22: Path Traversal

- **CWE-22: filepath.Join with user input**: 3424 instances
- **CWE-22: os.Open with user-controlled path**: 952 instances
- **CWE-22: File read with constructed path**: 8416 instances

### CWE-78: OS Command Injection

- **CWE-78: exec.Command with user input**: 916 instances
- **CWE-78: exec.Command with string formatting**: 37632 instances
- **CWE-78: Shell command execution**: 32704 instances

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
