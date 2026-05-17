# Go Ecosystem Vulnerability Impact Report

**Generated:** 2026-05-17 00:52 UTC
**Scanner:** [go-safeinput](https://github.com/ravisastryk/go-safeinput)
**Coverage:** MITRE CWE Top 25 vulnerabilities

## Executive Summary

| Metric | Value |
|--------|-------|
| **Total Vulnerable Instances** | **321572** |
| Total Stars Affected | 176579 |
| Total Forks Affected | 18601 |
| CWEs Analyzed | 5 |

## Vulnerability Breakdown by CWE

| CWE | Vulnerability Type | Instances | Severity |
|-----|-------------------|-----------|----------|
| **CWE-502** | Deserialization of Untrusted Data | **216912** | CRITICAL |
| **CWE-79** | Cross-site Scripting (XSS) | **44364** | HIGH |
| **CWE-89** | SQL Injection | **60296** | CRITICAL |
| **CWE-22** | Path Traversal | **0** | HIGH |
| **CWE-78** | OS Command Injection | **0** | CRITICAL |

## Detailed Pattern Analysis

### CWE-502: Deserialization of Untrusted Data

- **CWE-502: JSON deserialization into interface{}**: 137664 instances
- **CWE-502: YAML deserialization into interface{}**: 7612 instances
- **CWE-502: JSON decoder into interface{}**: 61760 instances
- **CWE-502: XML deserialization into interface{}**: 3640 instances
- **CWE-502: Using yaml.v2 (vulnerable to custom tags)**: 6236 instances

### CWE-79: Cross-site Scripting (XSS)

- **CWE-79: Potential XSS via HTML template rendering**: 9956 instances
- **CWE-79: Direct write to ResponseWriter (potential XSS)**: 31520 instances
- **CWE-79: Using template.JS (bypasses escaping)**: 2888 instances

### CWE-89: SQL Injection

- **CWE-89: SQL query with string concatenation**: 7896 instances
- **CWE-89: SQL exec with string concatenation**: 26768 instances
- **CWE-89: Raw SQL with string interpolation**: 25632 instances

### CWE-22: Path Traversal



### CWE-78: OS Command Injection



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
