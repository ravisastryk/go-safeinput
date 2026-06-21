# Go Ecosystem Vulnerability Impact Report

**Generated:** 2026-06-21 01:02 UTC
**Scanner:** [go-safeinput](https://github.com/ravisastryk/go-safeinput)
**Coverage:** MITRE CWE Top 25 vulnerabilities

## Executive Summary

| Metric | Value |
|--------|-------|
| **Total Vulnerable Instances** | **242824** |
| Total Stars Affected | 84159 |
| Total Forks Affected | 8862 |
| CWEs Analyzed | 5 |

## Vulnerability Breakdown by CWE

| CWE | Vulnerability Type | Instances | Severity |
|-----|-------------------|-----------|----------|
| **CWE-502** | Deserialization of Untrusted Data | **186844** | CRITICAL |
| **CWE-79** | Cross-site Scripting (XSS) | **55980** | HIGH |
| **CWE-89** | SQL Injection | **0** | CRITICAL |
| **CWE-22** | Path Traversal | **0** | HIGH |
| **CWE-78** | OS Command Injection | **0** | CRITICAL |

## Detailed Pattern Analysis

### CWE-502: Deserialization of Untrusted Data

- **CWE-502: JSON deserialization into interface{}**: 112128 instances
- **CWE-502: YAML deserialization into interface{}**: 6448 instances
- **CWE-502: JSON decoder into interface{}**: 56528 instances
- **CWE-502: XML deserialization into interface{}**: 3872 instances
- **CWE-502: Using yaml.v2 (vulnerable to custom tags)**: 7868 instances

### CWE-79: Cross-site Scripting (XSS)

- **CWE-79: Potential XSS via HTML template rendering**: 15884 instances
- **CWE-79: Direct write to ResponseWriter (potential XSS)**: 40096 instances

### CWE-89: SQL Injection



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
