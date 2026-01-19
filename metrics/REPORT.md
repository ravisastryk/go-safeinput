# Go Ecosystem Vulnerability Impact Report

**Generated:** 2026-01-19 05:21 UTC
**Scanner:** [go-safeinput](https://github.com/ravisastryk/go-safeinput)
**Coverage:** MITRE CWE Top 25 vulnerabilities

## Executive Summary

| Metric | Value |
|--------|-------|
| **Total Vulnerable Instances** | **347872** |
| Total Stars Affected | 84998 |
| Total Forks Affected | 8367 |
| CWEs Analyzed | 5 |

## Vulnerability Breakdown by CWE

| CWE | Vulnerability Type | Instances | Severity |
|-----|-------------------|-----------|----------|
| **CWE-502** | Deserialization of Untrusted Data | **166240** | CRITICAL |
| **CWE-79** | Cross-site Scripting (XSS) | **46156** | HIGH |
| **CWE-89** | SQL Injection | **54904** | CRITICAL |
| **CWE-22** | Path Traversal | **11408** | HIGH |
| **CWE-78** | OS Command Injection | **69164** | CRITICAL |

## Detailed Pattern Analysis

### CWE-502: Deserialization of Untrusted Data

- **CWE-502: JSON deserialization into interface{}**: 92160 instances
- **CWE-502: YAML deserialization into interface{}**: 6512 instances
- **CWE-502: JSON decoder into interface{}**: 52736 instances
- **CWE-502: XML deserialization into interface{}**: 3456 instances
- **CWE-502: Using yaml.v2 (vulnerable to custom tags)**: 11376 instances

### CWE-79: Cross-site Scripting (XSS)

- **CWE-79: Potential XSS via HTML template rendering**: 10444 instances
- **CWE-79: Direct write to ResponseWriter (potential XSS)**: 33408 instances
- **CWE-79: Using template.JS (bypasses escaping)**: 2304 instances

### CWE-89: SQL Injection

- **CWE-89: SQL query with string concatenation**: 7544 instances
- **CWE-89: SQL exec with string concatenation**: 28992 instances
- **CWE-89: Raw SQL with string interpolation**: 18368 instances

### CWE-22: Path Traversal

- **CWE-22: filepath.Join with user input**: 3232 instances
- **CWE-22: os.Open with user-controlled path**: 952 instances
- **CWE-22: File read with constructed path**: 7224 instances

### CWE-78: OS Command Injection

- **CWE-78: exec.Command with user input**: 876 instances
- **CWE-78: exec.Command with string formatting**: 37632 instances
- **CWE-78: Shell command execution**: 30656 instances

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
