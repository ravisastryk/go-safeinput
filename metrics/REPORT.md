# Go Ecosystem Vulnerability Impact Report

**Generated:** 2026-03-15 00:39 UTC
**Scanner:** [go-safeinput](https://github.com/ravisastryk/go-safeinput)
**Coverage:** MITRE CWE Top 25 vulnerabilities

## Executive Summary

| Metric | Value |
|--------|-------|
| **Total Vulnerable Instances** | **362544** |
| Total Stars Affected | 136032 |
| Total Forks Affected | 14833 |
| CWEs Analyzed | 5 |

## Vulnerability Breakdown by CWE

| CWE | Vulnerability Type | Instances | Severity |
|-----|-------------------|-----------|----------|
| **CWE-502** | Deserialization of Untrusted Data | **172836** | CRITICAL |
| **CWE-79** | Cross-site Scripting (XSS) | **48040** | HIGH |
| **CWE-89** | SQL Injection | **56256** | CRITICAL |
| **CWE-22** | Path Traversal | **13188** | HIGH |
| **CWE-78** | OS Command Injection | **72224** | CRITICAL |

## Detailed Pattern Analysis

### CWE-502: Deserialization of Untrusted Data

- **CWE-502: JSON deserialization into interface{}**: 97280 instances
- **CWE-502: YAML deserialization into interface{}**: 9548 instances
- **CWE-502: JSON decoder into interface{}**: 53376 instances
- **CWE-502: XML deserialization into interface{}**: 3664 instances
- **CWE-502: Using yaml.v2 (vulnerable to custom tags)**: 8968 instances

### CWE-79: Cross-site Scripting (XSS)

- **CWE-79: Potential XSS via HTML template rendering**: 13224 instances
- **CWE-79: Direct write to ResponseWriter (potential XSS)**: 32192 instances
- **CWE-79: Using template.JS (bypasses escaping)**: 2624 instances

### CWE-89: SQL Injection

- **CWE-89: SQL query with string concatenation**: 10112 instances
- **CWE-89: SQL exec with string concatenation**: 24480 instances
- **CWE-89: Raw SQL with string interpolation**: 21664 instances

### CWE-22: Path Traversal

- **CWE-22: filepath.Join with user input**: 3936 instances
- **CWE-22: os.Open with user-controlled path**: 996 instances
- **CWE-22: File read with constructed path**: 8256 instances

### CWE-78: OS Command Injection

- **CWE-78: exec.Command with user input**: 992 instances
- **CWE-78: exec.Command with string formatting**: 37312 instances
- **CWE-78: Shell command execution**: 33920 instances

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
