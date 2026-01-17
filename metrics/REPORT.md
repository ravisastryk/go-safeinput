# CWE-502 Vulnerability Impact Report

**Generated:** 2026-01-17 06:16 UTC
**Scanner:** [go-safeinput](https://github.com/ravisastryk/go-safeinput)

## Summary

| Metric | Value |
|--------|-------|
| Vulnerable Code Instances | 169392 |
| Total Stars Affected | 0 |
| Total Forks Affected | 0 |

## Patterns Detected

| Pattern | Count | Severity |
|---------|-------|----------|
| json-unmarshal-interface | 94720 | HIGH |
| yaml-unmarshal-interface | 6512 | HIGH |
| json-decoder-interface | 52736 | HIGH |
| xml-unmarshal-interface | 3456 | HIGH |
| yaml-v2-import | 11968 | MEDIUM |

## Fix with go-safeinput

```go
import "github.com/ravisastryk/go-safeinput/safedeserialize"

var user User
err := safedeserialize.JSON(data, &user)
```

## Links

- [CWE-502](https://cwe.mitre.org/data/definitions/502.html)
- [Semgrep Rule](https://github.com/semgrep/semgrep-rules)
