# safedeserialize

Secure deserialization library for Go that mitigates CWE-502 vulnerabilities.

## Overview

`safedeserialize` prevents common deserialization attacks by:

- Rejecting `interface{}` as deserialization targets
- Enforcing size limits on input data
- Limiting nesting depth to prevent stack exhaustion
- Providing type whitelisting capabilities
- Offering strict parsing modes that reject unknown fields

## Installation

```bash
go get github.com/ravisastryk/go-safeinput
```

## Quick Start

```go
import "github.com/ravisastryk/go-safeinput/safedeserialize"

type User struct {
    ID    int    `json:"id"`
    Name  string `json:"name"`
    Email string `json:"email"`
}

// Basic usage
var user User
err := safedeserialize.JSON(data, &user)

// With options
err := safedeserialize.JSON(data, &user,
    safedeserialize.WithMaxSize(1<<16),
    safedeserialize.WithMaxDepth(16),
    safedeserialize.WithStrictMode(true),
)
```

## Supported Formats

| Format | Functions |
|--------|-----------|
| JSON | `JSON()`, `JSONReader()` |
| YAML | `YAML()`, `YAMLReader()` |
| XML | `XML()`, `XMLReader()` |
| Gob | `Gob()`, `GobReader()` |

## Security Features

### 1. Blocks interface{} targets

```go
// This will return ErrInterfaceTarget
var data interface{}
err := safedeserialize.JSON(input, &data)

// This is the correct approach
var user User
err := safedeserialize.JSON(input, &user)
```

### 2. Blocks map[string]interface{}

```go
// This will return ErrMapInterface
var data map[string]interface{}
err := safedeserialize.JSON(input, &data)

// Allow explicitly if needed (not recommended)
err := safedeserialize.JSON(input, &data,
    safedeserialize.WithAllowMapStringInterface(true),
)
```

### 3. Size limits

```go
// Default: 1MB
// Custom: 64KB
err := safedeserialize.JSON(data, &user,
    safedeserialize.WithMaxSize(1<<16),
)
```

### 4. Depth limits

```go
// Default: 32 levels
// Custom: 10 levels
err := safedeserialize.JSON(data, &user,
    safedeserialize.WithMaxDepth(10),
)
```

### 5. Type whitelisting

```go
// Only allow specific types
registry := safedeserialize.NewTypeRegistry()
registry.Register(User{})
registry.Register(Config{})

err := safedeserialize.JSON(data, &user, registry.Option())
```

### 6. Strict mode

Strict mode (enabled by default):
- JSON: Rejects unknown fields
- YAML: Rejects unknown fields
- Validates struct fields for interface{} types

```go
// Disable strict mode (not recommended)
err := safedeserialize.JSON(data, &user,
    safedeserialize.WithStrictMode(false),
)
```

## API Reference

### Functions

```go
// JSON deserialization
func JSON(data []byte, v interface{}, opts ...Option) error
func JSONReader(r io.Reader, v interface{}, opts ...Option) error

// YAML deserialization
func YAML(data []byte, v interface{}, opts ...Option) error
func YAMLReader(r io.Reader, v interface{}, opts ...Option) error

// XML deserialization
func XML(data []byte, v interface{}, opts ...Option) error
func XMLReader(r io.Reader, v interface{}, opts ...Option) error

// Gob deserialization
func Gob(data []byte, v interface{}, opts ...Option) error
func GobReader(r io.Reader, v interface{}, opts ...Option) error
```

### Options

```go
WithMaxSize(size int64)              // Set max data size
WithMaxDepth(depth int)              // Set max nesting depth
WithAllowedTypes(types ...string)    // Set type whitelist
WithStrictMode(strict bool)          // Enable/disable strict parsing
WithAllowMapStringInterface(bool)    // Allow map[string]interface{}
WithAllowSliceInterface(bool)        // Allow []interface{}
```

### Decoder (Reusable)

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

### TypeRegistry

```go
registry := safedeserialize.NewTypeRegistry()
registry.Register(User{})
registry.Register(&Config{})
registry.RegisterMultiple(Type1{}, Type2{}, Type3{})

// Check registration
if registry.IsRegistered(User{}) { ... }

// Get type names
names := registry.TypeNames()

// Use as option
err := safedeserialize.JSON(data, &user, registry.Option())
```

### Errors

```go
var (
    ErrDataTooLarge     // Data exceeds MaxSize
    ErrNilTarget        // Target is nil
    ErrNotPointer       // Target is not a pointer
    ErrInterfaceTarget  // Target is interface{}
    ErrMapInterface     // Target is map[string]interface{}
    ErrSliceInterface   // Target is []interface{}
    ErrTypeNotAllowed   // Type not in allowed list
    ErrMaxDepthExceeded // Nesting depth exceeded
    ErrEmptyData        // Input data is empty
)
```

## HTTP Handler Example

```go
func CreateUser(w http.ResponseWriter, r *http.Request) {
    var req CreateUserRequest
    
    err := safedeserialize.JSONReader(r.Body, &req,
        safedeserialize.WithMaxSize(1<<16), // 64KB max
    )
    if err != nil {
        http.Error(w, "Invalid request", http.StatusBadRequest)
        return
    }
    
    // Process request...
}
```

## Configuration Loading Example

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

## Defaults

| Setting | Default Value |
|---------|---------------|
| MaxSize | 1MB (1 << 20) |
| MaxDepth | 32 |
| StrictMode | true |
| AllowMapStringInterface | false |
| AllowSliceInterface | false |

## Why This Matters

CWE-502 (Deserialization of Untrusted Data) can lead to:

- Remote Code Execution (RCE)
- Denial of Service (DoS)
- Authentication bypass
- Data manipulation

Common vulnerable patterns in Go:

```go
// DANGEROUS - allows arbitrary structures
var data interface{}
json.Unmarshal(untrustedInput, &data)

// DANGEROUS - no size limit
body, _ := io.ReadAll(r.Body)
json.Unmarshal(body, &config)

// DANGEROUS - yaml.v2 custom tags
yaml.Unmarshal(data, &config)
```

## Running Tests

```bash
go test -v ./safedeserialize/...
go test -bench=. ./safedeserialize/...
```

## License

MIT License

## References

- CWE-502: https://cwe.mitre.org/data/definitions/502.html
- OWASP Deserialization: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/16-Testing_for_HTTP_Incoming_Requests

## Author

Ravi Sastry Kadali ([@ravisastryk](https://github.com/ravisastryk))
