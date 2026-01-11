// Package safedeserialize provides secure deserialization utilities for Go
// that mitigate CWE-502: Deserialization of Untrusted Data.
//
// # Overview
//
// This package prevents common deserialization vulnerabilities by:
//   - Rejecting interface{} as deserialization targets
//   - Enforcing size limits on input data
//   - Limiting nesting depth to prevent stack exhaustion
//   - Providing type whitelisting capabilities
//   - Offering strict parsing modes
//
// # Basic Usage
//
// The simplest way to use this package is with the format-specific functions:
//
//	type User struct {
//	    ID    int    `json:"id"`
//	    Name  string `json:"name"`
//	    Email string `json:"email"`
//	}
//
//	var user User
//	err := safedeserialize.JSON(data, &user)
//
// # Options
//
// All functions accept optional configuration:
//
//	err := safedeserialize.JSON(data, &user,
//	    safedeserialize.WithMaxSize(1<<16),    // 64KB limit
//	    safedeserialize.WithMaxDepth(10),      // 10 levels max
//	    safedeserialize.WithStrictMode(true),  // Reject unknown fields
//	)
//
// # Type Registry
//
// For additional security, you can whitelist allowed types:
//
//	registry := safedeserialize.NewTypeRegistry()
//	registry.Register(User{})
//	registry.Register(Config{})
//
//	err := safedeserialize.JSON(data, &user, registry.Option())
//
// # Decoder
//
// For repeated operations with the same options, use a Decoder:
//
//	decoder := safedeserialize.NewDecoder(
//	    safedeserialize.WithMaxSize(1<<20),
//	    safedeserialize.WithStrictMode(true),
//	)
//
//	decoder.JSON(data1, &obj1)
//	decoder.JSON(data2, &obj2)
//
// # HTTP Integration
//
// Use with HTTP handlers:
//
//	func Handler(w http.ResponseWriter, r *http.Request) {
//	    var req Request
//	    err := safedeserialize.JSONReader(r.Body, &req,
//	        safedeserialize.WithMaxSize(1<<16),
//	    )
//	    if err != nil {
//	        http.Error(w, "Invalid request", http.StatusBadRequest)
//	        return
//	    }
//	    // Process request...
//	}
//
// # Security
//
// This package protects against:
//   - Arbitrary type instantiation via interface{}
//   - Memory exhaustion via oversized payloads
//   - Stack exhaustion via deeply nested structures
//   - Unexpected data via unknown fields (strict mode)
//
// # References
//
//   - CWE-502: https://cwe.mitre.org/data/definitions/502.html
//   - Repository: https://github.com/ravisastryk/go-safeinput
package safedeserialize
