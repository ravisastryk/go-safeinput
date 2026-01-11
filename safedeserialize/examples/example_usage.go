// Package main demonstrates usage of the safedeserialize package.
//
// This file contains examples showing:
// - Basic JSON/YAML/XML deserialization
// - Using options for custom limits
// - Type registries for whitelisting
// - HTTP handler integration
// - Configuration file loading
//
// Run: go run example_usage.go
package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/ravisastryk/go-safeinput/safedeserialize"
)

// Example data structures
type User struct {
	ID       int      `json:"id" yaml:"id"`
	Username string   `json:"username" yaml:"username"`
	Email    string   `json:"email" yaml:"email"`
	Roles    []string `json:"roles" yaml:"roles"`
}

type APIRequest struct {
	Action  string `json:"action"`
	Payload struct {
		UserID int    `json:"user_id"`
		Data   string `json:"data"`
	} `json:"payload"`
}

type AppConfig struct {
	Server struct {
		Host         string `yaml:"host"`
		Port         int    `yaml:"port"`
		ReadTimeout  int    `yaml:"read_timeout"`
		WriteTimeout int    `yaml:"write_timeout"`
	} `yaml:"server"`
	Database struct {
		Host     string `yaml:"host"`
		Port     int    `yaml:"port"`
		Name     string `yaml:"name"`
		User     string `yaml:"user"`
		Password string `yaml:"password"`
		MaxConns int    `yaml:"max_conns"`
	} `yaml:"database"`
	Features []string `yaml:"features"`
}

// Example 1: Basic JSON deserialization
func example1BasicJSON() {
	fmt.Println("=== Example 1: Basic JSON ===")

	jsonData := []byte(`{
		"id": 1,
		"username": "johndoe",
		"email": "john@example.com",
		"roles": ["admin", "user"]
	}`)

	var user User
	err := safedeserialize.JSON(jsonData, &user)
	if err != nil {
		log.Printf("Error: %v", err)
		return
	}

	fmt.Printf("User: %+v\n\n", user)
}

// Example 2: YAML configuration loading
func example2YAMLConfig() {
	fmt.Println("=== Example 2: YAML Config ===")

	yamlData := []byte(`
server:
  host: localhost
  port: 8080
  read_timeout: 30
  write_timeout: 30
database:
  host: db.example.com
  port: 5432
  name: myapp
  user: appuser
  password: secret
  max_conns: 20
features:
  - auth
  - logging
  - metrics
`)

	var config AppConfig
	err := safedeserialize.YAML(yamlData, &config)
	if err != nil {
		log.Printf("Error: %v", err)
		return
	}

	fmt.Printf("Server: %s:%d\n", config.Server.Host, config.Server.Port)
	fmt.Printf("Database: %s@%s\n", config.Database.User, config.Database.Host)
	fmt.Printf("Features: %v\n\n", config.Features)
}

// Example 3: Custom size and depth limits
func example3CustomLimits() {
	fmt.Println("=== Example 3: Custom Limits ===")

	jsonData := []byte(`{"id": 1, "username": "test", "email": "test@test.com", "roles": []}`)

	var user User
	err := safedeserialize.JSON(jsonData, &user,
		safedeserialize.WithMaxSize(1<<16),   // 64KB limit
		safedeserialize.WithMaxDepth(10),     // 10 levels max
		safedeserialize.WithStrictMode(true), // Reject unknown fields
	)
	if err != nil {
		log.Printf("Error: %v", err)
		return
	}

	fmt.Printf("User: %+v\n\n", user)
}

// Example 4: Type registry for whitelisting
func example4TypeRegistry() {
	fmt.Println("=== Example 4: Type Registry ===")

	// Create registry and register allowed types
	registry := safedeserialize.NewTypeRegistry()
	registry.Register(User{})
	registry.Register(APIRequest{})

	fmt.Printf("Registered types: %v\n", registry.TypeNames())

	// Use registry for validation
	jsonData := []byte(`{"id": 1, "username": "test", "email": "test@test.com", "roles": []}`)

	var user User
	err := safedeserialize.JSON(jsonData, &user, registry.Option())
	if err != nil {
		log.Printf("Error: %v", err)
		return
	}

	fmt.Printf("User: %+v\n\n", user)
}

// Example 5: Reusable decoder
func example5Decoder() {
	fmt.Println("=== Example 5: Reusable Decoder ===")

	// Create decoder with preset options
	decoder := safedeserialize.NewDecoder(
		safedeserialize.WithMaxSize(1<<20),
		safedeserialize.WithMaxDepth(16),
		safedeserialize.WithStrictMode(true),
	)

	// Decode multiple messages
	messages := [][]byte{
		[]byte(`{"id": 1, "username": "alice", "email": "alice@test.com", "roles": ["user"]}`),
		[]byte(`{"id": 2, "username": "bob", "email": "bob@test.com", "roles": ["admin"]}`),
		[]byte(`{"id": 3, "username": "carol", "email": "carol@test.com", "roles": ["user", "moderator"]}`),
	}

	for i, msg := range messages {
		var user User
		if err := decoder.JSON(msg, &user); err != nil {
			log.Printf("Message %d error: %v", i, err)
			continue
		}
		fmt.Printf("Message %d: %+v\n", i, user)
	}
	fmt.Println()
}

// Example 6: HTTP handler integration
func example6HTTPHandler() {
	fmt.Println("=== Example 6: HTTP Handler ===")

	// Create a sample handler
	handler := func(w http.ResponseWriter, r *http.Request) {
		var req APIRequest

		err := safedeserialize.JSONReader(r.Body, &req,
			safedeserialize.WithMaxSize(1<<16), // 64KB max request
		)
		if err != nil {
			http.Error(w, fmt.Sprintf("Invalid request: %v", err), http.StatusBadRequest)
			return
		}

		// Process request...
		// Sanitize user input before logging to prevent log injection
		action := strings.ReplaceAll(strings.ReplaceAll(req.Action, "\n", ""), "\r", "")
		fmt.Printf("Action: %q, UserID: %d\n", action, req.Payload.UserID)
		w.WriteHeader(http.StatusOK)
	}

	// Simulate a request (in real code, this would be http.ListenAndServe)
	fmt.Printf("Handler function created: %T\n\n", handler)
}

// Example 7: Error handling
func example7ErrorHandling() {
	fmt.Println("=== Example 7: Error Handling ===")

	// Test various error conditions
	testCases := []struct {
		name string
		data []byte
		test func([]byte) error
	}{
		{
			name: "Empty data",
			data: []byte{},
			test: func(d []byte) error {
				var u User
				return safedeserialize.JSON(d, &u)
			},
		},
		{
			name: "Oversized data",
			data: make([]byte, 100),
			test: func(d []byte) error {
				var u User
				return safedeserialize.JSON(d, &u, safedeserialize.WithMaxSize(10))
			},
		},
		{
			name: "Interface target",
			data: []byte(`{"key": "value"}`),
			test: func(d []byte) error {
				var target interface{}
				return safedeserialize.JSON(d, &target)
			},
		},
		{
			name: "Map interface target",
			data: []byte(`{"key": "value"}`),
			test: func(d []byte) error {
				var target map[string]interface{}
				return safedeserialize.JSON(d, &target)
			},
		},
	}

	for _, tc := range testCases {
		err := tc.test(tc.data)
		if err != nil {
			fmt.Printf("%s: %v\n", tc.name, err)
		} else {
			fmt.Printf("%s: no error (unexpected)\n", tc.name)
		}
	}
	fmt.Println()
}

// Example 8: Loading config from file
func example8ConfigFile() {
	fmt.Println("=== Example 8: Config File Loading ===")

	// Create a temporary config file
	configContent := []byte(`
server:
  host: 0.0.0.0
  port: 3000
  read_timeout: 60
  write_timeout: 60
database:
  host: localhost
  port: 5432
  name: testdb
  user: testuser
  password: testpass
  max_conns: 5
features:
  - api
  - websocket
`)

	tmpFile := "/tmp/test_config.yaml"
	if err := os.WriteFile(tmpFile, configContent, 0600); err != nil {
		log.Printf("Failed to write temp file: %v", err)
		return
	}
	defer func() {
		if err := os.Remove(tmpFile); err != nil {
			log.Printf("Failed to remove temp file: %v", err)
		}
	}()

	// Load and parse the config
	data, err := os.ReadFile(tmpFile)
	if err != nil {
		log.Printf("Failed to read file: %v", err)
		return
	}

	var config AppConfig
	err = safedeserialize.YAML(data, &config,
		safedeserialize.WithMaxSize(1<<16), // 64KB max config size
	)
	if err != nil {
		log.Printf("Failed to parse config: %v", err)
		return
	}

	fmt.Printf("Loaded config:\n")
	fmt.Printf("  Server: %s:%d\n", config.Server.Host, config.Server.Port)
	fmt.Printf("  Database: %s:%d/%s\n", config.Database.Host, config.Database.Port, config.Database.Name)
	fmt.Printf("  Features: %v\n\n", config.Features)
}

func main() {
	fmt.Println("safedeserialize Examples")
	fmt.Println("========================")
	fmt.Println()

	example1BasicJSON()
	example2YAMLConfig()
	example3CustomLimits()
	example4TypeRegistry()
	example5Decoder()
	example6HTTPHandler()
	example7ErrorHandling()
	example8ConfigFile()

	fmt.Println("All examples completed.")
}
