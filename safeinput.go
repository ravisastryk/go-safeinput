// Package safeinput provides context-aware input sanitization for Go applications.
// It addresses MITRE CWE Top 25 injection vulnerabilities including:
//   - CWE-79: Cross-site Scripting (XSS)
//   - CWE-89: SQL Injection
//   - CWE-22: Path Traversal
//   - CWE-78: OS Command Injection
package safeinput

import (
	"strings"

	"github.com/ravisastryk/go-safeinput/html"
	"github.com/ravisastryk/go-safeinput/path"
	"github.com/ravisastryk/go-safeinput/sql"
)

// Context defines the output context for sanitization.
type Context int

const (
	// HTMLBody sanitizes for HTML body content (CWE-79).
	HTMLBody Context = iota
	// HTMLAttribute sanitizes for HTML attribute values (CWE-79).
	HTMLAttribute
	// SQLIdentifier sanitizes SQL identifiers (CWE-89).
	SQLIdentifier
	// SQLValue validates values before queries (CWE-89).
	SQLValue
	// FilePath sanitizes filesystem paths (CWE-22).
	FilePath
	// URLPath sanitizes URL path components.
	URLPath
	// URLQuery sanitizes URL query parameters.
	URLQuery
	// ShellArg sanitizes shell command arguments (CWE-78).
	ShellArg
)

// String returns a human-readable name for the context.
func (c Context) String() string {
	names := []string{
		"HTMLBody", "HTMLAttribute", "SQLIdentifier", "SQLValue",
		"FilePath", "URLPath", "URLQuery", "ShellArg",
	}
	if int(c) >= 0 && int(c) < len(names) {
		return names[c]
	}
	return "Unknown"
}

// Sanitizer provides the main sanitization interface.
type Sanitizer struct {
	html   *html.Sanitizer
	sql    *sql.Sanitizer
	path   *path.Sanitizer
	config Config
}

// Config holds sanitizer configuration options.
type Config struct {
	MaxInputLength  int
	AllowedHTMLTags []string
	BasePath        string
	StrictMode      bool
	StripNullBytes  bool
}

// New creates a new Sanitizer with the given configuration.
func New(cfg Config) *Sanitizer {
	if cfg.MaxInputLength == 0 {
		cfg.MaxInputLength = 10000
	}
	return &Sanitizer{
		html:   html.New(cfg.AllowedHTMLTags),
		sql:    sql.New(),
		path:   path.New(cfg.BasePath),
		config: cfg,
	}
}

// Default returns a Sanitizer with secure default settings.
func Default() *Sanitizer {
	return New(Config{
		MaxInputLength: 10000,
		StrictMode:     true,
		StripNullBytes: true,
	})
}

// Sanitize processes input for the specified context.
func (s *Sanitizer) Sanitize(input string, ctx Context) (string, error) {
	if len(input) > s.config.MaxInputLength {
		return "", ErrInputTooLong
	}

	if strings.ContainsRune(input, 0) {
		if s.config.StripNullBytes {
			input = StripNullBytes(input)
		} else {
			return "", ErrNullByte
		}
	}

	switch ctx {
	case HTMLBody:
		return s.html.SanitizeBody(input), nil
	case HTMLAttribute:
		return s.html.SanitizeAttribute(input), nil
	case SQLIdentifier:
		return s.sql.SanitizeIdentifier(input)
	case SQLValue:
		return s.sql.ValidateValue(input)
	case FilePath:
		return s.path.Sanitize(input)
	case URLPath, URLQuery:
		return s.html.SanitizeAttribute(input), nil
	case ShellArg:
		return SanitizeShellArg(input), nil
	default:
		return "", ErrUnknownContext
	}
}

// MustSanitize panics on error.
func (s *Sanitizer) MustSanitize(input string, ctx Context) string {
	result, err := s.Sanitize(input, ctx)
	if err != nil {
		panic(err)
	}
	return result
}

// IsValid checks if input is valid for the given context.
func (s *Sanitizer) IsValid(input string, ctx Context) bool {
	_, err := s.Sanitize(input, ctx)
	return err == nil
}

// GetConfig returns a copy of the configuration.
func (s *Sanitizer) GetConfig() Config {
	return s.config
}

// StripNullBytes removes null bytes from a string.
func StripNullBytes(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != 0 {
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// SanitizeShellArg sanitizes shell command arguments (CWE-78).
// Only allows alphanumeric characters, dash, underscore, period, and forward slash.
func SanitizeShellArg(input string) string {
	var b strings.Builder
	b.Grow(len(input))
	for _, r := range input {
		if isAllowedShellChar(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func isAllowedShellChar(r rune) bool {
	return (r >= 'a' && r <= 'z') ||
		(r >= 'A' && r <= 'Z') ||
		(r >= '0' && r <= '9') ||
		r == '-' || r == '_' || r == '.' || r == '/'
}
