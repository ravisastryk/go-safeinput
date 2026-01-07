// Package sql provides SQL injection prevention (CWE-89).
package sql

import (
	"errors"
	"regexp"
	"strings"
)

// Errors returned by the SQL sanitizer.
var (
	ErrInvalidIdentifier = errors.New("invalid SQL identifier")
	ErrReservedWord      = errors.New("SQL reserved word not allowed")
	ErrSuspiciousPattern = errors.New("suspicious SQL pattern detected")
	ErrIdentifierTooLong = errors.New("SQL identifier exceeds maximum length")
)

var reservedWords = map[string]bool{
	"select": true, "insert": true, "update": true, "delete": true,
	"drop": true, "truncate": true, "alter": true, "create": true,
	"exec": true, "execute": true, "union": true, "or": true,
	"and": true, "where": true, "from": true, "into": true,
	"values": true, "set": true, "null": true, "table": true,
	"database": true, "schema": true, "grant": true, "revoke": true,
}

var dangerousPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(\bor\b|\band\b)\s*[\d'"]+\s*=\s*[\d'"]+`),
	regexp.MustCompile(`(?i)['"]?\s*(\bor\b|\band\b)\s*['"]?`),
	regexp.MustCompile(`--`),
	regexp.MustCompile(`/\*`),
	regexp.MustCompile(`\*/`),
	regexp.MustCompile(`(?i);\s*(drop|delete|truncate|alter|exec|insert|update|select)`),
	regexp.MustCompile(`(?i)\bunion\b.*\bselect\b`),
	regexp.MustCompile(`['"]?\s*;\s*`),
	regexp.MustCompile(`(?i)0x[0-9a-f]+`),
	regexp.MustCompile(`(?i)\bchar\s*\(`),
	regexp.MustCompile(`(?i)\b(benchmark|sleep|waitfor|delay)\b`),
}

var validIdentifier = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

// Sanitizer provides SQL sanitization.
type Sanitizer struct {
	maxLen int
	strict bool
}

// New creates a SQL Sanitizer.
func New() *Sanitizer {
	return &Sanitizer{maxLen: 128, strict: true}
}

// SanitizeIdentifier validates a SQL identifier.
func (s *Sanitizer) SanitizeIdentifier(input string) (string, error) {
	if len(input) > s.maxLen {
		return "", ErrIdentifierTooLong
	}
	if len(input) == 0 || !validIdentifier.MatchString(input) {
		return "", ErrInvalidIdentifier
	}
	if s.strict && reservedWords[strings.ToLower(input)] {
		return "", ErrReservedWord
	}
	return input, nil
}

// ValidateValue checks for suspicious SQL patterns.
func (s *Sanitizer) ValidateValue(input string) (string, error) {
	for _, p := range dangerousPatterns {
		if p.MatchString(input) {
			return "", ErrSuspiciousPattern
		}
	}
	return input, nil
}

// QuoteStyle represents SQL quoting styles.
type QuoteStyle int

const (
	// QuoteStyleNone represents no quoting.
	QuoteStyleNone QuoteStyle = iota
	// QuoteStyleStandard represents standard SQL double-quote quoting.
	QuoteStyleStandard
	// QuoteStyleMySQL represents MySQL backtick quoting.
	QuoteStyleMySQL
	// QuoteStylePostgres represents PostgreSQL double-quote quoting.
	QuoteStylePostgres
	// QuoteStyleSQLServer represents SQL Server bracket quoting.
	QuoteStyleSQLServer
)

// QuoteIdentifier safely quotes a SQL identifier.
func (s *Sanitizer) QuoteIdentifier(input string, style QuoteStyle) (string, error) {
	sanitized, err := s.SanitizeIdentifier(input)
	if err != nil {
		return "", err
	}
	switch style {
	case QuoteStyleMySQL:
		return "`" + sanitized + "`", nil
	case QuoteStylePostgres, QuoteStyleStandard:
		return `"` + sanitized + `"`, nil
	case QuoteStyleSQLServer:
		return "[" + sanitized + "]", nil
	default:
		return sanitized, nil
	}
}

// SetStrictMode enables/disables strict mode.
func (s *Sanitizer) SetStrictMode(strict bool) { s.strict = strict }

// SetMaxIdentifierLength sets max identifier length.
func (s *Sanitizer) SetMaxIdentifierLength(n int) { s.maxLen = n }

// StrictMode returns strict mode status.
func (s *Sanitizer) StrictMode() bool { return s.strict }

// MaxIdentifierLength returns max length.
func (s *Sanitizer) MaxIdentifierLength() int { return s.maxLen }

// IsReservedWord checks if word is reserved.
func IsReservedWord(word string) bool { return reservedWords[strings.ToLower(word)] }
