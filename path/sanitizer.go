// Package path provides path traversal prevention (CWE-22).
package path

import (
	"errors"
	"path/filepath"
	"strings"
)

// Errors returned by the path sanitizer.
var (
	ErrPathTraversal    = errors.New("path traversal detected")
	ErrAbsolutePath     = errors.New("absolute paths not allowed")
	ErrInvalidCharacter = errors.New("invalid character in path")
	ErrOutsideBasePath  = errors.New("path escapes base directory")
	ErrEmptyPath        = errors.New("empty path not allowed")
)

var blockedSequences = []string{
	"..", "../", "..\\", "..%2f", "..%5c", "%2e%2e",
	"....//", "..../", ".%2e", "%2e.", "..%252f", "..%255c",
}

// Sanitizer provides path sanitization.
type Sanitizer struct {
	basePath      string
	allowAbsolute bool
}

// New creates a path Sanitizer.
func New(basePath string) *Sanitizer {
	return &Sanitizer{basePath: basePath}
}

// validateCharacters checks for invalid characters.
func validateCharacters(input string) error {
	if strings.ContainsRune(input, 0) {
		return ErrInvalidCharacter
	}
	for _, r := range input {
		if r < 32 && r != '\t' {
			return ErrInvalidCharacter
		}
		if r == 127 {
			return ErrInvalidCharacter
		}
	}
	return nil
}

// checkTraversalSequences checks for path traversal patterns.
func checkTraversalSequences(normalized string) error {
	lower := strings.ToLower(normalized)
	for _, seq := range blockedSequences {
		if strings.Contains(lower, seq) {
			return ErrPathTraversal
		}
	}
	return nil
}

// checkTraversalPaths checks for traversal in the cleaned path.
func checkTraversalPaths(cleaned string) error {
	if strings.HasPrefix(cleaned, "..") ||
		strings.Contains(cleaned, string(filepath.Separator)+"..") {
		return ErrPathTraversal
	}
	return nil
}

// verifyWithinBasePath verifies the path is within the base directory.
func (s *Sanitizer) verifyWithinBasePath(cleaned string) error {
	absBase, err := filepath.Abs(s.basePath)
	if err != nil {
		return err
	}
	absResult, err := filepath.Abs(filepath.Join(s.basePath, cleaned))
	if err != nil {
		return err
	}
	if !strings.HasPrefix(absResult, absBase+string(filepath.Separator)) &&
		absResult != absBase {
		return ErrOutsideBasePath
	}
	return nil
}

// Sanitize validates and cleans a file path.
func (s *Sanitizer) Sanitize(input string) (string, error) {
	if input == "" {
		return "", ErrEmptyPath
	}

	if err := validateCharacters(input); err != nil {
		return "", err
	}

	normalized := filepath.FromSlash(input)

	if err := checkTraversalSequences(normalized); err != nil {
		return "", err
	}

	cleaned := filepath.Clean(normalized)

	if !s.allowAbsolute && filepath.IsAbs(cleaned) {
		return "", ErrAbsolutePath
	}

	if err := checkTraversalPaths(cleaned); err != nil {
		return "", err
	}

	if s.basePath != "" {
		if err := s.verifyWithinBasePath(cleaned); err != nil {
			return "", err
		}
	}

	return cleaned, nil
}

// Join safely joins path components.
func (s *Sanitizer) Join(base string, components ...string) (string, error) {
	result := base
	for _, comp := range components {
		sanitized, err := s.Sanitize(comp)
		if err != nil {
			return "", err
		}
		result = filepath.Join(result, sanitized)
	}
	return result, nil
}

// SetAllowAbsolute configures whether absolute paths are allowed.
func (s *Sanitizer) SetAllowAbsolute(allow bool) {
	s.allowAbsolute = allow
}

// BasePath returns the configured base path.
func (s *Sanitizer) BasePath() string {
	return s.basePath
}

// AllowAbsolute returns whether absolute paths are allowed.
func (s *Sanitizer) AllowAbsolute() bool {
	return s.allowAbsolute
}

// IsTraversal checks if a path contains traversal sequences.
func IsTraversal(input string) bool {
	lower := strings.ToLower(input)
	for _, seq := range blockedSequences {
		if strings.Contains(lower, seq) {
			return true
		}
	}
	return false
}
