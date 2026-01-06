// Package html provides XSS prevention (CWE-79) using pure Go.
package html

import (
	"html"
	"regexp"
	"strings"
)

var (
	tagPattern    = regexp.MustCompile(`<[^>]*>`)
	scriptPattern = regexp.MustCompile(`(?i)<script[\s\S]*?</script>`)
	stylePattern  = regexp.MustCompile(`(?i)<style[\s\S]*?</style>`)
	iframePattern = regexp.MustCompile(`(?i)<iframe[\s\S]*?</iframe>`)
	objectPattern = regexp.MustCompile(`(?i)<object[\s\S]*?</object>`)
	embedPattern  = regexp.MustCompile(`(?i)<embed[\s\S]*?</embed>`)
	linkPattern   = regexp.MustCompile(`(?i)<link[^>]*>`)
	metaPattern   = regexp.MustCompile(`(?i)<meta[^>]*>`)
	eventPattern  = regexp.MustCompile(`(?i)\s+on\w+\s*=\s*["'][^"']*["']`)
	eventPattern2 = regexp.MustCompile(`(?i)\s+on\w+\s*=\s*[^\s>]+`)
)

// Sanitizer provides HTML sanitization.
type Sanitizer struct {
	allowedTags map[string]bool
	stripAll    bool
}

// New creates an HTML Sanitizer.
func New(allowedTags []string) *Sanitizer {
	s := &Sanitizer{allowedTags: make(map[string]bool)}
	if len(allowedTags) == 0 {
		s.stripAll = true
	} else {
		for _, tag := range allowedTags {
			s.allowedTags[strings.ToLower(tag)] = true
		}
	}
	return s
}

// SanitizeBody removes dangerous HTML elements.
func (s *Sanitizer) SanitizeBody(input string) string {
	result := scriptPattern.ReplaceAllString(input, "")
	result = stylePattern.ReplaceAllString(result, "")
	result = iframePattern.ReplaceAllString(result, "")
	result = objectPattern.ReplaceAllString(result, "")
	result = embedPattern.ReplaceAllString(result, "")
	result = linkPattern.ReplaceAllString(result, "")
	result = metaPattern.ReplaceAllString(result, "")
	result = eventPattern.ReplaceAllString(result, "")
	result = eventPattern2.ReplaceAllString(result, "")
	if s.stripAll {
		result = tagPattern.ReplaceAllString(result, "")
	}
	return strings.TrimSpace(result)
}

// SanitizeAttribute escapes HTML attribute values.
func (s *Sanitizer) SanitizeAttribute(input string) string {
	return html.EscapeString(input)
}

// StripTags removes all HTML tags.
func (s *Sanitizer) StripTags(input string) string {
	return tagPattern.ReplaceAllString(input, "")
}

// AllowedTags returns the list of allowed tags.
func (s *Sanitizer) AllowedTags() []string {
	tags := make([]string, 0, len(s.allowedTags))
	for tag := range s.allowedTags {
		tags = append(tags, tag)
	}
	return tags
}

// IsStripAll returns whether all tags are stripped.
func (s *Sanitizer) IsStripAll() bool {
	return s.stripAll
}

// EscapeString escapes HTML special characters.
func EscapeString(s string) string {
	return html.EscapeString(s)
}

// UnescapeString unescapes HTML entities.
func UnescapeString(s string) string {
	return html.UnescapeString(s)
}

// UGC returns a sanitizer for User Generated Content.
func UGC() *Sanitizer {
	return New([]string{"b", "i", "u", "strong", "em", "p", "br", "ul", "ol", "li", "a"})
}
