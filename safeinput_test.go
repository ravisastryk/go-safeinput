package safeinput

import (
	"strings"
	"testing"
)

func TestDefault(t *testing.T) {
	s := Default()
	if s == nil {
		t.Fatal("Default() returned nil")
	}
	cfg := s.GetConfig()
	if cfg.MaxInputLength != 10000 {
		t.Errorf("MaxInputLength = %d, want 10000", cfg.MaxInputLength)
	}
}

func TestNew(t *testing.T) {
	cfg := Config{MaxInputLength: 5000, BasePath: "/tmp"}
	s := New(cfg)
	if s.GetConfig().MaxInputLength != 5000 {
		t.Errorf("MaxInputLength = %d, want 5000", s.GetConfig().MaxInputLength)
	}
}

func TestNew_DefaultMaxLength(t *testing.T) {
	s := New(Config{})
	if s.GetConfig().MaxInputLength != 10000 {
		t.Errorf("Default MaxInputLength = %d, want 10000", s.GetConfig().MaxInputLength)
	}
}

func TestSanitize_HTMLBody(t *testing.T) {
	s := Default()
	tests := []struct {
		input string
		want  string
	}{
		{"<script>alert('xss')</script>Hello", "Hello"},
		{"<b>Bold</b>", "Bold"},
		{"Normal text", "Normal text"},
		{"<img src=x onerror=alert(1)>", ""},
		{"<div onclick='bad()'>Hi</div>", "Hi"},
		{"<style>body{}</style>Text", "Text"},
		{"<iframe>Bad</iframe>Safe", "Safe"},
		{"<a href='x'>Link</a>", "Link"},
	}
	for _, tt := range tests {
		got, err := s.Sanitize(tt.input, HTMLBody)
		if err != nil {
			t.Errorf("Sanitize(%q) error = %v", tt.input, err)
		}
		if got != tt.want {
			t.Errorf("Sanitize(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestSanitize_HTMLAttribute(t *testing.T) {
	s := Default()
	tests := []struct {
		input string
		want  string
	}{
		{`"quoted"`, `&#34;quoted&#34;`},
		{"<script>", "&lt;script&gt;"},
		{"a & b", "a &amp; b"},
		{"normal", "normal"},
	}
	for _, tt := range tests {
		got, _ := s.Sanitize(tt.input, HTMLAttribute)
		if got != tt.want {
			t.Errorf("Sanitize(%q, HTMLAttribute) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestSanitize_FilePath(t *testing.T) {
	s := Default()
	valid := []string{"file.txt", "subdir/file.txt", "a/b/c.txt"}
	for _, input := range valid {
		if _, err := s.Sanitize(input, FilePath); err != nil {
			t.Errorf("Sanitize(%q) should be valid: %v", input, err)
		}
	}
	invalid := []string{"../etc/passwd", "..\\windows", "..%2f..%2f"}
	for _, input := range invalid {
		if _, err := s.Sanitize(input, FilePath); err == nil {
			t.Errorf("Sanitize(%q) should fail", input)
		}
	}
}

func TestSanitize_SQLIdentifier(t *testing.T) {
	s := Default()
	valid := []string{"users", "user_data", "_private", "Table123"}
	for _, input := range valid {
		if _, err := s.Sanitize(input, SQLIdentifier); err != nil {
			t.Errorf("Sanitize(%q) should be valid: %v", input, err)
		}
	}
	invalid := []string{"123table", "user;drop", "", "users'"}
	for _, input := range invalid {
		if _, err := s.Sanitize(input, SQLIdentifier); err == nil {
			t.Errorf("Sanitize(%q) should fail", input)
		}
	}
}

func TestSanitize_SQLValue(t *testing.T) {
	s := Default()
	if _, err := s.Sanitize("normal text", SQLValue); err != nil {
		t.Errorf("Normal text should be valid: %v", err)
	}
	attacks := []string{"' OR '1'='1", "'; DROP TABLE--", "UNION SELECT *"}
	for _, input := range attacks {
		if _, err := s.Sanitize(input, SQLValue); err == nil {
			t.Errorf("Sanitize(%q) should detect injection", input)
		}
	}
}

func TestSanitize_ShellArg(t *testing.T) {
	s := Default()
	got, _ := s.Sanitize("file; rm -rf /", ShellArg)
	if strings.Contains(got, ";") {
		t.Errorf("ShellArg should strip semicolons: %q", got)
	}
}

func TestSanitize_URLPath(t *testing.T) {
	s := Default()
	if _, err := s.Sanitize("path/to/file", URLPath); err != nil {
		t.Errorf("URLPath error: %v", err)
	}
}

func TestSanitize_URLQuery(t *testing.T) {
	s := Default()
	if _, err := s.Sanitize("key=value", URLQuery); err != nil {
		t.Errorf("URLQuery error: %v", err)
	}
}

func TestSanitize_MaxLength(t *testing.T) {
	s := New(Config{MaxInputLength: 10})
	if _, err := s.Sanitize("this is too long", HTMLBody); err != ErrInputTooLong {
		t.Errorf("Expected ErrInputTooLong, got %v", err)
	}
}

func TestSanitize_NullByte(t *testing.T) {
	s := New(Config{StripNullBytes: false, MaxInputLength: 1000})
	if _, err := s.Sanitize("file\x00.txt", HTMLBody); err != ErrNullByte {
		t.Errorf("Expected ErrNullByte, got %v", err)
	}
}

func TestSanitize_StripNullBytes(t *testing.T) {
	s := New(Config{StripNullBytes: true, MaxInputLength: 1000})
	got, _ := s.Sanitize("hello\x00world", HTMLBody)
	if got != "helloworld" {
		t.Errorf("Expected 'helloworld', got %q", got)
	}
}

func TestSanitize_UnknownContext(t *testing.T) {
	s := Default()
	if _, err := s.Sanitize("test", Context(999)); err != ErrUnknownContext {
		t.Errorf("Expected ErrUnknownContext, got %v", err)
	}
}

func TestMustSanitize(t *testing.T) {
	s := Default()
	if result := s.MustSanitize("hello", HTMLBody); result != "hello" {
		t.Errorf("MustSanitize = %q, want 'hello'", result)
	}
}

func TestMustSanitize_Panic(t *testing.T) {
	s := New(Config{MaxInputLength: 5})
	defer func() {
		if r := recover(); r == nil {
			t.Error("MustSanitize should panic")
		}
	}()
	s.MustSanitize("this is too long", HTMLBody)
}

func TestIsValid(t *testing.T) {
	s := Default()
	if !s.IsValid("hello", HTMLBody) {
		t.Error("IsValid should be true")
	}
	if s.IsValid("../etc/passwd", FilePath) {
		t.Error("IsValid should be false for traversal")
	}
}

func TestContext_String(t *testing.T) {
	tests := []struct {
		ctx  Context
		want string
	}{
		{HTMLBody, "HTMLBody"},
		{HTMLAttribute, "HTMLAttribute"},
		{SQLIdentifier, "SQLIdentifier"},
		{SQLValue, "SQLValue"},
		{FilePath, "FilePath"},
		{URLPath, "URLPath"},
		{URLQuery, "URLQuery"},
		{ShellArg, "ShellArg"},
		{Context(999), "Unknown"},
		{Context(-1), "Unknown"},
	}
	for _, tt := range tests {
		if got := tt.ctx.String(); got != tt.want {
			t.Errorf("Context(%d).String() = %q, want %q", tt.ctx, got, tt.want)
		}
	}
}

func TestStripNullBytes(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"hello", "hello"},
		{"hel\x00lo", "hello"},
		{"\x00\x00\x00", ""},
		{"a\x00b\x00c", "abc"},
	}
	for _, tt := range tests {
		if got := StripNullBytes(tt.input); got != tt.want {
			t.Errorf("StripNullBytes(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestSanitizeShellArg(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"filename.txt", "filename.txt"},
		{"path/to/file", "path/to/file"},
		{"file; rm -rf /", "filerm-rf/"},
		{"$(whoami)", "whoami"},
		{"`id`", "id"},
		{"a-b_c.d/e", "a-b_c.d/e"},
	}
	for _, tt := range tests {
		if got := SanitizeShellArg(tt.input); got != tt.want {
			t.Errorf("SanitizeShellArg(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestIsAllowedShellChar(t *testing.T) {
	allowed := []rune{'a', 'Z', '0', '-', '_', '.', '/'}
	for _, r := range allowed {
		if !isAllowedShellChar(r) {
			t.Errorf("isAllowedShellChar(%q) should be true", r)
		}
	}
	notAllowed := []rune{';', '|', '&', '$', '`', '(', ')', ' '}
	for _, r := range notAllowed {
		if isAllowedShellChar(r) {
			t.Errorf("isAllowedShellChar(%q) should be false", r)
		}
	}
}

func BenchmarkSanitize_HTMLBody(b *testing.B) {
	s := Default()
	input := "<script>alert('xss')</script>Hello"
	for i := 0; i < b.N; i++ {
		_, _ = s.Sanitize(input, HTMLBody)
	}
}

func BenchmarkSanitize_FilePath(b *testing.B) {
	s := Default()
	for i := 0; i < b.N; i++ {
		_, _ = s.Sanitize("user/uploads/avatar.png", FilePath)
	}
}
