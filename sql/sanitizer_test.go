package sql

import (
	"testing"
)

func TestNew(t *testing.T) {
	s := New()
	if s == nil {
		t.Fatal("New() returned nil")
	}
	if s.MaxIdentifierLength() != 128 {
		t.Errorf("MaxIdentifierLength = %d, want 128", s.MaxIdentifierLength())
	}
	if !s.StrictMode() {
		t.Error("StrictMode should be true")
	}
}

func TestSanitizeIdentifier_Valid(t *testing.T) {
	s := New()
	valid := []string{"users", "user_data", "_private", "Table123", "USERS", "a"}
	for _, input := range valid {
		got, err := s.SanitizeIdentifier(input)
		if err != nil {
			t.Errorf("SanitizeIdentifier(%q) error = %v", input, err)
		}
		if got != input {
			t.Errorf("SanitizeIdentifier(%q) = %q", input, got)
		}
	}
}

func TestSanitizeIdentifier_Invalid(t *testing.T) {
	s := New()
	invalid := []string{"123table", "user data", "user-data", "users;", "users'", `users"`, "", "a b"}
	for _, input := range invalid {
		_, err := s.SanitizeIdentifier(input)
		if err != ErrInvalidIdentifier {
			t.Errorf("SanitizeIdentifier(%q) = %v, want ErrInvalidIdentifier", input, err)
		}
	}
}

func TestSanitizeIdentifier_Reserved(t *testing.T) {
	s := New()
	reserved := []string{"select", "SELECT", "drop", "DROP", "table", "union", "or", "and"}
	for _, word := range reserved {
		_, err := s.SanitizeIdentifier(word)
		if err != ErrReservedWord {
			t.Errorf("SanitizeIdentifier(%q) = %v, want ErrReservedWord", word, err)
		}
	}
}

func TestSanitizeIdentifier_TooLong(t *testing.T) {
	s := New()
	s.SetMaxIdentifierLength(5)
	_, err := s.SanitizeIdentifier("toolong")
	if err != ErrIdentifierTooLong {
		t.Errorf("Expected ErrIdentifierTooLong, got %v", err)
	}
}

func TestValidateValue(t *testing.T) {
	s := New()
	valid := []string{"normal text", "user@example.com", "12345", "John's data"}
	for _, input := range valid {
		_, err := s.ValidateValue(input)
		if err != nil {
			t.Errorf("ValidateValue(%q) error = %v", input, err)
		}
	}
	attacks := []string{
		"' OR '1'='1", "' OR 1=1--", "x' AND '1'='1",
		"admin'--", "admin/**/", "' UNION SELECT *",
		"'; DROP TABLE--", "1; SLEEP(5)--",
		"0x414243", "CHAR(65,66)", "BENCHMARK(1000,SHA1('x'))",
	}
	for _, input := range attacks {
		_, err := s.ValidateValue(input)
		if err != ErrSuspiciousPattern {
			t.Errorf("ValidateValue(%q) = %v, want ErrSuspiciousPattern", input, err)
		}
	}
}

func TestQuoteIdentifier(t *testing.T) {
	s := New()
	tests := []struct {
		input   string
		style   QuoteStyle
		want    string
		wantErr bool
	}{
		{"users", QuoteStyleMySQL, "`users`", false},
		{"users", QuoteStylePostgres, `"users"`, false},
		{"users", QuoteStyleSQLServer, "[users]", false},
		{"users", QuoteStyleStandard, `"users"`, false},
		{"users", QuoteStyleNone, "users", false},
		{"users;", QuoteStyleMySQL, "", true},
	}
	for _, tt := range tests {
		got, err := s.QuoteIdentifier(tt.input, tt.style)
		if (err != nil) != tt.wantErr {
			t.Errorf("QuoteIdentifier(%q, %d) error = %v", tt.input, tt.style, err)
		}
		if !tt.wantErr && got != tt.want {
			t.Errorf("QuoteIdentifier(%q, %d) = %q, want %q", tt.input, tt.style, got, tt.want)
		}
	}
}

func TestStrictMode(t *testing.T) {
	s := New()
	if _, err := s.SanitizeIdentifier("select"); err != ErrReservedWord {
		t.Error("Should block reserved in strict mode")
	}
	s.SetStrictMode(false)
	if s.StrictMode() {
		t.Error("StrictMode should be false")
	}
	if _, err := s.SanitizeIdentifier("select"); err != nil {
		t.Errorf("Should allow reserved when strict=false: %v", err)
	}
}

func TestIsReservedWord(t *testing.T) {
	tests := []struct {
		word string
		want bool
	}{
		{"SELECT", true}, {"select", true}, {"DROP", true},
		{"users", false}, {"my_table", false},
	}
	for _, tt := range tests {
		if got := IsReservedWord(tt.word); got != tt.want {
			t.Errorf("IsReservedWord(%q) = %v, want %v", tt.word, got, tt.want)
		}
	}
}

func BenchmarkSanitizeIdentifier(b *testing.B) {
	s := New()
	for i := 0; i < b.N; i++ {
		_, _ = s.SanitizeIdentifier("user_profiles")
	}
}

func BenchmarkValidateValue(b *testing.B) {
	s := New()
	for i := 0; i < b.N; i++ {
		_, _ = s.ValidateValue("Normal user input")
	}
}
