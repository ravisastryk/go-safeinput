package path

import (
	"testing"
)

func TestNew(t *testing.T) {
	s := New("")
	if s == nil {
		t.Fatal("New returned nil")
	}
	if s.BasePath() != "" {
		t.Errorf("BasePath = %q, want empty", s.BasePath())
	}
	if s.AllowAbsolute() {
		t.Error("AllowAbsolute should be false")
	}
}

func TestNew_WithBasePath(t *testing.T) {
	s := New("/var/www")
	if s.BasePath() != "/var/www" {
		t.Errorf("BasePath = %q, want '/var/www'", s.BasePath())
	}
}

func TestSanitize_Valid(t *testing.T) {
	s := New("")
	valid := []struct {
		input string
		want  string
	}{
		{"file.txt", "file.txt"},
		{"subdir/file.txt", "subdir/file.txt"},
		{"my_file.txt", "my_file.txt"},
		{"my-file.txt", "my-file.txt"},
		{"a/b/c/d/file.txt", "a/b/c/d/file.txt"},
		{"file.name.txt", "file.name.txt"},
		{".", "."},
	}
	for _, tt := range valid {
		got, err := s.Sanitize(tt.input)
		if err != nil {
			t.Errorf("Sanitize(%q) error = %v", tt.input, err)
		}
		if got != tt.want {
			t.Errorf("Sanitize(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestSanitize_PathTraversal(t *testing.T) {
	s := New("")
	attacks := []string{
		"../etc/passwd", "../../etc/passwd", "../../../etc",
		"foo/../../../etc", "..\\..\\windows",
		"..%2f..%2f", "..%5c..%5c", "%2e%2e/",
		".%2e/", "%2e./", "..%252f", "....//",
	}
	for _, input := range attacks {
		_, err := s.Sanitize(input)
		if err != ErrPathTraversal {
			t.Errorf("Sanitize(%q) = %v, want ErrPathTraversal", input, err)
		}
	}
}

func TestSanitize_InvalidCharacter(t *testing.T) {
	s := New("")
	invalid := []string{
		"file.txt\x00.jpg", "file\n.txt", "file\r.txt",
		"file\x07.txt", "file\x7f.txt",
	}
	for _, input := range invalid {
		_, err := s.Sanitize(input)
		if err != ErrInvalidCharacter {
			t.Errorf("Sanitize(%q) = %v, want ErrInvalidCharacter", input, err)
		}
	}
}

func TestSanitize_AbsolutePath(t *testing.T) {
	s := New("")
	absolute := []string{"/etc/passwd", "/var/www/html"}
	for _, input := range absolute {
		_, err := s.Sanitize(input)
		if err != ErrAbsolutePath {
			t.Errorf("Sanitize(%q) = %v, want ErrAbsolutePath", input, err)
		}
	}
}

func TestSanitize_EmptyPath(t *testing.T) {
	s := New("")
	_, err := s.Sanitize("")
	if err != ErrEmptyPath {
		t.Errorf("Sanitize('') = %v, want ErrEmptyPath", err)
	}
}

func TestSanitize_TabAllowed(t *testing.T) {
	s := New("")
	got, err := s.Sanitize("file\t.txt")
	if err != nil {
		t.Errorf("Tab should be allowed: %v", err)
	}
	if got != "file\t.txt" {
		t.Errorf("Got %q, want 'file\\t.txt'", got)
	}
}

func TestSanitize_BasePath(t *testing.T) {
	s := New("/var/www/uploads")
	valid := []string{"file.txt", "user123/avatar.png", "users/123/img.png"}
	for _, input := range valid {
		_, err := s.Sanitize(input)
		if err != nil {
			t.Errorf("Sanitize(%q) error = %v", input, err)
		}
	}
}

func TestJoin(t *testing.T) {
	s := New("")
	got, err := s.Join("/uploads", "user123", "avatar.png")
	if err != nil {
		t.Errorf("Join error = %v", err)
	}
	if got != "/uploads/user123/avatar.png" {
		t.Errorf("Join = %q", got)
	}
}

func TestJoin_Traversal(t *testing.T) {
	s := New("")
	_, err := s.Join("/uploads", "user", "../../../etc/passwd")
	if err == nil {
		t.Error("Join should fail on traversal")
	}
}

func TestSetAllowAbsolute(t *testing.T) {
	s := New("")
	s.SetAllowAbsolute(true)
	if !s.AllowAbsolute() {
		t.Error("AllowAbsolute should be true")
	}
	_, err := s.Sanitize("/etc/passwd")
	if err == ErrAbsolutePath {
		t.Error("Should allow absolute paths")
	}
}

func TestIsTraversal(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"../passwd", true},
		{"..\\passwd", true},
		{"..%2f", true},
		{"%2e%2e", true},
		{"normal/path", false},
		{"file.txt", false},
	}
	for _, tt := range tests {
		if got := IsTraversal(tt.input); got != tt.want {
			t.Errorf("IsTraversal(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func BenchmarkSanitize(b *testing.B) {
	s := New("/var/www")
	for i := 0; i < b.N; i++ {
		_, _ = s.Sanitize("user123/images/avatar.png")
	}
}
