package html

import (
	"testing"
)

func TestNew(t *testing.T) {
	s := New(nil)
	if s == nil {
		t.Fatal("New(nil) returned nil")
	}
	if !s.IsStripAll() {
		t.Error("Expected stripAll=true for nil tags")
	}
}

func TestNew_WithTags(t *testing.T) {
	s := New([]string{"b", "i"})
	if s.IsStripAll() {
		t.Error("Expected stripAll=false")
	}
	if len(s.AllowedTags()) != 2 {
		t.Errorf("Expected 2 tags, got %d", len(s.AllowedTags()))
	}
}

func TestSanitizeBody(t *testing.T) {
	s := New(nil)
	tests := []struct {
		input string
		want  string
	}{
		{"<script>alert('xss')</script>Hello", "Hello"},
		{"<b>Bold</b>", "Bold"},
		{"Normal text", "Normal text"},
		{"<a href='x'>Link</a>", "Link"},
		{"<img src=x onerror=alert(1)>", ""},
		{"<div onclick='bad()'>Content</div>", "Content"},
		{"<style>body{display:none}</style>Text", "Text"},
		{"<iframe src='evil.com'></iframe>Safe", "Safe"},
		{"<object>Bad</object>OK", "OK"},
		{"<embed>Bad</embed>OK", "OK"},
		{"<link href='x'>Text", "Text"},
		{"<meta charset='x'>Text", "Text"},
		{"", ""},
		{"<SCRIPT>Bad</SCRIPT>OK", "OK"},
		{"<div onmouseover='x'>Hi</div>", "Hi"},
		{"<a href='#' onclick=alert(1)>X</a>", "X"},
	}
	for _, tt := range tests {
		got := s.SanitizeBody(tt.input)
		if got != tt.want {
			t.Errorf("SanitizeBody(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestSanitizeAttribute(t *testing.T) {
	s := New(nil)
	tests := []struct {
		input string
		want  string
	}{
		{`onclick="alert('xss')"`, `onclick=&#34;alert(&#39;xss&#39;)&#34;`},
		{"<script>", "&lt;script&gt;"},
		{"normal", "normal"},
		{`"quoted"`, `&#34;quoted&#34;`},
		{"a & b", "a &amp; b"},
		{"'single'", "&#39;single&#39;"},
	}
	for _, tt := range tests {
		got := s.SanitizeAttribute(tt.input)
		if got != tt.want {
			t.Errorf("SanitizeAttribute(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestStripTags(t *testing.T) {
	s := New(nil)
	tests := []struct {
		input string
		want  string
	}{
		{"<b>Bold</b> text", "Bold text"},
		{"No tags", "No tags"},
		{"<a><b><c>nested</c></b></a>", "nested"},
	}
	for _, tt := range tests {
		got := s.StripTags(tt.input)
		if got != tt.want {
			t.Errorf("StripTags(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestUGC(t *testing.T) {
	s := UGC()
	if s == nil {
		t.Fatal("UGC() returned nil")
	}
	if s.IsStripAll() {
		t.Error("UGC should not strip all")
	}
}

func TestEscapeString(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"<script>", "&lt;script&gt;"},
		{"a & b", "a &amp; b"},
		{`"quoted"`, `&#34;quoted&#34;`},
	}
	for _, tt := range tests {
		if got := EscapeString(tt.input); got != tt.want {
			t.Errorf("EscapeString(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestUnescapeString(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"&lt;script&gt;", "<script>"},
		{"a &amp; b", "a & b"},
		{"&#34;quoted&#34;", `"quoted"`},
	}
	for _, tt := range tests {
		if got := UnescapeString(tt.input); got != tt.want {
			t.Errorf("UnescapeString(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func BenchmarkSanitizeBody(b *testing.B) {
	s := New(nil)
	input := "<script>alert('xss')</script><b>Hello</b> World"
	for i := 0; i < b.N; i++ {
		_ = s.SanitizeBody(input)
	}
}
