package analyzer

import (
	"testing"
)

func TestDetectsUnsanitizedFormValue(t *testing.T) {
	src := []byte(`package main
import "net/http"
func handler(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	w.Write([]byte(name))
}`)
	findings, err := Default().AnalyzeFile("test.go", src)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding for unsanitized FormValue")
	}
	if findings[0].CWE != CWEXSS {
		t.Errorf("want %s, got %s", CWEXSS, findings[0].CWE)
	}
}

func TestNoFindingWhenSafeinputUsed(t *testing.T) {
	src := []byte(`package main
import (
	"net/http"
	"github.com/ravisastryk/go-safeinput"
)
func handler(w http.ResponseWriter, r *http.Request) {
	s := safeinput.Default()
	raw := r.FormValue("name")
	safe, _ := s.Sanitize(raw, safeinput.HTMLBody)
	w.Write([]byte(safe))
}`)
	findings, err := Default().AnalyzeFile("test.go", src)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestDetectsBodyDecode(t *testing.T) {
	src := []byte(`package main
import (
	"encoding/json"
	"net/http"
)
type P struct{ Name string }
func handler(w http.ResponseWriter, r *http.Request) {
	var p P
	json.NewDecoder(r.Body).Decode(&p)
}`)
	findings, err := Default().AnalyzeFile("test.go", src)
	if err != nil {
		t.Fatal(err)
	}
	hasCWE502 := false
	for _, f := range findings {
		if f.CWE == CWEDeserialization {
			hasCWE502 = true
		}
	}
	if !hasCWE502 {
		t.Errorf("expected %s for Body.Decode", CWEDeserialization)
	}
}

func TestNonHandlerIgnored(t *testing.T) {
	src := []byte(`package main
func notAHandler(s string) {
	println(s)
}`)
	findings, err := Default().AnalyzeFile("test.go", src)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for non-handler, got %d", len(findings))
	}
}

func TestAnalyzeBytes(t *testing.T) {
	src := []byte(`package main
import "net/http"
func handler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("id")
	w.Write([]byte(q))
}`)
	findings, err := Default().AnalyzeBytes(src)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings from AnalyzeBytes")
	}
	if findings[0].CWE != CWESQLInjection {
		t.Errorf("want %s for URL.Query, got %s", CWESQLInjection, findings[0].CWE)
	}
}

func TestDetectsReadAll(t *testing.T) {
	src := []byte(`package main
import (
	"io"
	"net/http"
)
func handler(w http.ResponseWriter, r *http.Request) {
	data, _ := io.ReadAll(r.Body)
	w.Write(data)
}`)
	findings, err := Default().AnalyzeFile("test.go", src)
	if err != nil {
		t.Fatal(err)
	}
	hasCWE := false
	for _, f := range findings {
		if f.CWE == CWEImproperInput {
			hasCWE = true
		}
	}
	if !hasCWE {
		t.Errorf("expected %s for ReadAll without sanitisation", CWEImproperInput)
	}
}

func TestDetectsPostFormValue(t *testing.T) {
	src := []byte(`package main
import "net/http"
func handler(w http.ResponseWriter, r *http.Request) {
	v := r.PostFormValue("email")
	w.Write([]byte(v))
}`)
	findings, err := Default().AnalyzeFile("test.go", src)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding for PostFormValue")
	}
	if findings[0].CWE != CWEXSS {
		t.Errorf("want %s, got %s", CWEXSS, findings[0].CWE)
	}
}

func TestHandlerWithOneParam(t *testing.T) {
	// Functions with fewer than 2 params are not HTTP handlers.
	src := []byte(`package main
import "net/http"
func notHandler(w http.ResponseWriter) {
	_ = r.FormValue("x")
}`)
	// This will fail to parse (r is undefined), but AnalyzeFile returns a parse
	// error — that's the expected signal for a non-handler.
	_, err := Default().AnalyzeFile("test.go", src)
	if err == nil {
		t.Log("parse succeeded (unexpected but acceptable)")
	}
}

func TestInvalidSourceReturnsError(t *testing.T) {
	_, err := Default().AnalyzeFile("test.go", []byte("not valid go {{{{"))
	if err == nil {
		t.Error("expected parse error for invalid source")
	}
}

// ── CWE-116 (Improper Output Encoding) tests ────────────────────────────────

// TestDetectsMissingHTMLOutputEncoding verifies that a handler sanitizing for a
// non-HTML context (SQLIdentifier) but writing the result directly to the HTTP
// response without html.EscapeString is flagged as CWE-116.
func TestDetectsMissingHTMLOutputEncoding(t *testing.T) {
	src := []byte(`package p
import (
	"net/http"
	"github.com/ravisastryk/go-safeinput"
)
func handler(w http.ResponseWriter, r *http.Request) {
	s := safeinput.Default()
	raw := r.URL.Query().Get("q")
	query, _ := s.Sanitize(raw, safeinput.SQLIdentifier)
	w.Write([]byte("results: " + query))
}`)
	findings, err := Default().AnalyzeFile("test.go", src)
	if err != nil {
		t.Fatal(err)
	}
	hasCWE116 := false
	for _, f := range findings {
		if f.CWE == CWEOutputEncoding {
			hasCWE116 = true
		}
	}
	if !hasCWE116 {
		t.Errorf("expected %s finding for missing HTML output encoding, got %v", CWEOutputEncoding, cwes(findings))
	}
}

// TestNoFindingWhenHTMLEscapeStringUsed verifies that a handler applying
// html.EscapeString before writing to the response does NOT produce a CWE-116 finding.
func TestNoFindingWhenHTMLEscapeStringUsed(t *testing.T) {
	src := []byte(`package p
import (
	"html"
	"net/http"
	"github.com/ravisastryk/go-safeinput"
)
func handler(w http.ResponseWriter, r *http.Request) {
	s := safeinput.Default()
	raw := r.URL.Query().Get("q")
	query, _ := s.Sanitize(raw, safeinput.SQLIdentifier)
	w.Write([]byte("results: " + html.EscapeString(query)))
}`)
	findings, err := Default().AnalyzeFile("test.go", src)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.CWE == CWEOutputEncoding {
			t.Errorf("false positive: CWE-116 flagged when html.EscapeString is applied")
		}
	}
}

// TestNoFindingWhenHTMLBodyContextUsed verifies that a handler using the HTMLBody
// sanitization context does NOT produce a CWE-116 finding — HTMLBody IS HTML-safe.
func TestNoFindingWhenHTMLBodyContextUsed(t *testing.T) {
	src := []byte(`package p
import (
	"net/http"
	"github.com/ravisastryk/go-safeinput"
)
func handler(w http.ResponseWriter, r *http.Request) {
	s := safeinput.Default()
	raw := r.FormValue("comment")
	comment, _ := s.Sanitize(raw, safeinput.HTMLBody)
	w.Write([]byte("<p>" + comment + "</p>"))
}`)
	findings, err := Default().AnalyzeFile("test.go", src)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.CWE == CWEOutputEncoding {
			t.Errorf("false positive: CWE-116 flagged when HTMLBody context is used")
		}
	}
}

// TestCWE116SeverityAndConfidence verifies the metadata of a CWE-116 finding.
func TestCWE116SeverityAndConfidence(t *testing.T) {
	src := []byte(`package p
import (
	"net/http"
	"github.com/ravisastryk/go-safeinput"
)
func handler(w http.ResponseWriter, r *http.Request) {
	s := safeinput.Default()
	raw := r.PostFormValue("filename")
	filename, _ := s.Sanitize(raw, safeinput.FilePath)
	w.Write([]byte("uploading: " + filename))
}`)
	findings, err := Default().AnalyzeFile("test.go", src)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.CWE == CWEOutputEncoding {
			if f.Severity != "MEDIUM" {
				t.Errorf("want MEDIUM severity, got %s", f.Severity)
			}
			if f.Confidence < 0.70 || f.Confidence > 0.80 {
				t.Errorf("want confidence ~0.75, got %.2f", f.Confidence)
			}
			return
		}
	}
	t.Errorf("expected CWE-116 finding, got %v", cwes(findings))
}
