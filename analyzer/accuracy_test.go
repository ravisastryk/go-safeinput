package analyzer

import (
	"testing"
)

// accuracyCase describes a snippet and whether it should produce a finding.
type accuracyCase struct {
	name        string
	src         []byte
	expectFound bool
	expectCWE   string // only checked when expectFound == true
}

// knownCases is the ground-truth corpus used to measure analyzer accuracy.
// Add new cases here as the analyzer evolves.
var knownCases = []accuracyCase{
	// ── True positives: must be detected ─────────────────────────────────────
	{
		name:        "unsanitized FormValue",
		expectFound: true, expectCWE: CWEXSS,
		src: []byte(`package p
import "net/http"
func h(w http.ResponseWriter, r *http.Request) {
	v := r.FormValue("q")
	w.Write([]byte(v))
}`),
	},
	{
		name:        "unsanitized PostFormValue",
		expectFound: true, expectCWE: CWEXSS,
		src: []byte(`package p
import "net/http"
func h(w http.ResponseWriter, r *http.Request) {
	v := r.PostFormValue("email")
	w.Write([]byte(v))
}`),
	},
	{
		name:        "unsanitized URL.Query",
		expectFound: true, expectCWE: CWESQLInjection,
		src: []byte(`package p
import "net/http"
func h(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	w.Write([]byte(id))
}`),
	},
	{
		name:        "unsanitized json.Decode on Body",
		expectFound: true, expectCWE: CWEDeserialization,
		src: []byte(`package p
import (
	"encoding/json"
	"net/http"
)
type P struct{ Name string }
func h(w http.ResponseWriter, r *http.Request) {
	var p P
	json.NewDecoder(r.Body).Decode(&p)
}`),
	},
	{
		name:        "unsanitized io.ReadAll on Body",
		expectFound: true, expectCWE: CWEImproperInput,
		src: []byte(`package p
import (
	"io"
	"net/http"
)
func h(w http.ResponseWriter, r *http.Request) {
	data, _ := io.ReadAll(r.Body)
	w.Write(data)
}`),
	},

	// ── CWE-116 true positives: missing HTML output encoding ─────────────────
	{
		name:        "safeinput SQLIdentifier + w.Write, no html.EscapeString (CWE-116)",
		expectFound: true, expectCWE: CWEOutputEncoding,
		src: []byte(`package p
import (
	"net/http"
	"github.com/ravisastryk/go-safeinput"
)
func h(w http.ResponseWriter, r *http.Request) {
	s := safeinput.Default()
	raw := r.URL.Query().Get("q")
	query, _ := s.Sanitize(raw, safeinput.SQLIdentifier)
	w.Write([]byte("results: " + query))
}`),
	},
	{
		name:        "safeinput FilePath + w.Write, no html.EscapeString (CWE-116)",
		expectFound: true, expectCWE: CWEOutputEncoding,
		src: []byte(`package p
import (
	"net/http"
	"github.com/ravisastryk/go-safeinput"
)
func h(w http.ResponseWriter, r *http.Request) {
	s := safeinput.Default()
	raw := r.PostFormValue("filename")
	filename, _ := s.Sanitize(raw, safeinput.FilePath)
	w.Write([]byte("uploading: " + filename))
}`),
	},

	// ── True negatives: must NOT be detected ─────────────────────────────────
	{
		name:        "safeinput used — no finding expected",
		expectFound: false,
		src: []byte(`package p
import (
	"net/http"
	"github.com/ravisastryk/go-safeinput"
)
func h(w http.ResponseWriter, r *http.Request) {
	s := safeinput.Default()
	raw := r.FormValue("q")
	safe, _ := s.Sanitize(raw, safeinput.HTMLBody)
	w.Write([]byte(safe))
}`),
	},
	{
		name:        "non-HTTP function — no finding expected",
		expectFound: false,
		src: []byte(`package p
func processData(data string) string {
	return data
}`),
	},
	{
		name:        "handler with one param — not an HTTP handler",
		expectFound: false,
		src: []byte(`package p
import "net/http"
func h(w http.ResponseWriter) {
	w.Write([]byte("ok"))
}`),
	},
	// ── CWE-116 true negatives: html.EscapeString or HTMLBody context used ───
	{
		name:        "safeinput SQLIdentifier + html.EscapeString — no CWE-116",
		expectFound: false,
		src: []byte(`package p
import (
	"html"
	"net/http"
	"github.com/ravisastryk/go-safeinput"
)
func h(w http.ResponseWriter, r *http.Request) {
	s := safeinput.Default()
	raw := r.URL.Query().Get("q")
	query, _ := s.Sanitize(raw, safeinput.SQLIdentifier)
	w.Write([]byte("results: " + html.EscapeString(query)))
}`),
	},
	{
		name:        "safeinput HTMLBody context — no CWE-116",
		expectFound: false,
		src: []byte(`package p
import (
	"net/http"
	"github.com/ravisastryk/go-safeinput"
)
func h(w http.ResponseWriter, r *http.Request) {
	s := safeinput.Default()
	raw := r.FormValue("comment")
	comment, _ := s.Sanitize(raw, safeinput.HTMLBody)
	w.Write([]byte("<p>" + comment + "</p>"))
}`),
	},
}

// TestAnalyzerAccuracy measures precision and recall over the known-case corpus.
// It fails if recall drops below 100% (missed true positive) or
// if a true negative is flagged (false positive).
func TestAnalyzerAccuracy(t *testing.T) {
	a := Default()

	var (
		truePos  int
		falsePos int
		falseNeg int
	)

	for _, tc := range knownCases {
		t.Run(tc.name, func(t *testing.T) {
			findings, err := a.AnalyzeBytes(tc.src)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}

			found := len(findings) > 0

			switch {
			case tc.expectFound && found:
				// True positive — verify CWE matches.
				truePos++
				hasCWE := false
				for _, f := range findings {
					if f.CWE == tc.expectCWE {
						hasCWE = true
					}
				}
				if !hasCWE {
					t.Errorf("detected finding but wrong CWE: want %s, got %v",
						tc.expectCWE, cwes(findings))
				}

			case tc.expectFound && !found:
				// False negative — missed a real issue.
				falseNeg++
				t.Errorf("missed vulnerability: expected %s finding", tc.expectCWE)

			case !tc.expectFound && found:
				// False positive — flagged safe code.
				falsePos++
				t.Errorf("false positive: flagged safe code as %v", cwes(findings))

			case !tc.expectFound && !found:
				// True negative — correctly left safe code alone.
			}
		})
	}

	total := len(knownCases)
	tp := truePos
	tpExpected := countExpected(knownCases)

	recall := pct(tp, tpExpected)
	precision := pct(tp, tp+falsePos)

	t.Logf("Accuracy report — %d cases", total)
	t.Logf("  True positives:  %d / %d  (recall    %.0f%%)", tp, tpExpected, recall)
	t.Logf("  False positives: %d        (precision %.0f%%)", falsePos, precision)
	t.Logf("  False negatives: %d", falseNeg)
}

// ── helpers ──────────────────────────────────────────────────────────────────

func cwes(findings []Finding) []string {
	out := make([]string, len(findings))
	for i, f := range findings {
		out[i] = f.CWE
	}
	return out
}

func countExpected(cases []accuracyCase) int {
	n := 0
	for _, c := range cases {
		if c.expectFound {
			n++
		}
	}
	return n
}

func pct(num, den int) float64 {
	if den == 0 {
		return 0
	}
	return float64(num) / float64(den) * 100
}
