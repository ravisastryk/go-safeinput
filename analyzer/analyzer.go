// Package analyzer provides an AST-based static analyser that detects
// HTTP handlers reading user input without go-safeinput sanitisation.
//
// It produces findings with CWE mappings, severity, and ready-to-paste
// fix code — making it suitable for both CI gating and IDE integration.
package analyzer

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
)

// CWE identifiers emitted by findings.
const (
	CWEXSS             = "CWE-79"
	CWESQLInjection    = "CWE-89"
	CWEDeserialization = "CWE-502"
	CWEImproperInput   = "CWE-20"
	// CWEOutputEncoding covers missing HTML output encoding: user-derived
	// values written to an HTTP response without html.EscapeString or an
	// equivalent HTML-safe context (e.g. safeinput.HTMLBody).
	// This matches the "XSS via taint analysis" pattern flagged by gosec G705
	// and CodeQL's go/reflected-xss rule.
	CWEOutputEncoding = "CWE-116"
)

// Finding represents a detected missing-sanitisation issue.
type Finding struct {
	File       string  `json:"file"`
	Line       int     `json:"line"`
	Function   string  `json:"function"`
	InputExpr  string  `json:"input_expression"`
	CWE        string  `json:"cwe"`
	Severity   string  `json:"severity"`
	Confidence float64 `json:"confidence"`
	Suggestion string  `json:"suggestion"`
	FixCode    string  `json:"fix_code"`
}

// Analyzer scans Go source for HTTP handlers that read user input
// without passing it through go-safeinput sanitization.
type Analyzer struct {
	InputSources []string
	SanitizerPkg string
}

// Default returns an Analyzer with production-ready defaults.
func Default() *Analyzer {
	return &Analyzer{
		InputSources: []string{
			"FormValue", "PostFormValue",
			"URL.Query", "Body",
			"ReadAll", "Decode",
		},
		SanitizerPkg: "safeinput",
	}
}

// AnalyzeFile parses a Go source file and returns findings.
func (a *Analyzer) AnalyzeFile(filename string, src []byte) ([]Finding, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filename, src, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}

	hasSanitizer := false
	for _, imp := range file.Imports {
		if imp.Path != nil && strings.Contains(imp.Path.Value, a.SanitizerPkg) {
			hasSanitizer = true
			break
		}
	}

	var findings []Finding

	ast.Inspect(file, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Body == nil || !isHTTPHandler(fn) {
			return true
		}

		// Pass 1: detect unsanitized input sources (CWE-79/89/502/20).
		var foundUserInput bool
		ast.Inspect(fn.Body, func(inner ast.Node) bool {
			call, ok := inner.(*ast.CallExpr)
			if !ok {
				return true
			}
			callName := exprString(call.Fun)
			for _, source := range a.InputSources {
				if strings.Contains(callName, source) {
					foundUserInput = true
					if !hasSanitizer || !bodyContainsSanitizer(fn.Body, fset, src) {
						pos := fset.Position(call.Pos())
						findings = append(findings, Finding{
							File:       filename,
							Line:       pos.Line,
							Function:   fn.Name.Name,
							InputExpr:  callName,
							CWE:        cweFor(source),
							Severity:   "HIGH",
							Confidence: 0.90,
							Suggestion: fmt.Sprintf("Sanitize %s with go-safeinput before use", callName),
							FixCode:    fixFor(callName, source),
						})
					}
				}
			}
			return true
		})

		// Pass 2: detect missing HTML output encoding (CWE-116).
		// Fires when a sanitizer IS used (so CWE-79/89 won't duplicate),
		// user input was read, the handler writes to the HTTP response, and
		// no HTML output encoding (html.EscapeString / HTMLBody) is applied.
		// This matches gosec G705 and CodeQL go/reflected-xss findings for
		// handlers that sanitize for a non-HTML context (SQL, FilePath, etc.)
		// but write the result directly to the response.
		if foundUserInput &&
			hasSanitizer && bodyContainsSanitizer(fn.Body, fset, src) &&
			bodyWritesToResponse(fn.Body, fset, src) &&
			!bodyHasHTMLEncoding(fn.Body, fset, src) {
			if writeLine := findResponseWriteLine(fn.Body, fset); writeLine > 0 {
				findings = append(findings, Finding{
					File:       filename,
					Line:       writeLine,
					Function:   fn.Name.Name,
					InputExpr:  "response write",
					CWE:        CWEOutputEncoding,
					Severity:   "MEDIUM",
					Confidence: 0.75,
					Suggestion: fmt.Sprintf(
						"Apply html.EscapeString to user-derived values in %s before writing to the HTML response (defense-in-depth for output context)",
						fn.Name.Name,
					),
					FixCode: fixForOutputEncoding(),
				})
			}
		}

		return true
	})
	return findings, nil
}

// AnalyzeBytes is a convenience wrapper for inline source.
func (a *Analyzer) AnalyzeBytes(src []byte) ([]Finding, error) {
	return a.AnalyzeFile("<stdin>", src)
}

func isHTTPHandler(fn *ast.FuncDecl) bool {
	if fn.Type.Params == nil || len(fn.Type.Params.List) < 2 {
		return false
	}
	for _, p := range fn.Type.Params.List {
		ts := exprString(p.Type)
		if strings.Contains(ts, "ResponseWriter") || strings.Contains(ts, "Request") {
			return true
		}
	}
	return false
}

func exprString(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		return exprString(e.X) + "." + e.Sel.Name
	case *ast.StarExpr:
		return "*" + exprString(e.X)
	default:
		return ""
	}
}

func bodyContainsSanitizer(body *ast.BlockStmt, fset *token.FileSet, src []byte) bool {
	s := fset.Position(body.Pos()).Offset
	e := min(fset.Position(body.End()).Offset, len(src))
	snippet := src[s:e]
	return bytes.Contains(snippet, []byte("safeinput")) ||
		bytes.Contains(snippet, []byte("safedecode"))
}

// bodyWritesToResponse reports whether the handler body contains a direct
// write to the HTTP response (w.Write or fmt.Fprintf).
func bodyWritesToResponse(body *ast.BlockStmt, fset *token.FileSet, src []byte) bool {
	s := fset.Position(body.Pos()).Offset
	e := min(fset.Position(body.End()).Offset, len(src))
	snippet := src[s:e]
	return bytes.Contains(snippet, []byte("w.Write")) ||
		bytes.Contains(snippet, []byte(".Fprintf"))
}

// bodyHasHTMLEncoding reports whether the handler body applies HTML-safe output
// encoding: html.EscapeString, the safeinput.HTMLBody context, or html/template.
func bodyHasHTMLEncoding(body *ast.BlockStmt, fset *token.FileSet, src []byte) bool {
	s := fset.Position(body.Pos()).Offset
	e := min(fset.Position(body.End()).Offset, len(src))
	snippet := src[s:e]
	return bytes.Contains(snippet, []byte("html.EscapeString")) ||
		bytes.Contains(snippet, []byte("HTMLBody")) ||
		bytes.Contains(snippet, []byte("template.HTML"))
}

// findResponseWriteLine returns the source line of the first w.Write or
// fmt.Fprintf call in body, or 0 if none is found.
func findResponseWriteLine(body *ast.BlockStmt, fset *token.FileSet) int {
	var line int
	ast.Inspect(body, func(n ast.Node) bool {
		if line > 0 {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		name := exprString(call.Fun)
		if strings.HasSuffix(name, ".Write") || strings.HasSuffix(name, ".Fprintf") {
			line = fset.Position(call.Pos()).Line
		}
		return true
	})
	return line
}

func cweFor(source string) string {
	switch {
	case strings.Contains(source, "FormValue"), strings.Contains(source, "PostForm"):
		return CWEXSS
	case strings.Contains(source, "Query"):
		return CWESQLInjection
	case strings.Contains(source, "Body"), strings.Contains(source, "Decode"):
		return CWEDeserialization
	default:
		return CWEImproperInput
	}
}

func fixFor(callName, source string) string {
	switch {
	case strings.Contains(source, "FormValue"):
		return `s := safeinput.Default()
raw := ` + callName + `
safe, err := s.Sanitize(raw, safeinput.HTMLBody)
if err != nil {
    http.Error(w, "invalid input", http.StatusBadRequest)
    return
}`
	case strings.Contains(source, "Body"), strings.Contains(source, "Decode"):
		return `dec := safeinput.NewSafeDecoder(r.Body, safeinput.DefaultDeserializationConfig())
var payload MyStruct
if err := dec.Decode(&payload); err != nil {
    http.Error(w, "invalid payload", http.StatusBadRequest)
    return
}`
	default:
		return fmt.Sprintf(`safe, err := safeinput.Default().Sanitize(%s, safeinput.HTMLBody)
if err != nil { http.Error(w, "bad input", 400); return }`, callName)
	}
}

func fixForOutputEncoding() string {
	return `import "html"

// Wrap user-derived values with html.EscapeString before writing to the HTML response.
// The sanitizer protected the input context (SQL/FilePath/etc.); html.EscapeString
// protects the output context (HTML).
safe := html.EscapeString(userValue)
w.Write([]byte("prefix: " + safe))

// For full context-aware escaping, prefer html/template:
// tmpl.Execute(w, struct{ Value string }{Value: userValue})`
}
