// Command analyzer runs the AgenticAnalyzer across a Go source tree,
// reports unsanitized HTTP input with CWE-mapped fix suggestions, and
// emits GitHub Actions workflow annotations so findings appear inline on PRs.
//
// Usage:
//
//	go run ./cmd/analyzer [flags]
//
// Flags:
//
//	-dir  string   root directory to scan (default ".")
//	-fmt  string   output format: text | json (default "text")
//	-exit-zero     always exit 0 (report-only mode, never block CI)
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/ravisastryk/go-safeinput/analyzer"
)

var skipDirs = map[string]bool{
	"vendor": true, ".git": true, "testdata": true,
}

// scan walks dir and returns all findings from non-test Go source files.
func scan(dir string) ([]analyzer.Finding, error) {
	a := analyzer.Default()
	var allFindings []analyzer.Finding

	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && skipDirs[d.Name()] {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		if src, readErr := os.ReadFile(path); readErr == nil { // #nosec G304 G122 -- path comes from filepath.WalkDir, not external input; no symlink TOCTOU risk in read-only walk
			if findings, analyzeErr := a.AnalyzeFile(path, src); analyzeErr == nil {
				allFindings = append(allFindings, findings...)
			}
		}
		return nil
	})
	return allFindings, err
}

// report writes findings to stdout in the requested format.
func report(findings []analyzer.Finding, format string) {
	if format == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(findings)
		return
	}

	if len(findings) == 0 {
		fmt.Println("✓ No unsanitized HTTP input detected")
		return
	}

	fmt.Printf("⚠ Found %d issue(s) with unsanitized HTTP input:\n\n", len(findings))
	for i, f := range findings {
		fmt.Printf("Issue %d: %s (line %d)\n", i+1, f.File, f.Line)
		fmt.Printf("  Function:   %s\n", f.Function)
		fmt.Printf("  Input:      %s\n", f.InputExpr)
		fmt.Printf("  CWE:        %s\n", f.CWE)
		fmt.Printf("  Severity:   %s (confidence: %.0f%%)\n", f.Severity, f.Confidence*100)
		fmt.Printf("  Suggestion: %s\n", f.Suggestion)
		fmt.Printf("  Fix:\n")
		for _, line := range strings.Split(f.FixCode, "\n") {
			fmt.Printf("    %s\n", line)
		}
		fmt.Println()

		// Emit GitHub Actions inline annotation so findings appear on the PR diff.
		fmt.Printf("::warning file=%s,line=%d,title=%s::%s\n",
			f.File, f.Line, f.CWE, f.Suggestion)
	}
}

func main() {
	dir := flag.String("dir", ".", "root directory to scan")
	format := flag.String("fmt", "text", "output format: text or json")
	exitZero := flag.Bool("exit-zero", false, "always exit 0 (report-only, non-blocking)")
	flag.Parse()

	findings, err := scan(*dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "walk error: %v\n", err)
		os.Exit(1)
	}

	report(findings, *format)

	if len(findings) > 0 && !*exitZero {
		os.Exit(1)
	}
}
