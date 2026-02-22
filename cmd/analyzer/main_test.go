package main

import (
	"os"
	"path/filepath"
	"testing"
)

var unsanitizedHandler = []byte(`package main
import "net/http"
func handler(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	w.Write([]byte(name))
}`)

func TestScanFindsFindings(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "handler.go"), unsanitizedHandler, 0600); err != nil {
		t.Fatal(err)
	}
	findings, err := scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Error("expected findings, got none")
	}
}

func TestScanEmptyDir(t *testing.T) {
	findings, err := scan(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestScanSkipsTestFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "handler_test.go"), unsanitizedHandler, 0600); err != nil {
		t.Fatal(err)
	}
	findings, err := scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings (test file skipped), got %d", len(findings))
	}
}

func TestScanSkipsVendor(t *testing.T) {
	dir := t.TempDir()
	vendor := filepath.Join(dir, "vendor")
	if err := os.MkdirAll(vendor, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(vendor, "handler.go"), unsanitizedHandler, 0600); err != nil {
		t.Fatal(err)
	}
	findings, err := scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings (vendor skipped), got %d", len(findings))
	}
}

func TestReport(t *testing.T) {
	// No-findings path.
	report(nil, "text")

	// With-findings path: text and JSON formats.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "h.go"), unsanitizedHandler, 0600); err != nil {
		t.Fatal(err)
	}
	findings, err := scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings for report test")
	}
	report(findings, "text")
	report(findings, "json")
}
