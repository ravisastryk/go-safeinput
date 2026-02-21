// Package after shows the same handlers from the "before" package,
// rewritten using go-safeinput to eliminate the vulnerabilities.
//
// Run the AgenticAnalyzer against this directory to confirm zero findings:
//
//	go run ./cmd/analyzer -dir ./examples/agentic/after
package after

import (
	"html"
	"net/http"
	"reflect"

	"github.com/ravisastryk/go-safeinput"
	"github.com/ravisastryk/go-safeinput/safedecode"
)

// SearchHandler — CWE-89 fixed: query param sanitized as SQL identifier;
// html.EscapeString applied before writing to the HTML response (defense-in-depth).
func SearchHandler(w http.ResponseWriter, r *http.Request) {
	s := safeinput.Default()
	raw := r.URL.Query().Get("q")
	query, err := s.Sanitize(raw, safeinput.SQLIdentifier)
	if err != nil {
		http.Error(w, "invalid query parameter", http.StatusBadRequest)
		return
	}
	w.Write([]byte("results for: " + html.EscapeString(query)))
}

// CommentHandler — CWE-79 fixed: form value sanitized for HTML body context.
func CommentHandler(w http.ResponseWriter, r *http.Request) {
	s := safeinput.Default()
	raw := r.FormValue("comment")
	comment, err := s.Sanitize(raw, safeinput.HTMLBody)
	if err != nil {
		http.Error(w, "invalid comment", http.StatusBadRequest)
		return
	}
	w.Write([]byte("<p>" + comment + "</p>"))
}

// UploadHandler — CWE-79 fixed: filename sanitized as a file path;
// html.EscapeString applied before writing to the HTML response (defense-in-depth).
func UploadHandler(w http.ResponseWriter, r *http.Request) {
	s := safeinput.Default()
	raw := r.PostFormValue("filename")
	filename, err := s.Sanitize(raw, safeinput.FilePath)
	if err != nil {
		http.Error(w, "invalid filename", http.StatusBadRequest)
		return
	}
	w.Write([]byte("uploading: " + html.EscapeString(filename)))
}

// CreateUserHandler — CWE-502 fixed: safedecode enforces size, depth and type limits.
type CreateUserRequest struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

func CreateUserHandler(w http.ResponseWriter, r *http.Request) {
	dec := safedecode.NewDecoder(r.Body, safedecode.Config{
		MaxBytes:     64 << 10, // 64 KB
		MaxDepth:     5,
		MaxKeys:      20,
		AllowedTypes: []reflect.Type{reflect.TypeOf(CreateUserRequest{})},
	})
	var req CreateUserRequest
	if err := dec.Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	w.Write([]byte("created: " + html.EscapeString(req.Name)))
}

// RawBodyHandler — CWE-20 fixed: body read is bounded by safedecode's MaxBytes.
func RawBodyHandler(w http.ResponseWriter, r *http.Request) {
	dec := safedecode.NewDecoder(r.Body, safedecode.Config{
		MaxBytes: 1 << 20, // 1 MB hard cap
		MaxDepth: 1,
		MaxKeys:  0,
	})
	var payload map[string]string
	if err := dec.Decode(&payload); err != nil {
		http.Error(w, "invalid payload", http.StatusBadRequest)
		return
	}
	w.Write([]byte("received"))
}
