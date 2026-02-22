// Package before shows common Go HTTP handlers that contain
// unsanitized input vulnerabilities.
//
// Run the AgenticAnalyzer against this directory to see findings:
//
//	go run ./cmd/analyzer -dir ./examples/agentic/before
package before

import (
	"encoding/json"
	"io"
	"net/http"
)

// SearchHandler reads a query param without sanitization — CWE-89.
func SearchHandler(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q") // ← AgenticAnalyzer will flag this
	w.Write([]byte("results for: " + query))
}

// CommentHandler reads a form value without sanitization — CWE-79.
func CommentHandler(w http.ResponseWriter, r *http.Request) {
	comment := r.FormValue("comment") // ← AgenticAnalyzer will flag this
	w.Write([]byte("<p>" + comment + "</p>"))
}

// UploadHandler reads a filename from POST form without sanitization — CWE-79.
func UploadHandler(w http.ResponseWriter, r *http.Request) {
	filename := r.PostFormValue("filename") // ← AgenticAnalyzer will flag this
	w.Write([]byte("uploading: " + filename))
}

// CreateUserHandler decodes JSON body without size/depth limits — CWE-502.
type CreateUserRequest struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

func CreateUserHandler(w http.ResponseWriter, r *http.Request) {
	var req CreateUserRequest
	json.NewDecoder(r.Body).Decode(&req) // ← AgenticAnalyzer will flag this
	w.Write([]byte("created: " + req.Name))
}

// RawBodyHandler reads the full request body without limits — CWE-20.
func RawBodyHandler(w http.ResponseWriter, r *http.Request) {
	data, _ := io.ReadAll(r.Body) // ← AgenticAnalyzer will flag this
	w.Write(data)
}
