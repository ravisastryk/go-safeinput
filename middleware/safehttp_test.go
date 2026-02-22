package middleware

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func stripTags(input string, _ Context) (string, error) {
	r := strings.NewReplacer("<", "", ">", "")
	return r.Replace(input), nil
}

func rejectTraversal(input string, ctx Context) (string, error) {
	if ctx == FilePath && strings.Contains(input, "..") {
		return "", fmt.Errorf("path traversal detected")
	}
	return stripTags(input, ctx)
}

func TestSanitizesXSSInQuery(t *testing.T) {
	var got string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.URL.Query().Get("q")
	})
	mw := New(inner, stripTags)
	req := httptest.NewRequest("GET", "/?q=<script>alert(1)</script>", nil)
	mw.ServeHTTP(httptest.NewRecorder(), req)

	if strings.Contains(got, "<script>") {
		t.Errorf("XSS payload survived: %q", got)
	}
}

func TestRejectsPathTraversal(t *testing.T) {
	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})
	mw := New(inner, rejectTraversal, WithContext("file", FilePath))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/?file=../../etc/passwd", nil)
	mw.ServeHTTP(rec, req)

	if called {
		t.Error("handler should not be called on rejection")
	}
	if rec.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", rec.Code)
	}
}

func TestContextRouting(t *testing.T) {
	var receivedCtx Context
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	san := func(input string, ctx Context) (string, error) {
		receivedCtx = ctx
		return input, nil
	}
	mw := New(inner, san, WithContext("path", FilePath), WithContext("sql", SQLIdentifier))

	req := httptest.NewRequest("GET", "/?path=/tmp/x", nil)
	mw.ServeHTTP(httptest.NewRecorder(), req)
	if receivedCtx != FilePath {
		t.Errorf("want FilePath, got %d", receivedCtx)
	}
}

func TestDefaultContextIsHTMLBody(t *testing.T) {
	var receivedCtx Context
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	san := func(input string, ctx Context) (string, error) {
		receivedCtx = ctx
		return input, nil
	}
	mw := New(inner, san)
	req := httptest.NewRequest("GET", "/?anything=hello", nil)
	mw.ServeHTTP(httptest.NewRecorder(), req)
	if receivedCtx != HTMLBody {
		t.Errorf("want HTMLBody (0), got %d", receivedCtx)
	}
}

func TestSanitizesPOSTForm(t *testing.T) {
	var got string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.PostFormValue("name")
	})
	mw := New(inner, stripTags)
	body := strings.NewReader("name=<b>Alice</b>")
	req := httptest.NewRequest("POST", "/", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	mw.ServeHTTP(httptest.NewRecorder(), req)
	if strings.Contains(got, "<b>") {
		t.Errorf("HTML tags survived in POST form: %q", got)
	}
}

func TestRejectsPOSTFormTraversal(t *testing.T) {
	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})
	mw := New(inner, rejectTraversal, WithContext("file", FilePath))
	body := strings.NewReader("file=../../etc/passwd")
	req := httptest.NewRequest("POST", "/", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	if called {
		t.Error("handler should not be called on rejection")
	}
	if rec.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", rec.Code)
	}
}

func TestWithErrorHandler(t *testing.T) {
	customCalled := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	custom := func(w http.ResponseWriter, r *http.Request, err error) {
		customCalled = true
		http.Error(w, "custom: "+err.Error(), http.StatusUnprocessableEntity)
	}
	mw := New(inner, rejectTraversal,
		WithContext("file", FilePath),
		WithErrorHandler(custom),
	)
	req := httptest.NewRequest("GET", "/?file=../../secret", nil)
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	if !customCalled {
		t.Error("custom error handler was not called")
	}
	if rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("want 422, got %d", rec.Code)
	}
}

func TestPUTFormSanitized(t *testing.T) {
	var got string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.PostFormValue("val")
	})
	mw := New(inner, stripTags)
	body := strings.NewReader("val=<em>hi</em>")
	req := httptest.NewRequest("PUT", "/", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	mw.ServeHTTP(httptest.NewRecorder(), req)
	if strings.Contains(got, "<em>") {
		t.Errorf("HTML survived in PUT form: %q", got)
	}
}
