// Package middleware provides SafeHTTP, a drop-in net/http middleware that
// automatically sanitizes all query parameters and form values before they
// reach the wrapped handler.
//
// It supports per-parameter context routing (e.g. "filepath" → path-traversal
// check, "search" → SQL-identifier check) and configurable error handling.
package middleware

import (
	"fmt"
	"net/http"
)

// Context determines which sanitization strategy to apply.
type Context int

const (
	HTMLBody      Context = iota // XSS prevention (default)
	SQLIdentifier                // SQL injection prevention
	FilePath                     // path traversal prevention
	ShellArg                     // command injection prevention
)

// SanitizeFunc is the signature go-safeinput's Sanitize method matches.
type SanitizeFunc func(input string, ctx Context) (string, error)

// Option configures the middleware.
type Option func(*SafeHTTP)

// SafeHTTP wraps an http.Handler with automatic input sanitization.
type SafeHTTP struct {
	inner      http.Handler
	sanitize   SanitizeFunc
	contexts   map[string]Context
	defaultCtx Context
	onError    func(http.ResponseWriter, *http.Request, error)
}

// WithContext maps a parameter name to a specific sanitization context.
func WithContext(param string, ctx Context) Option {
	return func(s *SafeHTTP) { s.contexts[param] = ctx }
}

// WithErrorHandler overrides the default 400-response error handler.
func WithErrorHandler(h func(http.ResponseWriter, *http.Request, error)) Option {
	return func(s *SafeHTTP) { s.onError = h }
}

// New creates a SafeHTTP middleware wrapping the given handler.
func New(inner http.Handler, sanitize SanitizeFunc, opts ...Option) *SafeHTTP {
	s := &SafeHTTP{
		inner:      inner,
		sanitize:   sanitize,
		contexts:   make(map[string]Context),
		defaultCtx: HTMLBody,
		onError: func(w http.ResponseWriter, _ *http.Request, err error) {
			http.Error(w, fmt.Sprintf("input rejected: %s", err), http.StatusBadRequest)
		},
	}
	for _, o := range opts {
		o(s)
	}
	return s
}

// ServeHTTP sanitizes inputs then delegates to the wrapped handler.
func (s *SafeHTTP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// ── Query parameters ──
	q := r.URL.Query()
	for key, vals := range q {
		ctx := s.ctxFor(key)
		for i, v := range vals {
			safe, err := s.sanitize(v, ctx)
			if err != nil {
				s.onError(w, r, fmt.Errorf("param %q: %w", key, err))
				return
			}
			vals[i] = safe
		}
		q[key] = vals
	}
	r.URL.RawQuery = q.Encode()

	// ── Form values (POST/PUT/PATCH) ──
	if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch {
		if err := r.ParseForm(); err == nil {
			for key, vals := range r.PostForm {
				ctx := s.ctxFor(key)
				for i, v := range vals {
					safe, err := s.sanitize(v, ctx)
					if err != nil {
						s.onError(w, r, fmt.Errorf("field %q: %w", key, err))
						return
					}
					vals[i] = safe
				}
				r.PostForm[key] = vals
			}
		}
	}

	s.inner.ServeHTTP(w, r)
}

func (s *SafeHTTP) ctxFor(param string) Context {
	if ctx, ok := s.contexts[param]; ok {
		return ctx
	}
	return s.defaultCtx
}
