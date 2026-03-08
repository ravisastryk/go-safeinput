// Package safedecode provides a safe JSON decoder with protection against
// CWE-502 (Deserialization of Untrusted Data).
//
// It enforces payload size limits, nesting depth limits, key-count limits,
// and an optional type allowlist to prevent resource-exhaustion attacks
// and unexpected type coercion.
package safedecode

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"sync"
)

// Sentinel errors returned by Decoder.Decode.
var (
	ErrPayloadTooLarge = errors.New("safedecode: payload exceeds maximum allowed size")
	ErrNestingTooDeep  = errors.New("safedecode: nesting exceeds maximum allowed depth")
	ErrTypeNotAllowed  = errors.New("safedecode: type is not in the allowlist")
	ErrTooManyKeys     = errors.New("safedecode: object has too many keys")
)

// Config controls safety limits.
type Config struct {
	MaxBytes     int64          // max payload bytes (default 1 MB)
	MaxDepth     int            // max nesting depth (default 20)
	MaxKeys      int            // max total object keys (default 1000)
	AllowedTypes []reflect.Type // if set, only these types may decode
}

// DefaultConfig returns production-safe defaults.
func DefaultConfig() Config {
	return Config{
		MaxBytes: 1 << 20,
		MaxDepth: 20,
		MaxKeys:  1000,
	}
}

// Decoder wraps json.Decoder with safety constraints.
type Decoder struct {
	reader io.Reader
	config Config
	mu     sync.Mutex
}

// NewDecoder creates a safe decoder.
func NewDecoder(r io.Reader, cfg Config) *Decoder {
	return &Decoder{
		reader: io.LimitReader(r, cfg.MaxBytes+1),
		config: cfg,
	}
}

// Decode safely decodes JSON into v, enforcing all configured limits.
func (d *Decoder) Decode(v interface{}) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if len(d.config.AllowedTypes) > 0 {
		t := reflect.TypeOf(v)
		if t.Kind() == reflect.Ptr {
			t = t.Elem()
		}
		allowed := false
		for _, at := range d.config.AllowedTypes {
			if t == at {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("%w: %s", ErrTypeNotAllowed, t)
		}
	}

	data, err := io.ReadAll(d.reader)
	if err != nil {
		return fmt.Errorf("read: %w", err)
	}
	if int64(len(data)) > d.config.MaxBytes {
		return ErrPayloadTooLarge
	}

	if depth := MeasureDepth(data); depth > d.config.MaxDepth {
		return fmt.Errorf("%w: depth %d > max %d", ErrNestingTooDeep, depth, d.config.MaxDepth)
	}

	if keys := CountKeys(data); keys > d.config.MaxKeys {
		return fmt.Errorf("%w: %d keys > max %d", ErrTooManyKeys, keys, d.config.MaxKeys)
	}

	return json.Unmarshal(data, v)
}

// MeasureDepth returns the maximum nesting depth of a JSON document.
func MeasureDepth(data []byte) int {
	max, cur := 0, 0
	inStr, esc := false, false
	for _, b := range data {
		if esc {
			esc = false
			continue
		}
		if b == '\\' && inStr {
			esc = true
			continue
		}
		if b == '"' {
			inStr = !inStr
			continue
		}
		if inStr {
			continue
		}
		switch b {
		case '{', '[':
			cur++
			if cur > max {
				max = cur
			}
		case '}', ']':
			cur--
		}
	}
	return max
}

// CountKeys estimates the number of object keys in a JSON document.
func CountKeys(data []byte) int {
	dec := json.NewDecoder(bytes.NewReader(data))
	n := 0
	depth := 0
	expectKey := false
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		switch tok {
		case json.Delim('{'):
			depth++
			expectKey = true
		case json.Delim('}'):
			depth--
			expectKey = false
		case json.Delim('['), json.Delim(']'):
			expectKey = false
		default:
			if expectKey {
				if _, ok := tok.(string); ok {
					n++
					expectKey = false
				}
			} else if depth > 0 {
				expectKey = true // next string token in object is a key
			}
		}
	}
	return n
}
