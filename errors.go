package safeinput

import "errors"

var (
	// ErrInputTooLong is returned when input exceeds maximum length.
	ErrInputTooLong   = errors.New("input exceeds maximum length")
	ErrUnknownContext = errors.New("unknown sanitization context")
	ErrNullByte       = errors.New("null byte detected in input")
)
