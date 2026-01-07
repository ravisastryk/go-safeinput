package safeinput

import "errors"

var (
	// ErrInputTooLong is returned when input exceeds maximum length.
	ErrInputTooLong = errors.New("input exceeds maximum length")
	// ErrUnknownContext is returned when an unknown sanitization context is provided.
	ErrUnknownContext = errors.New("unknown sanitization context")
	// ErrNullByte is returned when a null byte is detected in input.
	ErrNullByte = errors.New("null byte detected in input")
)
