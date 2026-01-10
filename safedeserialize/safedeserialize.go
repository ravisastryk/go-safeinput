// Package safedeserialize provides secure deserialization utilities for Go
// that mitigate CWE-502: Deserialization of Untrusted Data.
//
// This package prevents common deserialization vulnerabilities by:
//   - Rejecting interface{} as deserialization targets
//   - Enforcing size limits on input data
//   - Limiting nesting depth to prevent stack exhaustion
//   - Providing type whitelisting capabilities
//   - Offering strict parsing modes
//
// Basic usage:
//
//	type User struct {
//	    Name  string `json:"name"`
//	    Email string `json:"email"`
//	}
//
//	var user User
//	err := safedeserialize.JSON(data, &user)
//
// With options:
//
//	err := safedeserialize.JSON(data, &user,
//	    safedeserialize.WithMaxSize(1<<20),
//	    safedeserialize.WithMaxDepth(16),
//	)
//
// Repository: https://github.com/ravisastryk/go-safeinput
// CWE Reference: https://cwe.mitre.org/data/definitions/502.html
package safedeserialize

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"reflect"
	"sync"

	"gopkg.in/yaml.v3"
)

// Version of the safedeserialize package
const Version = "1.0.0"

// Default configuration values
const (
	DefaultMaxSize  = 1 << 20 // 1MB
	DefaultMaxDepth = 32
)

// Common errors returned by safedeserialize functions
var (
	// ErrDataTooLarge is returned when input data exceeds MaxSize
	ErrDataTooLarge = errors.New("safedeserialize: data exceeds maximum allowed size")

	// ErrNilTarget is returned when the deserialization target is nil
	ErrNilTarget = errors.New("safedeserialize: target cannot be nil")

	// ErrNotPointer is returned when target is not a pointer
	ErrNotPointer = errors.New("safedeserialize: target must be a pointer")

	// ErrInterfaceTarget is returned when deserializing into interface{}
	ErrInterfaceTarget = errors.New("safedeserialize: cannot deserialize into interface{} type - use concrete struct")

	// ErrMapInterface is returned when deserializing into map[string]interface{}
	ErrMapInterface = errors.New("safedeserialize: cannot deserialize into map with interface{} values")

	// ErrSliceInterface is returned when deserializing into []interface{}
	ErrSliceInterface = errors.New("safedeserialize: cannot deserialize into slice of interface{}")

	// ErrTypeNotAllowed is returned when type is not in the allowed list
	ErrTypeNotAllowed = errors.New("safedeserialize: type not in allowed types list")

	// ErrMaxDepthExceeded is returned when nesting depth exceeds MaxDepth
	ErrMaxDepthExceeded = errors.New("safedeserialize: maximum nesting depth exceeded")

	// ErrEmptyData is returned when input data is empty
	ErrEmptyData = errors.New("safedeserialize: input data is empty")
)

// Options configures the behavior of safe deserialization
type Options struct {
	// MaxSize is the maximum allowed data size in bytes
	// Default: 1MB (1 << 20)
	MaxSize int64

	// MaxDepth is the maximum allowed nesting depth
	// Default: 32
	MaxDepth int

	// AllowedTypes is an optional whitelist of type names
	// If empty, all concrete (non-interface) types are allowed
	// Example: []string{"main.User", "main.Config"}
	AllowedTypes []string

	// StrictMode enables additional validation:
	// - JSON: DisallowUnknownFields
	// - Depth checking before parsing
	StrictMode bool

	// AllowMapStringInterface permits map[string]interface{} targets
	// Default: false (blocked for security)
	AllowMapStringInterface bool

	// AllowSliceInterface permits []interface{} targets
	// Default: false (blocked for security)
	AllowSliceInterface bool
}

// Option is a function that modifies Options
type Option func(*Options)

// DefaultOptions returns the default safe configuration
func DefaultOptions() *Options {
	return &Options{
		MaxSize:                 DefaultMaxSize,
		MaxDepth:                DefaultMaxDepth,
		StrictMode:              true,
		AllowMapStringInterface: false,
		AllowSliceInterface:     false,
	}
}

// WithMaxSize sets the maximum allowed data size
func WithMaxSize(size int64) Option {
	return func(o *Options) {
		if size > 0 {
			o.MaxSize = size
		}
	}
}

// WithMaxDepth sets the maximum allowed nesting depth
func WithMaxDepth(depth int) Option {
	return func(o *Options) {
		if depth > 0 {
			o.MaxDepth = depth
		}
	}
}

// WithAllowedTypes sets the whitelist of allowed type names
func WithAllowedTypes(types ...string) Option {
	return func(o *Options) {
		o.AllowedTypes = types
	}
}

// WithStrictMode enables or disables strict parsing
func WithStrictMode(strict bool) Option {
	return func(o *Options) {
		o.StrictMode = strict
	}
}

// WithAllowMapStringInterface permits map[string]interface{} targets
// Use with caution - this reduces security
func WithAllowMapStringInterface(allow bool) Option {
	return func(o *Options) {
		o.AllowMapStringInterface = allow
	}
}

// WithAllowSliceInterface permits []interface{} targets
// Use with caution - this reduces security
func WithAllowSliceInterface(allow bool) Option {
	return func(o *Options) {
		o.AllowSliceInterface = allow
	}
}

// JSON safely unmarshals JSON data into a concrete type
func JSON(data []byte, v interface{}, opts ...Option) error {
	options := DefaultOptions()
	for _, opt := range opts {
		opt(options)
	}
	return jsonUnmarshal(data, v, options)
}

// JSONReader safely decodes JSON from an io.Reader
func JSONReader(r io.Reader, v interface{}, opts ...Option) error {
	options := DefaultOptions()
	for _, opt := range opts {
		opt(options)
	}
	return jsonDecode(r, v, options)
}

// YAML safely unmarshals YAML data into a concrete type
func YAML(data []byte, v interface{}, opts ...Option) error {
	options := DefaultOptions()
	for _, opt := range opts {
		opt(options)
	}
	return yamlUnmarshal(data, v, options)
}

// YAMLReader safely decodes YAML from an io.Reader
func YAMLReader(r io.Reader, v interface{}, opts ...Option) error {
	options := DefaultOptions()
	for _, opt := range opts {
		opt(options)
	}
	return yamlDecode(r, v, options)
}

// XML safely unmarshals XML data into a concrete type
func XML(data []byte, v interface{}, opts ...Option) error {
	options := DefaultOptions()
	for _, opt := range opts {
		opt(options)
	}
	return xmlUnmarshal(data, v, options)
}

// XMLReader safely decodes XML from an io.Reader
func XMLReader(r io.Reader, v interface{}, opts ...Option) error {
	options := DefaultOptions()
	for _, opt := range opts {
		opt(options)
	}
	return xmlDecode(r, v, options)
}

// Gob safely decodes Gob data into a concrete type
func Gob(data []byte, v interface{}, opts ...Option) error {
	options := DefaultOptions()
	for _, opt := range opts {
		opt(options)
	}
	return gobDecode(bytes.NewReader(data), v, options)
}

// GobReader safely decodes Gob from an io.Reader
func GobReader(r io.Reader, v interface{}, opts ...Option) error {
	options := DefaultOptions()
	for _, opt := range opts {
		opt(options)
	}
	return gobDecode(r, v, options)
}

// Internal implementations

func jsonUnmarshal(data []byte, v interface{}, opts *Options) error {
	if len(data) == 0 {
		return ErrEmptyData
	}

	if int64(len(data)) > opts.MaxSize {
		return fmt.Errorf("%w: size %d exceeds limit %d", ErrDataTooLarge, len(data), opts.MaxSize)
	}

	if err := validateTarget(v, opts); err != nil {
		return err
	}

	if opts.StrictMode {
		if depth := measureJSONDepth(data); depth > opts.MaxDepth {
			return fmt.Errorf("%w: depth %d exceeds limit %d", ErrMaxDepthExceeded, depth, opts.MaxDepth)
		}
	}

	if opts.StrictMode {
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		return decoder.Decode(v)
	}

	return json.Unmarshal(data, v)
}

func jsonDecode(r io.Reader, v interface{}, opts *Options) error {
	if err := validateTarget(v, opts); err != nil {
		return err
	}

	limitedReader := io.LimitReader(r, opts.MaxSize+1)
	data, err := io.ReadAll(limitedReader)
	if err != nil {
		return fmt.Errorf("safedeserialize: read error: %w", err)
	}

	return jsonUnmarshal(data, v, opts)
}

func yamlUnmarshal(data []byte, v interface{}, opts *Options) error {
	if len(data) == 0 {
		return ErrEmptyData
	}

	if int64(len(data)) > opts.MaxSize {
		return fmt.Errorf("%w: size %d exceeds limit %d", ErrDataTooLarge, len(data), opts.MaxSize)
	}

	if err := validateTarget(v, opts); err != nil {
		return err
	}

	if opts.StrictMode {
		decoder := yaml.NewDecoder(bytes.NewReader(data))
		decoder.KnownFields(true)
		return decoder.Decode(v)
	}

	return yaml.Unmarshal(data, v)
}

func yamlDecode(r io.Reader, v interface{}, opts *Options) error {
	if err := validateTarget(v, opts); err != nil {
		return err
	}

	limitedReader := io.LimitReader(r, opts.MaxSize+1)
	data, err := io.ReadAll(limitedReader)
	if err != nil {
		return fmt.Errorf("safedeserialize: read error: %w", err)
	}

	return yamlUnmarshal(data, v, opts)
}

func xmlUnmarshal(data []byte, v interface{}, opts *Options) error {
	if len(data) == 0 {
		return ErrEmptyData
	}

	if int64(len(data)) > opts.MaxSize {
		return fmt.Errorf("%w: size %d exceeds limit %d", ErrDataTooLarge, len(data), opts.MaxSize)
	}

	if err := validateTarget(v, opts); err != nil {
		return err
	}

	if opts.StrictMode {
		decoder := xml.NewDecoder(bytes.NewReader(data))
		decoder.Strict = true
		return decoder.Decode(v)
	}

	return xml.Unmarshal(data, v)
}

func xmlDecode(r io.Reader, v interface{}, opts *Options) error {
	if err := validateTarget(v, opts); err != nil {
		return err
	}

	limitedReader := io.LimitReader(r, opts.MaxSize+1)
	data, err := io.ReadAll(limitedReader)
	if err != nil {
		return fmt.Errorf("safedeserialize: read error: %w", err)
	}

	return xmlUnmarshal(data, v, opts)
}

func gobDecode(r io.Reader, v interface{}, opts *Options) error {
	if err := validateTarget(v, opts); err != nil {
		return err
	}

	limitedReader := io.LimitReader(r, opts.MaxSize)
	decoder := gob.NewDecoder(limitedReader)
	return decoder.Decode(v)
}

// validateTarget ensures the deserialization target is safe
func validateTarget(v interface{}, opts *Options) error {
	if v == nil {
		return ErrNilTarget
	}

	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Ptr {
		return ErrNotPointer
	}

	if rv.IsNil() {
		return ErrNilTarget
	}

	elem := rv.Elem()
	if !elem.IsValid() {
		return ErrNilTarget
	}

	// Check for interface{} target
	if elem.Kind() == reflect.Interface {
		return ErrInterfaceTarget
	}

	// Check for map[string]interface{}
	if elem.Kind() == reflect.Map {
		if elem.Type().Elem().Kind() == reflect.Interface && !opts.AllowMapStringInterface {
			return ErrMapInterface
		}
	}

	// Check for []interface{}
	if elem.Kind() == reflect.Slice {
		if elem.Type().Elem().Kind() == reflect.Interface && !opts.AllowSliceInterface {
			return ErrSliceInterface
		}
	}

	// Check type whitelist
	if len(opts.AllowedTypes) > 0 {
		typeName := elem.Type().String()
		allowed := false
		for _, t := range opts.AllowedTypes {
			if t == typeName {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("%w: %s", ErrTypeNotAllowed, typeName)
		}
	}

	// Recursively check struct fields for interface{} types
	if opts.StrictMode && elem.Kind() == reflect.Struct {
		if err := validateStructFields(elem.Type(), opts, make(map[reflect.Type]bool)); err != nil {
			return err
		}
	}

	return nil
}

// validateStructFields checks struct fields for unsafe types
func validateStructFields(t reflect.Type, opts *Options, visited map[reflect.Type]bool) error {
	if visited[t] {
		return nil // Prevent infinite recursion
	}
	visited[t] = true

	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		fieldType := field.Type

		// Skip unexported fields
		if !field.IsExported() {
			continue
		}

		// Dereference pointers
		for fieldType.Kind() == reflect.Ptr {
			fieldType = fieldType.Elem()
		}

		switch fieldType.Kind() {
		case reflect.Interface:
			return fmt.Errorf("safedeserialize: struct field %s.%s is interface{} type", t.Name(), field.Name)
		case reflect.Map:
			if fieldType.Elem().Kind() == reflect.Interface && !opts.AllowMapStringInterface {
				return fmt.Errorf("safedeserialize: struct field %s.%s contains map with interface{} values", t.Name(), field.Name)
			}
		case reflect.Slice:
			elemType := fieldType.Elem()
			for elemType.Kind() == reflect.Ptr {
				elemType = elemType.Elem()
			}
			if elemType.Kind() == reflect.Interface && !opts.AllowSliceInterface {
				return fmt.Errorf("safedeserialize: struct field %s.%s is []interface{} type", t.Name(), field.Name)
			}
		case reflect.Struct:
			if err := validateStructFields(fieldType, opts, visited); err != nil {
				return err
			}
		}
	}

	return nil
}

// measureJSONDepth estimates the nesting depth of JSON data
func measureJSONDepth(data []byte) int {
	maxDepth := 0
	currentDepth := 0
	inString := false
	escaped := false

	for _, b := range data {
		if escaped {
			escaped = false
			continue
		}

		if b == '\\' && inString {
			escaped = true
			continue
		}

		if b == '"' {
			inString = !inString
			continue
		}

		if inString {
			continue
		}

		switch b {
		case '{', '[':
			currentDepth++
			if currentDepth > maxDepth {
				maxDepth = currentDepth
			}
		case '}', ']':
			currentDepth--
		}
	}

	return maxDepth
}

// TypeRegistry provides a thread-safe whitelist of allowed types
type TypeRegistry struct {
	mu    sync.RWMutex
	types map[string]reflect.Type
}

// NewTypeRegistry creates a new type registry
func NewTypeRegistry() *TypeRegistry {
	return &TypeRegistry{
		types: make(map[string]reflect.Type),
	}
}

// Register adds a type to the registry
// Pass a zero value or pointer: registry.Register(User{}) or registry.Register(&User{})
func (r *TypeRegistry) Register(v interface{}) *TypeRegistry {
	r.mu.Lock()
	defer r.mu.Unlock()

	t := reflect.TypeOf(v)
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	r.types[t.String()] = t
	return r
}

// RegisterMultiple adds multiple types to the registry
func (r *TypeRegistry) RegisterMultiple(values ...interface{}) *TypeRegistry {
	for _, v := range values {
		r.Register(v)
	}
	return r
}

// IsRegistered checks if a type is in the registry
func (r *TypeRegistry) IsRegistered(v interface{}) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	t := reflect.TypeOf(v)
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	_, ok := r.types[t.String()]
	return ok
}

// TypeNames returns the list of registered type names
func (r *TypeRegistry) TypeNames() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, 0, len(r.types))
	for name := range r.types {
		names = append(names, name)
	}
	return names
}

// Option returns an Option that uses this registry for type validation
func (r *TypeRegistry) Option() Option {
	return WithAllowedTypes(r.TypeNames()...)
}

// Decoder provides a reusable decoder with preset options
type Decoder struct {
	opts *Options
}

// NewDecoder creates a new decoder with the given options
func NewDecoder(opts ...Option) *Decoder {
	options := DefaultOptions()
	for _, opt := range opts {
		opt(options)
	}
	return &Decoder{opts: options}
}

// JSON decodes JSON data
func (d *Decoder) JSON(data []byte, v interface{}) error {
	return jsonUnmarshal(data, v, d.opts)
}

// JSONReader decodes JSON from a reader
func (d *Decoder) JSONReader(r io.Reader, v interface{}) error {
	return jsonDecode(r, v, d.opts)
}

// YAML decodes YAML data
func (d *Decoder) YAML(data []byte, v interface{}) error {
	return yamlUnmarshal(data, v, d.opts)
}

// YAMLReader decodes YAML from a reader
func (d *Decoder) YAMLReader(r io.Reader, v interface{}) error {
	return yamlDecode(r, v, d.opts)
}

// XML decodes XML data
func (d *Decoder) XML(data []byte, v interface{}) error {
	return xmlUnmarshal(data, v, d.opts)
}

// XMLReader decodes XML from a reader
func (d *Decoder) XMLReader(r io.Reader, v interface{}) error {
	return xmlDecode(r, v, d.opts)
}

// Gob decodes Gob data
func (d *Decoder) Gob(data []byte, v interface{}) error {
	return gobDecode(bytes.NewReader(data), v, d.opts)
}

// GobReader decodes Gob from a reader
func (d *Decoder) GobReader(r io.Reader, v interface{}) error {
	return gobDecode(r, v, d.opts)
}
