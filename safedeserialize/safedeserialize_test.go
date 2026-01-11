package safedeserialize

import (
	"bytes"
	"encoding/gob"
	"strings"
	"testing"
)

// Test types
type SimpleUser struct {
	ID    int    `json:"id" yaml:"id" xml:"id"`
	Name  string `json:"name" yaml:"name" xml:"name"`
	Email string `json:"email" yaml:"email" xml:"email"`
}

type NestedConfig struct {
	Server   ServerConfig   `json:"server" yaml:"server" xml:"server"`
	Database DatabaseConfig `json:"database" yaml:"database" xml:"database"`
}

type ServerConfig struct {
	Host string `json:"host" yaml:"host" xml:"host"`
	Port int    `json:"port" yaml:"port" xml:"port"`
}

type DatabaseConfig struct {
	Host     string `json:"host" yaml:"host" xml:"host"`
	Port     int    `json:"port" yaml:"port" xml:"port"`
	Name     string `json:"name" yaml:"name" xml:"name"`
	MaxConns int    `json:"max_conns" yaml:"max_conns" xml:"max_conns"`
}

type UnsafeStruct struct {
	Name string `json:"name"`
	Data any    `json:"data"`
}

type MapInterfaceStruct struct {
	Name   string         `json:"name"`
	Fields map[string]any `json:"fields"`
}

type SliceInterfaceStruct struct {
	Name  string `json:"name"`
	Items []any  `json:"items"`
}

// ============================================================================
// Table-Driven JSON Tests
// ============================================================================

func TestJSON(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		target  any
		opts    []Option
		wantErr bool
		errType error
		check   func(t *testing.T, target any)
	}{
		{name: "valid simple", data: []byte(`{"id": 1, "name": "John", "email": "john@example.com"}`), target: &SimpleUser{}, check: func(t *testing.T, v any) {
			if v.(*SimpleUser).ID != 1 {
				t.Error("bad ID")
			}
		}},
		{name: "valid nested", data: []byte(`{"server": {"host": "localhost", "port": 8080}, "database": {"host": "db.local", "port": 5432, "name": "mydb", "max_conns": 10}}`), target: &NestedConfig{}, check: func(t *testing.T, v any) {
			if v.(*NestedConfig).Server.Port != 8080 {
				t.Error("bad port")
			}
		}},
		{name: "any", data: []byte(`{}`), target: new(any), wantErr: true, errType: ErrInterfaceTarget},
		{name: "map interface", data: []byte(`{}`), target: &map[string]any{}, wantErr: true, errType: ErrMapInterface},
		{name: "slice interface", data: []byte(`[]`), target: &[]any{}, wantErr: true, errType: ErrSliceInterface},
		{name: "nil target", data: []byte(`{}`), target: nil, wantErr: true, errType: ErrNilTarget},
		{name: "non-pointer", data: []byte(`{}`), target: SimpleUser{}, wantErr: true, errType: ErrNotPointer},
		{name: "oversized", data: bytes.Repeat([]byte("x"), 2<<20), target: &SimpleUser{}, wantErr: true},
		{name: "empty", data: []byte{}, target: &SimpleUser{}, wantErr: true, errType: ErrEmptyData},
		{name: "size limit", data: bytes.Repeat([]byte(`{"id": 1234567890}`), 100), target: &SimpleUser{}, opts: []Option{WithMaxSize(10)}, wantErr: true},
		{name: "type not allowed", data: []byte(`{"id": 1, "name": "a", "email": "a@b.c"}`), target: &SimpleUser{}, opts: []Option{WithAllowedTypes("Other")}, wantErr: true},
		{name: "type allowed", data: []byte(`{"id": 1, "name": "a", "email": "a@b.c"}`), target: &SimpleUser{}, opts: []Option{WithAllowedTypes("safedeserialize.SimpleUser")}},
		{name: "non-strict", data: []byte(`{"id": 1, "name": "a", "email": "a@b.c", "x": 1}`), target: &SimpleUser{}, opts: []Option{WithStrictMode(false)}},
		{name: "allow map", data: []byte(`{"a": 1}`), target: &map[string]any{}, opts: []Option{WithAllowMapStringInterface(true)}},
		{name: "allow slice", data: []byte(`[1, 2]`), target: &[]any{}, opts: []Option{WithAllowSliceInterface(true)}},
		{name: "deep nest", data: []byte(strings.Repeat(`{"a":`, 50) + `1` + strings.Repeat(`}`, 50)), target: &struct{ A any }{}, opts: []Option{WithMaxDepth(32)}, wantErr: true},
		{name: "strict rejects unknown", data: []byte(`{"id": 1, "name": "a", "email": "a@b.c", "unknown": 1}`), target: &SimpleUser{}, opts: []Option{WithStrictMode(true)}, wantErr: true},
		{name: "unsafe struct", data: []byte(`{"name": "test", "data": "value"}`), target: &UnsafeStruct{}, opts: []Option{WithStrictMode(true)}, wantErr: true},
		{name: "map interface struct", data: []byte(`{"name": "test", "fields": {"key": "value"}}`), target: &MapInterfaceStruct{}, opts: []Option{WithStrictMode(true)}, wantErr: true},
		{name: "map interface allowed", data: []byte(`{"name": "test", "fields": {"key": "value"}}`), target: &MapInterfaceStruct{}, opts: []Option{WithAllowMapStringInterface(true), WithStrictMode(false)}},
		{name: "slice interface struct", data: []byte(`{"name": "test", "items": [1, 2, 3]}`), target: &SliceInterfaceStruct{}, opts: []Option{WithStrictMode(true)}, wantErr: true},
		{name: "slice interface allowed", data: []byte(`{"name": "test", "items": [1, 2, 3]}`), target: &SliceInterfaceStruct{}, opts: []Option{WithAllowSliceInterface(true), WithStrictMode(false)}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := JSON(tt.data, tt.target, tt.opts...)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error")
				} else if tt.errType != nil && err != tt.errType && !strings.Contains(err.Error(), "exceeds") && !strings.Contains(err.Error(), "depth") && !strings.Contains(err.Error(), "any") && !strings.Contains(err.Error(), "unknown field") {
					t.Errorf("expected error %v, got %v", tt.errType, err)
				}
			} else if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if err == nil && tt.check != nil {
				tt.check(t, tt.target)
			}
		})
	}
}

// ============================================================================
// Reader Tests
// ============================================================================

func TestReaders(t *testing.T) {
	tests := []struct {
		name    string
		fn      func(any, ...Option) error
		target  any
		wantErr bool
	}{
		{name: "JSONReader", fn: func(v any, opts ...Option) error {
			return JSONReader(strings.NewReader(`{"id": 1, "name": "a", "email": "a@b.c"}`), v, opts...)
		}, target: &SimpleUser{}},
		{name: "JSONReader interface", fn: func(v any, opts ...Option) error {
			return JSONReader(strings.NewReader(`{}`), v, opts...)
		}, target: new(any), wantErr: true},
		{name: "JSONReader oversized", fn: func(v any, _ ...Option) error {
			return JSONReader(strings.NewReader(strings.Repeat("x", 10000)), v, WithMaxSize(100))
		}, target: &SimpleUser{}, wantErr: true},
		{name: "YAMLReader", fn: func(v any, opts ...Option) error {
			return YAMLReader(strings.NewReader("id: 1\nname: a\nemail: a@b.c"), v, opts...)
		}, target: &SimpleUser{}},
		{name: "YAMLReader interface", fn: func(v any, opts ...Option) error {
			return YAMLReader(strings.NewReader("a: 1"), v, opts...)
		}, target: new(any), wantErr: true},
		{name: "YAMLReader oversized", fn: func(v any, _ ...Option) error {
			return YAMLReader(strings.NewReader(strings.Repeat("x: y\n", 10000)), v, WithMaxSize(100))
		}, target: &SimpleUser{}, wantErr: true},
		{name: "XMLReader", fn: func(v any, opts ...Option) error {
			return XMLReader(strings.NewReader(`<SimpleUser><id>1</id><name>a</name><email>a@b.c</email></SimpleUser>`), v, opts...)
		}, target: &SimpleUser{}},
		{name: "XMLReader interface", fn: func(v any, opts ...Option) error {
			return XMLReader(strings.NewReader(`<root></root>`), v, opts...)
		}, target: new(any), wantErr: true},
		{name: "XMLReader oversized", fn: func(v any, _ ...Option) error {
			return XMLReader(strings.NewReader(strings.Repeat("<item>x</item>", 10000)), v, WithMaxSize(100))
		}, target: &SimpleUser{}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.fn(tt.target)
			if tt.wantErr && err == nil {
				t.Error("expected error")
			} else if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// ============================================================================
// YAML, XML, Gob Tests
// ============================================================================

func TestYAML(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		target  any
		opts    []Option
		wantErr bool
	}{
		{name: "valid", data: []byte("id: 1\nname: a\nemail: a@b.c"), target: &SimpleUser{}},
		{name: "interface", data: []byte("a: 1"), target: new(any), wantErr: true},
		{name: "oversized", data: bytes.Repeat([]byte("x"), 2<<20), target: &SimpleUser{}, wantErr: true},
		{name: "empty", data: []byte{}, target: &SimpleUser{}, wantErr: true},
		{name: "non-strict", data: []byte("id: 1\nname: a\nemail: a@b.c\nx: 1"), target: &SimpleUser{}, opts: []Option{WithStrictMode(false)}},
		{name: "strict rejects", data: []byte("id: 1\nname: a\nemail: a@b.c\nx: 1"), target: &SimpleUser{}, opts: []Option{WithStrictMode(true)}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := YAML(tt.data, tt.target, tt.opts...)
			if (err != nil) != tt.wantErr {
				t.Errorf("wantErr=%v, got err=%v", tt.wantErr, err)
			}
		})
	}
}

func TestXML(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		target  any
		opts    []Option
		wantErr bool
	}{
		{name: "valid", data: []byte(`<SimpleUser><id>1</id><name>a</name><email>a@b.c</email></SimpleUser>`), target: &SimpleUser{}},
		{name: "interface", data: []byte(`<root></root>`), target: new(any), wantErr: true},
		{name: "empty", data: []byte{}, target: &SimpleUser{}, wantErr: true},
		{name: "strict", data: []byte(`<SimpleUser><id>1</id><name>a</name><email>a@b.c</email></SimpleUser>`), target: &SimpleUser{}, opts: []Option{WithStrictMode(true)}},
		{name: "non-strict", data: []byte(`<SimpleUser><id>1</id><name>a</name><email>a@b.c</email></SimpleUser>`), target: &SimpleUser{}, opts: []Option{WithStrictMode(false)}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := XML(tt.data, tt.target, tt.opts...)
			if (err != nil) != tt.wantErr {
				t.Errorf("wantErr=%v, got err=%v", tt.wantErr, err)
			}
		})
	}
}

func TestGob(t *testing.T) {
	encode := func(v any) ([]byte, *bytes.Buffer) {
		var buf bytes.Buffer
		if err := gob.NewEncoder(&buf).Encode(v); err != nil {
			t.Fatal(err)
		}
		return buf.Bytes(), &buf
	}

	data, buf := encode(&SimpleUser{ID: 1, Name: "a", Email: "a@b.c"})

	tests := []struct {
		name    string
		fn      func() error
		wantErr bool
	}{
		{name: "Gob valid", fn: func() error { return Gob(data, &SimpleUser{}) }},
		{name: "Gob interface", fn: func() error { d, _ := encode("test"); return Gob(d, new(any)) }, wantErr: true},
		{name: "GobReader valid", fn: func() error { return GobReader(buf, &SimpleUser{}) }},
		{name: "GobReader interface", fn: func() error { _, b := encode("test"); return GobReader(b, new(any)) }, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.fn()
			if (err != nil) != tt.wantErr {
				t.Errorf("wantErr=%v, got err=%v", tt.wantErr, err)
			}
		})
	}
}

// ============================================================================
// Decoder Tests
// ============================================================================

func TestDecoder(t *testing.T) {
	decoder := NewDecoder(WithMaxSize(1 << 20))

	tests := []struct {
		name string
		fn   func() error
	}{
		{name: "JSON", fn: func() error { return decoder.JSON([]byte(`{"id":1,"name":"a","email":"a@b.c"}`), &SimpleUser{}) }},
		{name: "JSONReader", fn: func() error {
			return decoder.JSONReader(strings.NewReader(`{"id":1,"name":"a","email":"a@b.c"}`), &SimpleUser{})
		}},
		{name: "YAML", fn: func() error { return decoder.YAML([]byte("id: 1\nname: a\nemail: a@b.c"), &SimpleUser{}) }},
		{name: "YAMLReader", fn: func() error {
			return decoder.YAMLReader(strings.NewReader("id: 1\nname: a\nemail: a@b.c"), &SimpleUser{})
		}},
		{name: "XML", fn: func() error {
			return decoder.XML([]byte(`<SimpleUser><id>1</id><name>a</name><email>a@b.c</email></SimpleUser>`), &SimpleUser{})
		}},
		{name: "XMLReader", fn: func() error {
			return decoder.XMLReader(strings.NewReader(`<SimpleUser><id>1</id><name>a</name><email>a@b.c</email></SimpleUser>`), &SimpleUser{})
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.fn(); err != nil {
				t.Error(err)
			}
		})
	}

	t.Run("Gob", func(t *testing.T) {
		var buf bytes.Buffer
		if err := gob.NewEncoder(&buf).Encode(&SimpleUser{ID: 1}); err != nil {
			t.Fatal(err)
		}
		if err := decoder.Gob(buf.Bytes(), &SimpleUser{}); err != nil {
			t.Error(err)
		}
	})

	t.Run("GobReader", func(t *testing.T) {
		var buf bytes.Buffer
		if err := gob.NewEncoder(&buf).Encode(&SimpleUser{ID: 1}); err != nil {
			t.Fatal(err)
		}
		if err := decoder.GobReader(&buf, &SimpleUser{}); err != nil {
			t.Error(err)
		}
	})

	t.Run("Reusable", func(t *testing.T) {
		r := NewTypeRegistry()
		r.Register(SimpleUser{})
		d := NewDecoder(WithMaxSize(1<<16), WithMaxDepth(16), r.Option())
		for i := 0; i < 3; i++ {
			if err := d.JSON([]byte(`{"id":1,"name":"a","email":"a@b.c"}`), &SimpleUser{}); err != nil {
				t.Fatal(err)
			}
		}
	})
}

// ============================================================================
// TypeRegistry Tests
// ============================================================================

func TestTypeRegistry(t *testing.T) {
	r := NewTypeRegistry()
	r.Register(SimpleUser{})
	r.Register(&NestedConfig{})

	if !r.IsRegistered(SimpleUser{}) || !r.IsRegistered(&SimpleUser{}) || !r.IsRegistered(NestedConfig{}) {
		t.Error("types not registered correctly")
	}

	type UnregisteredType struct{}
	if r.IsRegistered(UnregisteredType{}) {
		t.Error("should not be registered")
	}

	r2 := NewTypeRegistry()
	r2.RegisterMultiple(SimpleUser{}, NestedConfig{})
	if len(r2.TypeNames()) != 2 {
		t.Error("expected 2 types")
	}

	if err := JSON([]byte(`{"id":1,"name":"a","email":"a@b.c"}`), &SimpleUser{}, r.Option()); err != nil {
		t.Error(err)
	}
}

// ============================================================================
// Validation and Options Tests
// ============================================================================

func TestValidation(t *testing.T) {
	opts := DefaultOptions()

	tests := []struct {
		name    string
		target  any
		wantErr bool
	}{
		{name: "nil pointer", target: (*SimpleUser)(nil), wantErr: true},
		{name: "map concrete", target: &map[string]string{}},
		{name: "slice concrete", target: &[]string{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateTarget(tt.target, opts)
			if (err != nil) != tt.wantErr {
				t.Errorf("wantErr=%v, got err=%v", tt.wantErr, err)
			}
		})
	}
}

func TestOptions(t *testing.T) {
	opts := DefaultOptions()
	if opts.MaxSize != DefaultMaxSize || opts.MaxDepth != DefaultMaxDepth || !opts.StrictMode {
		t.Error("default options incorrect")
	}

	WithMaxSize(0)(opts)
	WithMaxSize(-1)(opts)
	if opts.MaxSize != DefaultMaxSize {
		t.Error("invalid values ignored")
	}

	WithMaxDepth(0)(opts)
	WithMaxDepth(-1)(opts)
	if opts.MaxDepth != DefaultMaxDepth {
		t.Error("invalid values ignored")
	}

	WithMaxSize(100)(opts)
	if opts.MaxSize != 100 {
		t.Error("valid value not set")
	}

	WithMaxDepth(10)(opts)
	if opts.MaxDepth != 10 {
		t.Error("valid value not set")
	}
}

func TestMeasureJSONDepth(t *testing.T) {
	tests := []struct {
		json  string
		depth int
	}{
		{`{}`, 1},
		{`{"a": 1}`, 1},
		{`{"a": {"b": 1}}`, 2},
		{`{"a": {"b": {"c": 1}}}`, 3},
		{`[1, 2]`, 1},
		{`[[1]]`, 2},
		{`{"a": [{"b": 1}]}`, 3},
		{`{"a": "{not nested}"}`, 1},
		{`{"a": "\"test\""}`, 1},
	}

	for _, tt := range tests {
		if d := measureJSONDepth([]byte(tt.json)); d != tt.depth {
			t.Errorf("json=%s: expected %d, got %d", tt.json, tt.depth, d)
		}
	}
}

// ============================================================================
// Benchmarks
// ============================================================================

func BenchmarkJSON(b *testing.B) {
	data := []byte(`{"id": 1, "name": "John", "email": "john@example.com"}`)
	var u SimpleUser
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = JSON(data, &u)
	}
}

func BenchmarkDecoder(b *testing.B) {
	decoder := NewDecoder()
	data := []byte(`{"id": 1, "name": "John", "email": "john@example.com"}`)
	var u SimpleUser
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = decoder.JSON(data, &u)
	}
}
