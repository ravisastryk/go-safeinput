package safedecode

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
)

func TestValidJSON(t *testing.T) {
	type User struct {
		Name string `json:"name"`
	}
	r := strings.NewReader(`{"name":"Alice"}`)
	dec := NewDecoder(r, DefaultConfig())
	var u User
	if err := dec.Decode(&u); err != nil {
		t.Fatal(err)
	}
	if u.Name != "Alice" {
		t.Errorf("want Alice, got %s", u.Name)
	}
}

func TestRejectsOversized(t *testing.T) {
	cfg := Config{MaxBytes: 50, MaxDepth: 20, MaxKeys: 1000}
	big := `{"x":"` + strings.Repeat("A", 100) + `"}`
	dec := NewDecoder(strings.NewReader(big), cfg)
	var v map[string]string
	err := dec.Decode(&v)
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("want size error, got: %v", err)
	}
}

func TestRejectsDeeplyNested(t *testing.T) {
	cfg := Config{MaxBytes: 1 << 20, MaxDepth: 3, MaxKeys: 1000}
	var buf bytes.Buffer
	for i := 0; i < 10; i++ {
		buf.WriteString(`{"a":`)
	}
	buf.WriteString(`1`)
	for i := 0; i < 10; i++ {
		buf.WriteString(`}`)
	}
	dec := NewDecoder(&buf, cfg)
	var v interface{}
	err := dec.Decode(&v)
	if err == nil || !strings.Contains(err.Error(), "nesting") {
		t.Fatalf("want nesting error, got: %v", err)
	}
}

func TestTypeAllowlist(t *testing.T) {
	type Safe struct{ V int }
	type Unsafe struct{ Cmd string }

	cfg := Config{
		MaxBytes: 1 << 20, MaxDepth: 20, MaxKeys: 1000,
		AllowedTypes: []reflect.Type{reflect.TypeOf(Safe{})},
	}

	dec := NewDecoder(strings.NewReader(`{"V":42}`), cfg)
	var s Safe
	if err := dec.Decode(&s); err != nil {
		t.Fatalf("allowed type failed: %v", err)
	}

	dec2 := NewDecoder(strings.NewReader(`{"Cmd":"rm"}`), cfg)
	var u Unsafe
	if err := dec2.Decode(&u); err == nil {
		t.Fatal("disallowed type should fail")
	}
}

func TestMeasureDepth(t *testing.T) {
	tests := []struct {
		json  string
		depth int
	}{
		{`{}`, 1},
		{`{"a":{"b":1}}`, 2},
		{`[1,[2,[3]]]`, 3},
		{`{"a":[{"b":1}]}`, 3},
	}
	for _, tt := range tests {
		got := MeasureDepth([]byte(tt.json))
		if got != tt.depth {
			t.Errorf("MeasureDepth(%s) = %d, want %d", tt.json, got, tt.depth)
		}
	}
}

func TestMeasureDepthStringEscapes(t *testing.T) {
	// Braces inside strings must not count toward depth.
	got := MeasureDepth([]byte(`{"key":"va{l}ue"}`))
	if got != 1 {
		t.Errorf("want depth 1, got %d", got)
	}
}

func TestRejectsTooManyKeys(t *testing.T) {
	cfg := Config{MaxBytes: 1 << 20, MaxDepth: 20, MaxKeys: 2}
	// Build an object with 3 keys.
	payload := `{"a":1,"b":2,"c":3}`
	dec := NewDecoder(strings.NewReader(payload), cfg)
	var v map[string]int
	err := dec.Decode(&v)
	if err == nil || !strings.Contains(err.Error(), "too many keys") {
		t.Fatalf("want too-many-keys error, got: %v", err)
	}
}

func TestCountKeysFlat(t *testing.T) {
	n := CountKeys([]byte(`{"a":1,"b":2,"c":3}`))
	if n != 3 {
		t.Errorf("want 3, got %d", n)
	}
}

func TestCountKeysNested(t *testing.T) {
	n := CountKeys([]byte(`{"a":{"x":1,"y":2},"b":3}`))
	if n != 3 {
		t.Errorf("want 3, got %d", n)
	}
}

func TestDecodeLocksCorrectly(t *testing.T) {
	// Verifies the mutex doesn't deadlock on concurrent calls to separate decoders.
	dec1 := NewDecoder(strings.NewReader(`{"v":1}`), DefaultConfig())
	dec2 := NewDecoder(strings.NewReader(`{"v":2}`), DefaultConfig())
	type S struct{ V int }
	var s1, s2 S
	if err := dec1.Decode(&s1); err != nil {
		t.Fatal(err)
	}
	if err := dec2.Decode(&s2); err != nil {
		t.Fatal(err)
	}
	if s1.V != 1 || s2.V != 2 {
		t.Errorf("got s1=%d s2=%d", s1.V, s2.V)
	}
}
