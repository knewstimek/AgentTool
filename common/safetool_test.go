package common

import (
	"encoding/json"
	"testing"

	"github.com/google/jsonschema-go/jsonschema"
)

func TestCoerceIntProperties(t *testing.T) {
	intProps := map[string]bool{
		"offset": true,
		"count":  true,
		"port":   true,
	}

	tests := []struct {
		name    string
		input   string
		wantKey string
		wantVal any
	}{
		{
			name:    "decimal string to int",
			input:   `{"offset":"123","file":"test.txt"}`,
			wantKey: "offset",
			wantVal: float64(123),
		},
		{
			name:    "hex string to int",
			input:   `{"offset":"0x1000"}`,
			wantKey: "offset",
			wantVal: float64(4096),
		},
		{
			name:    "octal string to int",
			input:   `{"offset":"0777"}`,
			wantKey: "offset",
			wantVal: float64(511),
		},
		{
			name:    "already int - no change",
			input:   `{"offset":42}`,
			wantKey: "offset",
			wantVal: float64(42),
		},
		{
			name:    "non-int prop string - no coercion",
			input:   `{"file":"123"}`,
			wantKey: "file",
			wantVal: "123",
		},
		{
			name:    "invalid number string - no coercion",
			input:   `{"offset":"hello"}`,
			wantKey: "offset",
			wantVal: "hello",
		},
		{
			name:    "negative decimal",
			input:   `{"count":"-5"}`,
			wantKey: "count",
			wantVal: float64(-5),
		},
		{
			name:    "multiple int props",
			input:   `{"offset":"10","count":"20","port":"8080"}`,
			wantKey: "port",
			wantVal: float64(8080),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := coerceIntProperties(json.RawMessage(tt.input), intProps)
			var m map[string]any
			if err := json.Unmarshal(result, &m); err != nil {
				t.Fatalf("failed to unmarshal result: %v", err)
			}
			got := m[tt.wantKey]
			if got != tt.wantVal {
				t.Errorf("key %q: got %v (%T), want %v (%T)", tt.wantKey, got, got, tt.wantVal, tt.wantVal)
			}
		})
	}
}

func TestCollectIntProperties(t *testing.T) {
	// nil schema
	result := collectIntProperties(nil)
	if len(result) != 0 {
		t.Errorf("expected empty map for nil schema, got %v", result)
	}

	// Direct integer type
	s := &jsonschema.Schema{
		Properties: map[string]*jsonschema.Schema{
			"count":  {Type: "integer"},
			"name":   {Type: "string"},
			"active": {Type: "boolean"},
		},
	}
	result = collectIntProperties(s)
	if !result["count"] {
		t.Error("expected count to be detected as integer")
	}
	if result["name"] {
		t.Error("name should not be detected as integer")
	}
}

func TestIsIntegerSchema(t *testing.T) {
	tests := []struct {
		name   string
		schema *jsonschema.Schema
		want   bool
	}{
		{
			name:   "direct integer",
			schema: &jsonschema.Schema{Type: "integer"},
			want:   true,
		},
		{
			name:   "string",
			schema: &jsonschema.Schema{Type: "string"},
			want:   false,
		},
		{
			name: "oneOf nullable integer",
			schema: &jsonschema.Schema{
				OneOf: []*jsonschema.Schema{
					{Type: "integer"},
					{Type: "null"},
				},
			},
			want: true,
		},
		{
			name: "anyOf nullable integer",
			schema: &jsonschema.Schema{
				AnyOf: []*jsonschema.Schema{
					{Type: "integer"},
					{Type: "null"},
				},
			},
			want: true,
		},
		{
			name: "oneOf without integer",
			schema: &jsonschema.Schema{
				OneOf: []*jsonschema.Schema{
					{Type: "string"},
					{Type: "null"},
				},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isIntegerSchema(tt.schema)
			if got != tt.want {
				t.Errorf("isIntegerSchema() = %v, want %v", got, tt.want)
			}
		})
	}
}
