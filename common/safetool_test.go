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

func TestCoerceStringArrayProperties(t *testing.T) {
	props := map[string]bool{"paths": true, "tags": true}

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "JSON-encoded string array -> actual array",
			input: `{"paths":"[\"a\",\"b\",\"c\"]"}`,
			want:  `{"paths":["a","b","c"]}`,
		},
		{
			name:  "already an array - no change",
			input: `{"paths":["a","b"]}`,
			want:  `{"paths":["a","b"]}`,
		},
		{
			name:  "non-array prop string - no coercion",
			input: `{"other":"[\"a\"]","paths":["x"]}`,
			want:  `{"other":"[\"a\"]","paths":["x"]}`,
		},
		{
			name:  "string that is not a JSON array - no coercion",
			input: `{"paths":"not-an-array"}`,
			want:  `{"paths":"not-an-array"}`,
		},
		{
			name:  "multiple string-array props coerced",
			input: `{"paths":"[\"a\"]","tags":"[\"x\",\"y\"]"}`,
			want:  `{"paths":["a"],"tags":["x","y"]}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := coerceStringArrayProperties(json.RawMessage(tt.input), props)
			var gotV, wantV any
			if err := json.Unmarshal(got, &gotV); err != nil {
				t.Fatalf("result is not valid JSON: %v", err)
			}
			if err := json.Unmarshal([]byte(tt.want), &wantV); err != nil {
				t.Fatalf("want is not valid JSON: %v", err)
			}
			gotB, _ := json.Marshal(gotV)
			wantB, _ := json.Marshal(wantV)
			if string(gotB) != string(wantB) {
				t.Errorf("got %s, want %s", gotB, wantB)
			}
		})
	}
}

func TestIsStringArraySchema(t *testing.T) {
	strItems := &jsonschema.Schema{Type: "string"}
	tests := []struct {
		name   string
		schema *jsonschema.Schema
		want   bool
	}{
		{
			name:   "direct array of strings",
			schema: &jsonschema.Schema{Type: "array", Items: strItems},
			want:   true,
		},
		{
			name:   "nullable array (Types slice)",
			schema: &jsonschema.Schema{Types: []string{"null", "array"}, Items: strItems},
			want:   true,
		},
		{
			name:   "array of non-strings",
			schema: &jsonschema.Schema{Type: "array", Items: &jsonschema.Schema{Type: "object"}},
			want:   false,
		},
		{
			name:   "no Items",
			schema: &jsonschema.Schema{Type: "array"},
			want:   false,
		},
		{
			name:   "plain string",
			schema: &jsonschema.Schema{Type: "string"},
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isStringArraySchema(tt.schema)
			if got != tt.want {
				t.Errorf("isStringArraySchema() = %v, want %v", got, tt.want)
			}
		})
	}
}
