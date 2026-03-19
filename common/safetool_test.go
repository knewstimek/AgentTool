package common

import (
	"encoding/json"
	"testing"
)

func TestCoerceIntProperties(t *testing.T) {
	intProps := map[string]bool{
		"offset": true,
		"count":  true,
		"port":   true,
	}

	tests := []struct {
		name     string
		input    string
		wantKey  string
		wantVal  any // nil = unchanged from input
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
	// Quick smoke test with nil schema
	result := collectIntProperties(nil)
	if len(result) != 0 {
		t.Errorf("expected empty map for nil schema, got %v", result)
	}
}
