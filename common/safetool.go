package common

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"reflect"
	"runtime/debug"
	"strconv"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// SafeAddTool registers a typed tool handler with:
//   - panic recovery (prevents server crash)
//   - lenient int parsing: string values that look like numbers (e.g. "123",
//     "0x1000") are coerced to integers before schema validation, so agents
//     don't fail on trivial type mismatches.
func SafeAddTool[In, Out any](s *mcp.Server, t *mcp.Tool, h mcp.ToolHandlerFor[In, Out]) {
	toolName := t.Name

	// Generate input schema from the In type so agents see correct parameter info.
	rt := reflect.TypeFor[In]()
	if rt.Kind() == reflect.Pointer {
		rt = rt.Elem()
	}
	schema, err := jsonschema.ForType(rt, &jsonschema.ForOptions{})
	if err != nil {
		panic(fmt.Sprintf("SafeAddTool %q: schema generation failed: %v", toolName, err))
	}
	t.InputSchema = schema

	resolved, err := schema.Resolve(&jsonschema.ResolveOptions{ValidateDefaults: true})
	if err != nil {
		panic(fmt.Sprintf("SafeAddTool %q: schema resolve failed: %v", toolName, err))
	}

	// Collect which properties are integer-typed for targeted coercion.
	intProps := collectIntProperties(schema)

	rawHandler := func(ctx context.Context, req *mcp.CallToolRequest) (result *mcp.CallToolResult, err error) {
		defer func() {
			if r := recover(); r != nil {
				stack := debug.Stack()
				log.Printf("PANIC in tool %q: %v\n%s", toolName, r, stack)
				result = toolError(fmt.Sprintf("internal error: panic in %s (see server logs)", toolName))
			}
		}()

		// Coerce string values to numbers for integer-typed properties.
		args := req.Params.Arguments
		if len(args) > 0 && len(intProps) > 0 {
			args = coerceIntProperties(args, intProps)
		}

		// Apply defaults and validate against schema.
		var v map[string]any
		if len(args) > 0 {
			if err := json.Unmarshal(args, &v); err != nil {
				return toolError(fmt.Sprintf("invalid arguments: %v", err)), nil
			}
		} else {
			v = make(map[string]any)
		}
		if err := resolved.ApplyDefaults(&v); err != nil {
			return toolError(fmt.Sprintf("applying defaults: %v", err)), nil
		}
		if err := resolved.Validate(&v); err != nil {
			return toolError(fmt.Sprintf("validation error: %v", err)), nil
		}

		// Re-marshal with defaults applied, then unmarshal into typed input.
		data, err := json.Marshal(v)
		if err != nil {
			return toolError(fmt.Sprintf("re-marshal error: %v", err)), nil
		}
		var in In
		if err := json.Unmarshal(data, &in); err != nil {
			return toolError(fmt.Sprintf("unmarshal error: %v", err)), nil
		}

		res, _, handlerErr := h(ctx, req, in)
		if handlerErr != nil {
			return toolError(handlerErr.Error()), nil
		}
		return res, nil
	}

	s.AddTool(t, rawHandler)
}

// toolError creates a CallToolResult with IsError=true.
func toolError(msg string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		IsError: true,
	}
}

// collectIntProperties returns a set of top-level property names that have
// type "integer" in the given schema.
func collectIntProperties(s *jsonschema.Schema) map[string]bool {
	result := make(map[string]bool)
	if s == nil || s.Properties == nil {
		return result
	}
	for name, prop := range s.Properties {
		if prop != nil && prop.Type == "integer" {
			result[name] = true
		}
	}
	return result
}

// coerceIntProperties takes raw JSON arguments and converts string values
// to numbers for properties that are known to be integer-typed.
// Supports decimal ("123"), hex ("0x1000"), and octal ("0777") strings.
func coerceIntProperties(data json.RawMessage, intProps map[string]bool) json.RawMessage {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil {
		return data // can't parse, return as-is
	}

	changed := false
	for key, raw := range m {
		if !intProps[key] {
			continue
		}
		// Check if value is a JSON string (starts with '"')
		if len(raw) < 2 || raw[0] != '"' {
			continue
		}
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			continue
		}
		// Try parsing as integer (base 0 = auto-detect: decimal, hex, octal)
		if n, err := strconv.ParseInt(s, 0, 64); err == nil {
			if b, err := json.Marshal(n); err == nil {
				m[key] = b
				changed = true
			}
		}
	}

	if !changed {
		return data
	}
	result, err := json.Marshal(m)
	if err != nil {
		return data
	}
	return result
}
