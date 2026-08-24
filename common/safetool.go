package common

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"reflect"
	"runtime/debug"
	"strconv"
	"strings"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// SafeAddTool registers a typed tool handler with:
//   - panic recovery (prevents server crash)
//   - lenient int parsing: string values that look like numbers (e.g. "123",
//     "0x1000") are coerced to integers before schema validation, so agents
//     don't fail on trivial type mismatches.
//
// Differences from mcp.AddTool (intentional trade-offs):
//   - Uses encoding/json (case-insensitive field matching) instead of SDK's
//     segmentio/encoding/json (case-sensitive). This is more lenient for agents.
//   - Out is not attached as StructuredContent. Some MCP clients present
//     structured content instead of text, which would hide the human-readable
//     result; attaching both would duplicate large payloads. Continuation and
//     truncation metadata is therefore included visibly in text content.
//   - Handler errors are always returned as tool errors (IsError=true), not as
//     JSON-RPC protocol errors. This lets agents see the error and retry, rather
//     than getting an opaque transport error. The SDK's jsonrpc.Error type is in
//     an internal package and cannot be type-asserted here.
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
	// interface{} was historically used for lenient number/bool parsing. That
	// made the generated MCP schema omit the property's type, so agents had to
	// infer it from prose. Restore a precise schema here while keeping the raw
	// coercion below for clients that serialize scalars as strings.
	annotateFlexibleScalarTypes(schema, rt)
	t.InputSchema = schema

	resolved, err := schema.Resolve(&jsonschema.ResolveOptions{ValidateDefaults: true})
	if err != nil {
		panic(fmt.Sprintf("SafeAddTool %q: schema resolve failed: %v", toolName, err))
	}

	// Collect which properties are integer-typed for targeted coercion.
	// Handles both direct "integer" type and nullable patterns like
	// oneOf: [{type: "integer"}, {type: "null"}] (Go *int fields).
	intProps := collectIntProperties(schema)
	boolProps := collectBoolProperties(schema)

	// Collect which properties are string-array-typed for coercion.
	// Agents sometimes pass arrays as JSON-encoded strings (double-encoding),
	// e.g. paths: "[\"a\",\"b\"]" instead of paths: ["a","b"].
	// We fix this before validation so agents don't waste tokens on retries.
	strArrProps := collectStringArrayProperties(schema)

	rawHandler := func(ctx context.Context, req *mcp.CallToolRequest) (result *mcp.CallToolResult, err error) {
		// Every tool call passes through here, which makes it the one place the
		// idle watcher can learn the server is still in use.
		MarkActivity()

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
		if len(args) > 0 && len(boolProps) > 0 {
			args = coerceBoolProperties(args, boolProps)
		}

		// Coerce JSON-encoded string values to actual arrays for string-array-typed properties.
		if len(args) > 0 && len(strArrProps) > 0 {
			args = coerceStringArrayProperties(args, strArrProps)
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
		LimitToolResultText(res, HardOutputChars)
		return res, nil
	}

	s.AddTool(t, rawHandler)
}

// annotateFlexibleScalarTypes gives top-level interface{} fields the type the
// handler already expects through FlexInt or FlexBool. read.offset is the sole
// intentionally polymorphic top-level scalar and advertises that fact in its
// description, so it remains untyped.
func annotateFlexibleScalarTypes(schema *jsonschema.Schema, rt reflect.Type) {
	if schema == nil || schema.Properties == nil || rt.Kind() != reflect.Struct {
		return
	}
	interfaceType := reflect.TypeFor[any]()
	for i := 0; i < rt.NumField(); i++ {
		field := rt.Field(i)
		if field.Type != interfaceType {
			continue
		}
		jsonName := strings.Split(field.Tag.Get("json"), ",")[0]
		if jsonName == "" || jsonName == "-" {
			continue
		}
		property := schema.Properties[jsonName]
		if property == nil || property.Type != "" || len(property.Types) > 0 {
			continue
		}
		description := strings.ToLower(property.Description)
		if strings.Contains(description, "string range") || strings.Contains(description, "array") {
			continue
		}
		if strings.Contains(description, "true or false") ||
			strings.Contains(description, "default false") ||
			strings.Contains(description, "default true") {
			property.Type = "boolean"
		} else {
			property.Type = "integer"
		}
	}
}

// toolError creates a CallToolResult with IsError=true.
func toolError(msg string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		IsError: true,
	}
}

// collectIntProperties returns a set of top-level property names that are
// integer-typed in the given schema. Also detects nullable integer patterns
// like oneOf: [{type: "integer"}, {type: "null"}] which jsonschema-go
// generates for Go *int pointer fields.
func collectIntProperties(s *jsonschema.Schema) map[string]bool {
	result := make(map[string]bool)
	if s == nil || s.Properties == nil {
		return result
	}
	for name, prop := range s.Properties {
		if prop != nil && isIntegerSchema(prop) {
			result[name] = true
		}
	}
	return result
}

func collectBoolProperties(s *jsonschema.Schema) map[string]bool {
	result := make(map[string]bool)
	if s == nil || s.Properties == nil {
		return result
	}
	for name, prop := range s.Properties {
		if prop != nil && prop.Type == "boolean" {
			result[name] = true
		}
	}
	return result
}

// isIntegerSchema checks if a schema represents an integer type, either
// directly (type: "integer") or via oneOf/anyOf nullable patterns.
func isIntegerSchema(s *jsonschema.Schema) bool {
	if s.Type == "integer" {
		return true
	}
	for _, sub := range s.OneOf {
		if sub != nil && sub.Type == "integer" {
			return true
		}
	}
	for _, sub := range s.AnyOf {
		if sub != nil && sub.Type == "integer" {
			return true
		}
	}
	return false
}

// collectStringArrayProperties returns a set of top-level property names that are
// string-array-typed, including nullable slice variants (Types: ["null","array"]).
func collectStringArrayProperties(s *jsonschema.Schema) map[string]bool {
	result := make(map[string]bool)
	if s == nil || s.Properties == nil {
		return result
	}
	for name, prop := range s.Properties {
		if prop != nil && isStringArraySchema(prop) {
			result[name] = true
		}
	}
	return result
}

// isStringArraySchema reports whether s represents a string-array type,
// handling both direct array schemas and nullable variants (Types: ["null","array"]).
func isStringArraySchema(s *jsonschema.Schema) bool {
	hasArrayType := s.Type == "array"
	if !hasArrayType {
		for _, t := range s.Types {
			if t == "array" {
				hasArrayType = true
				break
			}
		}
	}
	return hasArrayType && s.Items != nil && s.Items.Type == "string"
}

// coerceStringArrayProperties converts JSON-encoded string values to actual arrays
// for properties known to be string-array-typed. Handles the common agent mistake
// of passing e.g. paths: "[\"a\",\"b\"]" (string) instead of paths: ["a","b"] (array).
func coerceStringArrayProperties(data json.RawMessage, strArrProps map[string]bool) json.RawMessage {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil {
		return data
	}

	changed := false
	for key, raw := range m {
		if !strArrProps[key] {
			continue
		}
		// Only coerce string values (starts with '"')
		if len(raw) < 2 || raw[0] != '"' {
			continue
		}
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			continue
		}
		// Try to parse the string content as a JSON array of strings
		var arr []string
		if err := json.Unmarshal([]byte(s), &arr); err != nil {
			continue
		}
		if b, err := json.Marshal(arr); err == nil {
			m[key] = b
			changed = true
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

// coerceBoolProperties preserves the old FlexBool leniency while exposing a
// proper boolean MCP schema. XML-based clients sometimes encode booleans as
// strings, and a few older callers used 0/1.
func coerceBoolProperties(data json.RawMessage, boolProps map[string]bool) json.RawMessage {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil {
		return data
	}

	changed := false
	for key, raw := range m {
		if !boolProps[key] {
			continue
		}
		var value any
		if err := json.Unmarshal(raw, &value); err != nil {
			continue
		}
		var normalized bool
		switch v := value.(type) {
		case string:
			switch strings.ToLower(strings.TrimSpace(v)) {
			case "true", "1":
				normalized = true
			case "false", "0":
				normalized = false
			default:
				continue
			}
		case float64:
			if v != 0 && v != 1 {
				continue
			}
			normalized = v == 1
		default:
			continue
		}
		m[key] = json.RawMessage(strconv.FormatBool(normalized))
		changed = true
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
