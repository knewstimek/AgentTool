package common

import "strings"

// FlexBool converts an interface{} to bool, accepting both JSON boolean and
// string "true"/"false". Some MCP clients (e.g. Claude Code via XML tool call
// format) pass boolean parameters as JSON strings instead of JSON booleans,
// which fails strict schema type validation. Using interface{} for bool fields
// and FlexBool for conversion accepts both representations.
func FlexBool(v interface{}) bool {
	switch val := v.(type) {
	case bool:
		return val
	case string:
		return strings.ToLower(val) == "true"
	case float64:
		return val != 0
	}
	return false
}
