package common

import (
	"strconv"
	"strings"
)

// FlexInt converts an interface{} to int, accepting both JSON number and
// string representations. Some MCP clients (e.g. Claude Code via XML tool
// call format) may pass integer parameters as JSON strings instead of numbers.
func FlexInt(v interface{}) (int, bool) {
	switch val := v.(type) {
	case float64:
		return int(val), true
	case int:
		return val, true
	case int64:
		return int(val), true
	case string:
		s := strings.TrimSpace(val)
		if s == "" {
			return 0, true
		}
		n, err := strconv.Atoi(s)
		if err != nil {
			return 0, false
		}
		return n, true
	case nil:
		return 0, true
	}
	return 0, false
}
