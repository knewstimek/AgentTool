package common

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	// DefaultOutputChars is the normal response budget for tools that can emit
	// user-controlled or data-dependent amounts of text.
	DefaultOutputChars = 32 * 1024
	// HardOutputChars is a final server-wide safety net. Individual tools should
	// normally use DefaultOutputChars and provide a useful continuation cursor.
	HardOutputChars = 128 * 1024
)

// TextLineCount returns the number of lines bufio.ScanLines will expose. A
// final newline terminates the last line; it does not create a phantom empty
// line that would send an agent to a nonexistent continuation offset.
func TextLineCount(text string) int {
	if text == "" {
		return 0
	}
	count := strings.Count(text, "\n")
	if !strings.HasSuffix(text, "\n") {
		count++
	}
	return count
}

// TruncateRunes limits text by Unicode code points rather than bytes so tool
// output never contains a broken UTF-8 sequence. The caller supplies the
// suffix because different tools need different continuation guidance.
func TruncateRunes(text string, maxRunes int, suffix string) (string, bool) {
	if maxRunes < 0 || utf8.RuneCountInString(text) <= maxRunes {
		return text, false
	}
	if maxRunes == 0 {
		return "", true
	}
	runes := []rune(text)
	if len([]rune(suffix)) >= maxRunes {
		return string(runes[:maxRunes]), true
	}
	keep := maxRunes - len([]rune(suffix))
	return string(runes[:keep]) + suffix, true
}

// AppendWithinRuneBudget appends text only when the complete fragment fits.
// Keeping result records atomic lets callers report an exact continuation
// offset instead of cutting a row, variable, or symbol in half.
func AppendWithinRuneBudget(sb *strings.Builder, used *int, text string, maxRunes int) bool {
	n := utf8.RuneCountInString(text)
	if maxRunes > 0 && *used+n > maxRunes {
		return false
	}
	sb.WriteString(text)
	*used += n
	return true
}

// LimitToolResultText applies the server-wide last-resort response cap to all
// text content in a tool result. Tool-specific pagination remains preferable:
// this guard exists so a newly-added or overlooked tool can never dump
// megabytes into an agent context without saying that data was omitted.
// Non-text content (for example MCP images) is left untouched.
func LimitToolResultText(result *mcp.CallToolResult, maxRunes int) bool {
	if result == nil || maxRunes <= 0 {
		return false
	}

	total := 0
	for _, content := range result.Content {
		if text, ok := content.(*mcp.TextContent); ok {
			total += utf8.RuneCountInString(text.Text)
		}
	}
	if total <= maxRunes {
		return false
	}

	suffix := fmt.Sprintf(
		"\n[truncated=true; original_chars=%d; limit=%d; narrow the request or use paging parameters]",
		total, maxRunes,
	)
	remaining := maxRunes
	markerWritten := false
	filtered := make([]mcp.Content, 0, len(result.Content))
	for _, content := range result.Content {
		text, ok := content.(*mcp.TextContent)
		if !ok {
			filtered = append(filtered, content)
			continue
		}
		if markerWritten {
			continue
		}

		count := utf8.RuneCountInString(text.Text)
		if count < remaining-utf8.RuneCountInString(suffix) {
			filtered = append(filtered, text)
			remaining -= count
			continue
		}

		limited, _ := TruncateRunes(text.Text, remaining, suffix)
		copyText := *text
		copyText.Text = limited
		filtered = append(filtered, &copyText)
		markerWritten = true
	}
	result.Content = filtered
	return true
}
