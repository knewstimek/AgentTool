package common

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestTruncateRunesKeepsUTF8Valid(t *testing.T) {
	got, truncated := TruncateRunes("가나다라마바사", 5, "…")
	if !truncated || got != "가나다라…" {
		t.Fatalf("got %q truncated=%v", got, truncated)
	}
	if !utf8.ValidString(got) {
		t.Fatal("truncation produced invalid UTF-8")
	}
}

func TestAppendWithinRuneBudgetIsAtomic(t *testing.T) {
	var sb strings.Builder
	used := 0
	if !AppendWithinRuneBudget(&sb, &used, "가나", 3) {
		t.Fatal("first fragment should fit")
	}
	if AppendWithinRuneBudget(&sb, &used, "다라", 3) {
		t.Fatal("second fragment should not fit")
	}
	if sb.String() != "가나" || used != 2 {
		t.Fatalf("partial fragment was appended: %q, used=%d", sb.String(), used)
	}
}

func TestTextLineCountMatchesScanLines(t *testing.T) {
	tests := map[string]int{
		"":           0,
		"one":        1,
		"one\n":      1,
		"one\ntwo":   2,
		"one\ntwo\n": 2,
		"one\n\n":    2,
	}
	for input, want := range tests {
		if got := TextLineCount(input); got != want {
			t.Errorf("TextLineCount(%q) = %d, want %d", input, got, want)
		}
	}
}

func TestLimitToolResultTextIsVisibleAndUTF8Safe(t *testing.T) {
	result := &mcp.CallToolResult{Content: []mcp.Content{
		&mcp.TextContent{Text: strings.Repeat("가", 200)},
	}}
	if !LimitToolResultText(result, 120) {
		t.Fatal("expected truncation")
	}
	got := result.Content[0].(*mcp.TextContent).Text
	if !utf8.ValidString(got) {
		t.Fatal("result is not valid UTF-8")
	}
	if utf8.RuneCountInString(got) > 120 {
		t.Fatalf("result exceeds limit: %d", utf8.RuneCountInString(got))
	}
	if !strings.Contains(got, "truncated=true") || !strings.Contains(got, "original_chars=200") {
		t.Fatalf("missing actionable truncation metadata: %q", got)
	}
}
