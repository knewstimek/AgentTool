package grep

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestHandleBoundsLongLinesAndTotalOutput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "large.txt")
	line := "MATCH-" + strings.Repeat("가", 200)
	if err := os.WriteFile(path, []byte(line+"\n"+line+"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	result, out, err := Handle(context.Background(), nil, GrepInput{
		Pattern: "MATCH", Path: path, MaxResults: 100000,
		MaxLineChars: 40, MaxOutputChars: 60,
	})
	if err != nil || result.IsError {
		t.Fatalf("grep failed: err=%v result=%+v", err, result)
	}
	text := result.Content[0].(*mcp.TextContent).Text
	if !utf8.ValidString(text) {
		t.Fatal("result is not valid UTF-8")
	}
	if utf8.RuneCountInString(text) > 60 {
		t.Fatalf("output exceeded limit: %d", utf8.RuneCountInString(text))
	}
	if !strings.Contains(text, "line truncated") {
		t.Fatalf("missing long-line marker: %q", text)
	}
	if !out.Truncated {
		t.Fatal("expected total output truncation")
	}
}

func TestHandleAllowsLargeResultLimitButRejectsRunawayValue(t *testing.T) {
	path := filepath.Join(t.TempDir(), "one.txt")
	if err := os.WriteFile(path, []byte("match\n"), 0644); err != nil {
		t.Fatal(err)
	}
	result, _, _ := Handle(context.Background(), nil, GrepInput{Pattern: "match", Path: path, MaxResults: hardMaxResults})
	if result.IsError {
		t.Fatal("documented maximum should be accepted")
	}
	result, _, _ = Handle(context.Background(), nil, GrepInput{Pattern: "match", Path: path, MaxResults: hardMaxResults + 1})
	if !result.IsError {
		t.Fatal("value above hard maximum should be rejected")
	}
}

func TestSearchFileStopsBuildingContextAtOutputBudget(t *testing.T) {
	path := filepath.Join(t.TempDir(), "context.txt")
	content := strings.Repeat("context line\n", 1000) + "MATCH\n" + strings.Repeat("context line\n", 1000)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	result, err := searchFile(path, regexp.MustCompile("MATCH"), hardMaxResults, searchOpts{
		before: 1000, after: 1000, maxLineChars: 100, maxOutputChars: 200,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.outputTruncated {
		t.Fatal("expected search-time output truncation")
	}
	if result.displayChars > 200 || len(result.matches) > 20 {
		t.Fatalf("search accumulated too much output: chars=%d lines=%d", result.displayChars, len(result.matches))
	}
}

func TestHandleReportsExactHasMoreBoundaryToMCP(t *testing.T) {
	for _, tc := range []struct {
		name    string
		content string
		hasMore bool
	}{
		{name: "exact limit", content: "match one\nmatch two\n", hasMore: false},
		{name: "one beyond limit", content: "match one\nmatch two\nmatch three\n", hasMore: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "matches.txt")
			if err := os.WriteFile(path, []byte(tc.content), 0644); err != nil {
				t.Fatal(err)
			}

			result, out, err := Handle(context.Background(), nil, GrepInput{
				Pattern: "match", Path: path, MaxResults: 2, MaxOutputChars: 10000,
			})
			if err != nil || result.IsError {
				t.Fatalf("grep failed: err=%v result=%+v", err, result)
			}
			if out.HasMore != tc.hasMore || out.LimitReached != tc.hasMore {
				t.Fatalf("has_more=%v limit_reached=%v, want %v", out.HasMore, out.LimitReached, tc.hasMore)
			}
			// Structured output would be rendered instead of the text by clients
			// that support it, hiding every matching line.
			if result.StructuredContent != nil {
				t.Fatalf("grep must return text only, got structured %#v", result.StructuredContent)
			}
			text := result.Content[0].(*mcp.TextContent).Text
			if !strings.Contains(text, "match one") {
				t.Fatalf("matching lines missing from the text the agent sees: %q", text)
			}
			if strings.Contains(text, "More grep results") != tc.hasMore {
				t.Fatalf("visible continuation marker mismatch: %q", text)
			}
		})
	}
}

func TestDirectoryHasMoreLooksPastExactFileBoundary(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("match\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.txt"), []byte("match\n"), 0644); err != nil {
		t.Fatal(err)
	}

	_, out, err := Handle(context.Background(), nil, GrepInput{
		Pattern: "match", Path: dir, MaxResults: 1, MaxOutputChars: 10000,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !out.HasMore {
		t.Fatal("expected directory look-ahead to find a match in the next file")
	}
}
