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
