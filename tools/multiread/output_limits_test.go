package multiread

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestMultiReadUsesOneTotalBudget(t *testing.T) {
	dir := t.TempDir()
	var paths []string
	for i := 0; i < 3; i++ {
		path := filepath.Join(dir, string(rune('a'+i))+".txt")
		if err := os.WriteFile(path, []byte(strings.Repeat("0123456789abcdefghijklmnopqrstuvwxyz\n", 500)), 0o600); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, path)
	}

	result, out, err := Handle(context.Background(), nil, MultiReadInput{FilePaths: paths})
	if err != nil || result.IsError {
		t.Fatalf("multiread failed: err=%v result=%v", err, result)
	}
	text := result.Content[0].(*mcp.TextContent).Text
	if utf8.RuneCountInString(text) > 32768 {
		t.Fatalf("result exceeded default total budget: %d", utf8.RuneCountInString(text))
	}
	if !out.Truncated || !strings.Contains(text, "truncated=true") {
		t.Fatalf("missing visible truncation metadata: %+v", out)
	}
}

func TestMultiReadLongLineDoesNotDisappear(t *testing.T) {
	path := filepath.Join(t.TempDir(), "long.txt")
	if err := os.WriteFile(path, []byte(strings.Repeat("가", 70000)+"\nsecond\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	result, out, err := Handle(context.Background(), nil, MultiReadInput{FilePaths: []string{path}})
	if err != nil || result.IsError {
		t.Fatalf("multiread failed: err=%v result=%v", err, result)
	}
	text := result.Content[0].(*mcp.TextContent).Text
	if out.ErrorCount != 0 || !strings.Contains(text, "line_truncated=true") || !strings.Contains(text, "second") {
		t.Fatalf("long line was silently lost: %+v\n%s", out, text)
	}
}
