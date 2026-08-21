package diff

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Lines are compared with their endings normalized, so two files differing only
// in line endings produce no hunk. Saying nothing there reads as "identical".
func TestHandleReportsLineEndingOnlyDifference(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.txt")
	b := filepath.Join(dir, "b.txt")
	if err := os.WriteFile(a, []byte("a\r\nb\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(b, []byte("a\nb\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	result, _, err := Handle(context.Background(), nil, DiffInput{FileA: a, FileB: b})
	if err != nil || result.IsError {
		t.Fatalf("diff failed: err=%v result=%+v", err, result)
	}
	text := result.Content[0].(*mcp.TextContent).Text
	if !strings.Contains(text, "line endings differ") {
		t.Fatalf("line-ending-only difference not reported: %q", text)
	}
	if !strings.Contains(text, "Mixed") || !strings.Contains(text, "LF") {
		t.Fatalf("report lacks the per-file summary: %q", text)
	}
}

func TestHandleStillReportsIdenticalFiles(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.txt")
	b := filepath.Join(dir, "b.txt")
	for _, p := range []string{a, b} {
		if err := os.WriteFile(p, []byte("a\r\nb\r\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	result, _, err := Handle(context.Background(), nil, DiffInput{FileA: a, FileB: b})
	if err != nil || result.IsError {
		t.Fatalf("diff failed: err=%v result=%+v", err, result)
	}
	if text := result.Content[0].(*mcp.TextContent).Text; text != "Files are identical" {
		t.Fatalf("identical files reported as %q", text)
	}
}
