package read

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestReadDefaultsAreBoundedAndContinue(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "many.txt")
	var content strings.Builder
	for i := 1; i <= 450; i++ {
		fmt.Fprintf(&content, "line-%03d\n", i)
	}
	if err := os.WriteFile(path, []byte(content.String()), 0o600); err != nil {
		t.Fatal(err)
	}

	result, out, err := Handle(context.Background(), nil, ReadInput{FilePath: path})
	if err != nil || result.IsError {
		t.Fatalf("read failed: err=%v result=%v", err, result)
	}
	text := result.Content[0].(*mcp.TextContent).Text
	if out.ReturnedLines != defaultLineLimit || out.NextOffset != 401 || !out.Truncated {
		t.Fatalf("unexpected metadata: %+v", out)
	}
	if !strings.Contains(text, "next_offset=401") || strings.Contains(text, "line-401") {
		t.Fatalf("unexpected bounded output footer/content: %s", text[len(text)-200:])
	}
}

func TestReadLongLineIsReportedNotSilentlyDropped(t *testing.T) {
	path := filepath.Join(t.TempDir(), "long.txt")
	if err := os.WriteFile(path, []byte(strings.Repeat("가", 70000)+"\nsecond\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	result, out, err := Handle(context.Background(), nil, ReadInput{FilePath: path})
	if err != nil || result.IsError {
		t.Fatalf("read failed: err=%v result=%v", err, result)
	}
	text := result.Content[0].(*mcp.TextContent).Text
	if !out.Truncated || !strings.Contains(text, "line_truncated=true") || !strings.Contains(text, "second") {
		t.Fatalf("long-line truncation was not visible: %+v\n%s", out, text[len(text)-250:])
	}
}

func TestReadDoesNotInventLineAfterFinalNewline(t *testing.T) {
	path := filepath.Join(t.TempDir(), "one.txt")
	if err := os.WriteFile(path, []byte("one\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	result, out, err := Handle(context.Background(), nil, ReadInput{FilePath: path})
	if err != nil || result.IsError {
		t.Fatalf("read failed: err=%v result=%v", err, result)
	}
	text := result.Content[0].(*mcp.TextContent).Text
	if out.TotalLines != 1 || out.NextOffset != 0 || !strings.Contains(text, "lines=1-1/1") {
		t.Fatalf("final newline created a phantom line: %+v\n%s", out, text)
	}
}

func TestReadEmptyFileReportsZeroLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.txt")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	result, out, err := Handle(context.Background(), nil, ReadInput{FilePath: path})
	if err != nil || result.IsError {
		t.Fatalf("read failed: err=%v result=%v", err, result)
	}
	text := result.Content[0].(*mcp.TextContent).Text
	if out.TotalLines != 0 || out.ReturnedLines != 0 || !strings.Contains(text, "lines=0-0/0") {
		t.Fatalf("unexpected empty-file metadata: %+v\n%s", out, text)
	}
}
