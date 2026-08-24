package grep

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestGrepCursorContinuesWithoutRepeating(t *testing.T) {
	path := filepath.Join(t.TempDir(), "matches.txt")
	if err := os.WriteFile(path, []byte("match-1\nmatch-2\nmatch-3\nmatch-4\nmatch-5\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	first, firstOut, err := Handle(context.Background(), nil, GrepInput{Pattern: "match", Path: path, MaxResults: 2})
	if err != nil || first.IsError || firstOut.NextCursor == "" {
		t.Fatalf("first page failed: err=%v out=%+v", err, firstOut)
	}
	second, secondOut, err := Handle(context.Background(), nil, GrepInput{
		Pattern: "match", Path: path, MaxResults: 2, Cursor: firstOut.NextCursor,
	})
	if err != nil || second.IsError {
		t.Fatalf("second page failed: err=%v out=%+v", err, secondOut)
	}
	text := second.Content[0].(*mcp.TextContent).Text
	if strings.Contains(text, "match-1") || !strings.Contains(text, "match-3") || !strings.Contains(text, "match-4") {
		t.Fatalf("cursor repeated or skipped results: %q", text)
	}
}

func TestDirectorySearchUsesRelativePathsAndIgnoreDefaults(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "node_modules"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "keep.txt"), []byte("needle\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "node_modules", "dep.txt"), []byte("needle\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".gitignore"), []byte("ignored.txt\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "ignored.txt"), []byte("needle\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	result, _, err := Handle(context.Background(), nil, GrepInput{Pattern: "needle", Path: root})
	if err != nil || result.IsError {
		t.Fatalf("grep failed: %v", err)
	}
	text := result.Content[0].(*mcp.TextContent).Text
	if !strings.Contains(text, "keep.txt\n  1:needle") || strings.Contains(text, root) || strings.Contains(text, "dep.txt") || strings.Contains(text, "ignored.txt\n") {
		t.Fatalf("unexpected relative/ignored output: %q", text)
	}

	result, _, err = Handle(context.Background(), nil, GrepInput{Pattern: "needle", Path: root, IncludeIgnored: true})
	if err != nil || result.IsError {
		t.Fatalf("include_ignored grep failed: %v", err)
	}
	text = result.Content[0].(*mcp.TextContent).Text
	if !strings.Contains(text, "dep.txt") || !strings.Contains(text, "ignored.txt") {
		t.Fatalf("include_ignored did not restore skipped paths: %q", text)
	}
}

func TestCompactOutputGroupsRepeatedFilePaths(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "many.txt")
	if err := os.WriteFile(path, []byte("needle one\nneedle two\nneedle three\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	result, _, err := Handle(context.Background(), nil, GrepInput{Pattern: "needle", Path: root})
	if err != nil || result.IsError {
		t.Fatalf("grep failed: %v", err)
	}
	text := result.Content[0].(*mcp.TextContent).Text
	if strings.Count(text, "many.txt") != 1 || !strings.Contains(text, "  3:needle three") {
		t.Fatalf("path was not grouped: %q", text)
	}

	classic, _, err := Handle(context.Background(), nil, GrepInput{Pattern: "needle", Path: root, OutputFormat: "classic"})
	if err != nil || classic.IsError {
		t.Fatalf("classic grep failed: %v", err)
	}
	if got := classic.Content[0].(*mcp.TextContent).Text; strings.Count(got, "many.txt") != 3 {
		t.Fatalf("classic layout not preserved: %q", got)
	}
}

func TestExplicitHiddenRootIsSearchable(t *testing.T) {
	root := filepath.Join(t.TempDir(), ".github")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "workflow.yml"), []byte("needle\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	result, _, err := Handle(context.Background(), nil, GrepInput{Pattern: "needle", Path: root})
	if err != nil || result.IsError {
		t.Fatalf("grep failed: %v", err)
	}
	if text := result.Content[0].(*mcp.TextContent).Text; !strings.Contains(text, "workflow.yml") {
		t.Fatalf("explicit hidden root was skipped: %q", text)
	}
}
