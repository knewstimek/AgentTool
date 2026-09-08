package glob

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestGlobReportsTotalAndContinuesPastOld500Limit(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < 510; i++ {
		path := filepath.Join(root, fmt.Sprintf("file-%03d.txt", i))
		if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	result, out, err := Handle(context.Background(), nil, GlobInput{Pattern: "**/*.txt", Path: root, Limit: 500})
	if err != nil || result.IsError {
		t.Fatalf("glob failed: err=%v result=%v", err, result)
	}
	if out.Count != 510 || out.Returned != 500 || !out.HasMore || out.NextCursor == "" {
		t.Fatalf("unexpected first page metadata: %+v", out)
	}
	if text := result.Content[0].(*mcp.TextContent).Text; !strings.Contains(text, "total=510") || !strings.Contains(text, "has_more=true") {
		t.Fatalf("metadata is not visible: %q", text[len(text)-250:])
	}

	_, second, err := Handle(context.Background(), nil, GlobInput{
		Pattern: "**/*.txt", Path: root, Limit: 500, Cursor: out.NextCursor,
	})
	if err != nil || second.Returned != 10 || second.HasMore {
		t.Fatalf("unexpected second page: err=%v out=%+v", err, second)
	}
}

func TestGlobDefaultsToRelativePathsAndSkipsGeneratedDirs(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "node_modules"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "main.go"), []byte("package main"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "node_modules", "dep.go"), []byte("package dep"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, out, err := Handle(context.Background(), nil, GlobInput{Pattern: "**/*.go", Path: root})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Files) != 1 || out.Files[0] != "main.go" {
		t.Fatalf("unexpected default paths: %+v", out.Files)
	}
	_, explicit, err := Handle(context.Background(), nil, GlobInput{Pattern: "node_modules/**/*.go", Path: root})
	if err != nil || len(explicit.Files) != 1 || explicit.Files[0] != "node_modules/dep.go" {
		t.Fatalf("explicit generated root was not searched: err=%v files=%+v", err, explicit.Files)
	}
}

func TestGlobHonorsIgnoreAndGitignoreTogether(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "ignored-dir"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"keep.txt", "git-only.txt", "ignore-only.txt", "shared.txt"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "ignored-dir", "child.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".gitignore"), []byte("git-only.txt\nshared.txt\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".ignore"), []byte("ignore-only.txt\nignored-dir/\n!shared.txt\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		pattern       string
		includedCount int
	}{{"*.txt", 4}, {"**/*.txt", 5}} {
		pattern := tc.pattern
		_, out, err := Handle(context.Background(), nil, GlobInput{Pattern: pattern, Path: root})
		if err != nil {
			t.Fatalf("glob %q failed: %v", pattern, err)
		}
		if len(out.Files) != 2 || !containsPath(out.Files, "keep.txt") || !containsPath(out.Files, "shared.txt") {
			t.Fatalf("glob %q did not apply combined ignore rules: %+v", pattern, out.Files)
		}

		_, included, err := Handle(context.Background(), nil, GlobInput{
			Pattern: pattern, Path: root, IncludeIgnored: true,
		})
		if err != nil {
			t.Fatalf("include_ignored glob %q failed: %v", pattern, err)
		}
		if len(included.Files) != tc.includedCount {
			t.Fatalf("include_ignored glob %q returned %+v", pattern, included.Files)
		}
	}
}

func containsPath(paths []string, want string) bool {
	for _, path := range paths {
		if path == want {
			return true
		}
	}
	return false
}
