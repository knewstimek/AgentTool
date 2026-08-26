package edit

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestDryRunLargeSparseReplacementsAreNotExpanded(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "large.txt")
	lines := make([]string, 6000)
	for i := range lines {
		lines[i] = fmt.Sprintf("line-%05d", i)
	}
	for _, at := range []int{100, 3000, 5000} {
		lines[at] += " TARGET"
	}
	before := strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(path, []byte(before), 0o644); err != nil {
		t.Fatal(err)
	}

	result, _, err := Handle(context.Background(), nil, EditInput{
		FilePath: path, OldString: "TARGET", NewString: "CHANGED",
		ReplaceAll: true, DryRun: true,
	})
	if err != nil || result.IsError {
		t.Fatalf("dry run failed: err=%v result=%+v", err, result)
	}
	text := result.Content[0].(*mcp.TextContent).Text
	if hunks := strings.Count(text, "\n@@ "); hunks != 3 {
		t.Fatalf("hunk count = %d, want 3\n%s", hunks, text)
	}
	added, removed := previewChangedLineCounts(text)
	if added != 3 || removed != 3 {
		t.Fatalf("changed lines = +%d -%d, want +3 -3", added, removed)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != before {
		t.Fatal("dry run modified the file")
	}
}

func previewChangedLineCounts(diff string) (added, removed int) {
	for _, line := range strings.Split(diff, "\n") {
		if strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++") {
			added++
		}
		if strings.HasPrefix(line, "-") && !strings.HasPrefix(line, "---") {
			removed++
		}
	}
	return added, removed
}
