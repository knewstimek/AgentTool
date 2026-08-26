package diff

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestHandleLargeSparseInsertionsAreNotExpanded(t *testing.T) {
	dir := t.TempDir()
	pathA := filepath.Join(dir, "before.txt")
	pathB := filepath.Join(dir, "after.txt")

	before := make([]string, 7453)
	for i := range before {
		before[i] = fmt.Sprintf("line-%05d", i)
	}
	after := append([]string(nil), before...)
	for _, at := range []int{5362, 3394, 857} {
		block := make([]string, 7)
		for i := range block {
			block[i] = fmt.Sprintf("insert-%05d-%d", at, i)
		}
		after = append(after[:at], append(block, after[at:]...)...)
	}

	if err := os.WriteFile(pathA, []byte(strings.Join(before, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pathB, []byte(strings.Join(after, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	result, output, err := Handle(context.Background(), nil, DiffInput{
		FileA: pathA, FileB: pathB, ContextLines: 1, MaxOutputChars: 131072,
	})
	if err != nil || result.IsError {
		t.Fatalf("diff failed: err=%v result=%+v", err, result)
	}
	if output.Truncated {
		t.Fatal("sparse diff was truncated")
	}
	text := result.Content[0].(*mcp.TextContent).Text
	if hunks := strings.Count(text, "\n@@ "); hunks != 3 {
		t.Fatalf("hunk count = %d, want 3\n%s", hunks, text)
	}
	added, removed := changedLineCounts(text)
	if added != 21 || removed != 0 {
		t.Fatalf("changed lines = +%d -%d, want +21 -0", added, removed)
	}
}

func changedLineCounts(diff string) (added, removed int) {
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
