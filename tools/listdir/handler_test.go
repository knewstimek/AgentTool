package listdir

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func boolPointer(v bool) *bool { return &v }

func createFile(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestHandlePagination(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 5; i++ {
		createFile(t, filepath.Join(dir, fmt.Sprintf("file-%d.txt", i)))
	}

	cursor := ""
	seen := make(map[string]bool)
	pages := 0
	for {
		_, out, err := Handle(context.Background(), nil, ListDirInput{
			Path: dir, MaxEntries: 2, RelativePaths: true, Cursor: cursor,
		})
		if err != nil {
			t.Fatal(err)
		}
		pages++
		for _, line := range strings.Split(out.Tree, "\n") {
			if strings.HasPrefix(line, "file-") {
				if seen[line] {
					t.Fatalf("duplicate entry across pages: %s", line)
				}
				seen[line] = true
			}
		}
		if !out.HasMore {
			break
		}
		if out.NextCursor == "" {
			t.Fatal("has_more without next_cursor")
		}
		cursor = out.NextCursor
	}
	if len(seen) != 5 || pages != 3 {
		t.Fatalf("got %d unique entries over %d pages", len(seen), pages)
	}
}

func TestHandleExactLimitDoesNotClaimAnotherPage(t *testing.T) {
	dir := t.TempDir()
	createFile(t, filepath.Join(dir, "A.txt"))
	createFile(t, filepath.Join(dir, "B.txt"))
	result, out, err := Handle(context.Background(), nil, ListDirInput{Path: dir, MaxEntries: 2})
	if err != nil {
		t.Fatal(err)
	}
	if out.HasMore || out.Truncated || out.NextCursor != "" {
		t.Fatalf("exact-limit page incorrectly marked incomplete: %+v", out)
	}
	structured, ok := result.StructuredContent.(ListDirOutput)
	if !ok || structured.ReturnedFiles != 2 {
		t.Fatalf("missing structured MCP output: %#v", result.StructuredContent)
	}
}

func TestHandlePaginationAcrossNestedTraversal(t *testing.T) {
	dir := t.TempDir()
	createFile(t, filepath.Join(dir, "a", "z.txt"))
	createFile(t, filepath.Join(dir, "a.txt"))
	createFile(t, filepath.Join(dir, "b.txt"))

	var got []string
	cursor := ""
	for {
		_, out, err := Handle(context.Background(), nil, ListDirInput{
			Path: dir, MaxDepth: 2, MaxEntries: 1, RelativePaths: true,
			FilesOnly: true, Cursor: cursor,
		})
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, strings.Split(out.Tree, "\n")[0])
		if !out.HasMore {
			break
		}
		cursor = out.NextCursor
	}
	want := []string{"a/z.txt", "a.txt", "b.txt"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("nested page order = %v, want %v", got, want)
	}
}

func TestHandleNameAndTypeFilters(t *testing.T) {
	dir := t.TempDir()
	createFile(t, filepath.Join(dir, "Alpha.txt"))
	createFile(t, filepath.Join(dir, "Beta.txt"))
	createFile(t, filepath.Join(dir, "Apple", "AChild.go"))
	createFile(t, filepath.Join(dir, "Apple", "BChild.go"))

	_, out, err := Handle(context.Background(), nil, ListDirInput{
		Path: dir, RelativePaths: true, FilesOnly: true, NamePattern: "A*",
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.ReturnedFiles != 2 || out.ReturnedDirs != 0 ||
		!strings.Contains(out.Tree, "Alpha.txt") || !strings.Contains(out.Tree, "Apple/AChild.go") ||
		strings.Contains(out.Tree, "Beta.txt") || strings.Contains(out.Tree, "BChild.go") {
		t.Fatalf("unexpected filtered output:\n%s", out.Tree)
	}

	_, out, err = Handle(context.Background(), nil, ListDirInput{
		Path: dir, DirectoriesOnly: true, Include: []string{"App*"}, CountsOnly: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.TotalDirs != 1 || out.TotalFiles != 0 || out.Tree != "(1 directories, 0 files)" {
		t.Fatalf("unexpected counts output: %+v", out)
	}
}

func TestHandleDefaultLimit(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < defaultMaxEntries+1; i++ {
		createFile(t, filepath.Join(dir, fmt.Sprintf("f-%03d", i)))
	}
	_, out, err := Handle(context.Background(), nil, ListDirInput{Path: dir, Flat: boolPointer(true)})
	if err != nil {
		t.Fatal(err)
	}
	if out.ReturnedFiles != defaultMaxEntries || !out.Truncated || out.NextCursor == "" {
		t.Fatalf("default limit not enforced: %+v", out)
	}
}

func TestHandleRejectsCursorForDifferentQuery(t *testing.T) {
	dir := t.TempDir()
	createFile(t, filepath.Join(dir, "A.txt"))
	createFile(t, filepath.Join(dir, "B.txt"))
	_, first, err := Handle(context.Background(), nil, ListDirInput{Path: dir, MaxEntries: 1})
	if err != nil {
		t.Fatal(err)
	}
	result, _, err := Handle(context.Background(), nil, ListDirInput{
		Path: dir, MaxEntries: 1, Cursor: first.NextCursor, FilesOnly: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsError {
		t.Fatal("cursor from a different filter query should be rejected")
	}
}

func TestHandleRejectsStaleCursor(t *testing.T) {
	dir := t.TempDir()
	firstPath := filepath.Join(dir, "A.txt")
	createFile(t, firstPath)
	createFile(t, filepath.Join(dir, "B.txt"))
	_, first, err := Handle(context.Background(), nil, ListDirInput{Path: dir, MaxEntries: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(firstPath); err != nil {
		t.Fatal(err)
	}
	result, _, err := Handle(context.Background(), nil, ListDirInput{
		Path: dir, MaxEntries: 1, Cursor: first.NextCursor,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsError {
		t.Fatal("cursor whose last entry was removed should be rejected as stale")
	}
}
