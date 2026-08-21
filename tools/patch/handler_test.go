package patch

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func apply(t *testing.T, original, diff string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "target.txt")
	if err := os.WriteFile(path, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}
	result, _, err := Handle(context.Background(), nil, PatchInput{FilePath: path, Patch: diff})
	if err != nil || result.IsError {
		t.Fatalf("patch failed: result=%+v err=%v", result, err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(got)
}

// A file mixing CRLF and LF must keep each line's own ending: normalizing the
// whole file and rebuilding it rewrites every line outside the hunk.
func TestPatchPreservesMixedLineEndings(t *testing.T) {
	got := apply(t, "a\r\nb\nc\r\n", "@@ -1,3 +1,3 @@\n a\n-b\n+B\n c\n")
	if got != "a\r\nB\nc\r\n" {
		t.Fatalf("file bytes = %q, want %q", got, "a\r\nB\nc\r\n")
	}
}

func TestPatchKeepsCRLFOnCRLFOnlyFile(t *testing.T) {
	got := apply(t, "a\r\nb\r\nc\r\n", "@@ -1,3 +1,3 @@\n a\n-b\n+B\n c\n")
	if got != "a\r\nB\r\nc\r\n" {
		t.Fatalf("file bytes = %q, want %q", got, "a\r\nB\r\nc\r\n")
	}
}

// A file with no trailing newline keeps that property, and an appended line
// still gets a terminator on the line it follows.
func TestPatchRespectsMissingTrailingNewline(t *testing.T) {
	got := apply(t, "a\nb", "@@ -1,2 +1,2 @@\n a\n-b\n+B\n")
	if got != "a\nB" {
		t.Fatalf("file bytes = %q, want %q", got, "a\nB")
	}
	got = apply(t, "a\nb", "@@ -1,2 +1,3 @@\n a\n b\n+c\n")
	if got != "a\nb\nc" {
		t.Fatalf("appended line: file bytes = %q, want %q", got, "a\nb\nc")
	}
}
