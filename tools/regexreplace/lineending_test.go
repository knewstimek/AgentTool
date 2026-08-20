package regexreplace

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestHandleNormalizesReplacementToCRLF(t *testing.T) {
	path := filepath.Join(t.TempDir(), "crlf.txt")
	if err := os.WriteFile(path, []byte("a\r\nb\r\nc\r\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	result, _, err := Handle(context.Background(), nil, RegexReplaceInput{
		Path: path, Pattern: "b", Replacement: "x\ny",
	})
	if err != nil || result.IsError {
		t.Fatalf("Handle() failed: result=%+v err=%v", result, err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := "a\r\nx\r\ny\r\nc\r\n"
	if string(got) != want {
		t.Fatalf("file bytes = %q, want %q", got, want)
	}
}
