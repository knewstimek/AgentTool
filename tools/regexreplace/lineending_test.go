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

// A file mixing both forms must keep each region's own newline: converting the
// whole replacement to one dominant form rewrites the minority region.
func TestHandleUsesPerMatchLineEndings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mixed.txt")
	original := "crlf1\r\nHIT\r\ncrlf2\r\nlf1\nHIT\nlf2\n"
	if err := os.WriteFile(path, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}
	result, out, err := Handle(context.Background(), nil, RegexReplaceInput{
		Path: path, Pattern: "HIT", Replacement: "x\ny",
	})
	if err != nil || result.IsError {
		t.Fatalf("Handle() failed: result=%+v err=%v", result, err)
	}
	if out.TotalReplacements != 2 {
		t.Fatalf("replacements = %d, want 2", out.TotalReplacements)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := "crlf1\r\nx\r\ny\r\ncrlf2\r\nlf1\nx\ny\nlf2\n"
	if string(got) != want {
		t.Fatalf("file bytes = %q, want %q", got, want)
	}
}

// A file with no newline of its own still needs the replacement's newlines
// converted -- to the default, not left as whatever the agent sent.
func TestHandleNormalizesReplacementInNewlineFreeFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oneline.txt")
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	result, _, err := Handle(context.Background(), nil, RegexReplaceInput{
		Path: path, Pattern: "x", Replacement: "a\r\nb",
	})
	if err != nil || result.IsError {
		t.Fatalf("Handle() failed: result=%+v err=%v", result, err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "a\nb" {
		t.Fatalf("file bytes = %q, want %q", got, "a\nb")
	}
}

func TestHandleCapturesSurviveLineEndingConversion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "captures.txt")
	if err := os.WriteFile(path, []byte("key=value\r\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	result, _, err := Handle(context.Background(), nil, RegexReplaceInput{
		Path: path, Pattern: `(\w+)=(\w+)`, Replacement: "$2\n$1",
	})
	if err != nil || result.IsError {
		t.Fatalf("Handle() failed: result=%+v err=%v", result, err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "value\r\nkey\r\n" {
		t.Fatalf("file bytes = %q", got)
	}
}
