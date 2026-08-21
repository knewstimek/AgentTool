package regexreplace

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
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

// In a file with no newline of its own there is no region to follow, so a
// replacement carrying the LF that JSON transport imposes is still converted to
// the default. A replacement carrying an explicit CR is not: nobody types \r by
// accident, and rewriting it would be the same overreach as the bug this whole
// change fixes.
func TestHandleReplacementInNewlineFreeFile(t *testing.T) {
	for _, tc := range []struct {
		name        string
		replacement string
		want        string
	}{
		{"incidental LF is normalized", "a\nb", "a\nb"},
		{"explicit CR is kept", "a\r\nb", "a\r\nb"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "oneline.txt")
			if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
				t.Fatal(err)
			}
			result, _, err := Handle(context.Background(), nil, RegexReplaceInput{
				Path: path, Pattern: "x", Replacement: tc.replacement,
			})
			if err != nil || result.IsError {
				t.Fatalf("Handle() failed: result=%+v err=%v", result, err)
			}
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tc.want {
				t.Fatalf("file bytes = %q, want %q", got, tc.want)
			}
		})
	}
}

// A miss caused by CRLF must be explained with evidence from the scan, and an
// LF-only tree must NOT get the hint -- it would send the agent after a
// line-ending theory that does not apply.
func TestHandleExplainsCRLFMissOnlyWhenCRLFWasSeen(t *testing.T) {
	dir := t.TempDir()
	crlf := filepath.Join(dir, "crlf.txt")
	lf := filepath.Join(dir, "lf.txt")
	if err := os.WriteFile(crlf, []byte("foo\r\nbar\r\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lf, []byte("foo\nbar\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name     string
		path     string
		pattern  string
		wantHint bool
	}{
		{"CRLF file, end anchor", crlf, `(?m)^foo$`, true},
		{"CRLF file, literal newline", crlf, `foo\nbar`, true},
		{"LF file, end anchor", lf, `(?m)^nothing$`, false},
		{"CRLF file, no newline construct", crlf, `zzz`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, out, err := Handle(context.Background(), nil, RegexReplaceInput{
				Path: tc.path, Pattern: tc.pattern, Replacement: "X", DryRun: true,
			})
			if err != nil || result.IsError {
				t.Fatalf("Handle() failed: result=%+v err=%v", result, err)
			}
			if out.TotalReplacements != 0 {
				t.Fatalf("expected no matches, got %d", out.TotalReplacements)
			}
			text := result.Content[0].(*mcp.TextContent).Text
			if got := strings.Contains(text, "CRLF line endings"); got != tc.wantHint {
				t.Fatalf("hint present=%v, want %v: %q", got, tc.wantHint, text)
			}
		})
	}
}

// Converting line endings must not be undone by the region normalization that
// exists for ordinary replacements -- otherwise the tool reports replacements
// while leaving the file byte-identical.
func TestHandleLineEndingConversionSurvives(t *testing.T) {
	for _, tc := range []struct {
		name        string
		pattern     string
		replacement string
		in          string
		want        string
	}{
		{"CRLF to LF", `\r\n`, "\n", "a\r\nb\r\n", "a\nb\n"},
		{"LF to CRLF", `\n`, "\r\n", "a\nb\n", "a\r\nb\r\n"},
		{"CR to LF", `\r`, "\n", "a\rb\r", "a\nb\n"},
		// The defensive forms this tool recommends for matching either style
		// are NOT conversions: the replacement still follows the region.
		{"optional CR keeps region", `x\r?\n`, "y\n", "A\r\nx\r\nB\n", "A\r\ny\r\nB\n"},
		{"alternation keeps region", `x(?:\r\n|\n)`, "y\n", "A\r\nx\r\nB\n", "A\r\ny\r\nB\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "f.txt")
			if err := os.WriteFile(path, []byte(tc.in), 0o644); err != nil {
				t.Fatal(err)
			}
			result, out, err := Handle(context.Background(), nil, RegexReplaceInput{
				Path: path, Pattern: tc.pattern, Replacement: tc.replacement,
			})
			if err != nil || result.IsError {
				t.Fatalf("Handle() failed: result=%+v err=%v", result, err)
			}
			if out.TotalReplacements == 0 {
				t.Fatal("pattern did not match")
			}
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tc.want {
				t.Fatalf("file bytes = %q, want %q", got, tc.want)
			}
		})
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
