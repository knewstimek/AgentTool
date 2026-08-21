package grep

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// A CRLF line ends with a terminator, not with content: an end-anchored pattern
// must still match, and every output mode must agree about it.
func TestHandleMatchesEndAnchorOnCRLFLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "crlf.txt")
	if err := os.WriteFile(path, []byte("foo\r\nbar\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	for _, mode := range []string{"content", "count", "files_with_matches"} {
		result, out, err := Handle(context.Background(), nil, GrepInput{
			Pattern: "^foo$", Path: path, OutputMode: mode,
		})
		if err != nil || result.IsError {
			t.Fatalf("%s: grep failed: err=%v result=%+v", mode, err, result)
		}
		if out.Count == 0 {
			t.Fatalf("%s: end-anchored pattern found nothing in a CRLF file", mode)
		}
	}
}

// grep is one of the most-used tools here, so every file shape is checked
// against every output mode, and the modes are checked against each other: the
// bug this guards was content/count disagreeing with files_with_matches.
func TestHandleLineEndingMatrix(t *testing.T) {
	dir := t.TempDir()
	shapes := []struct {
		name  string
		bytes string
		lines int // lines containing "hit"
	}{
		{"LF", "hit one\nmiss\nhit two\n", 2},
		{"CRLF", "hit one\r\nmiss\r\nhit two\r\n", 2},
		{"mixed", "hit one\r\nmiss\nhit two\r\n", 2},
		{"CR only", "hit one\rmiss\rhit two\r", 1}, // a lone CR is not a line break here
		{"no trailing newline", "hit one\r\nmiss\r\nhit two", 2},
	}
	patterns := []struct {
		name    string
		pattern string
		perFile map[string]int // expected matching lines, by shape name
	}{
		{"plain", "hit", nil}, // nil = use the shape's line count
		{"start anchored", "^hit", nil},
		{"end anchored", "hit one$", map[string]int{
			"LF": 1, "CRLF": 1, "mixed": 1, "CR only": 0, "no trailing newline": 1,
		}},
	}

	for _, s := range shapes {
		path := filepath.Join(dir, strings.ReplaceAll(s.name, " ", "_")+".txt")
		if err := os.WriteFile(path, []byte(s.bytes), 0o644); err != nil {
			t.Fatal(err)
		}
		for _, p := range patterns {
			want := s.lines
			if p.perFile != nil {
				want = p.perFile[s.name]
			}
			t.Run(s.name+"/"+p.name, func(t *testing.T) {
				// content mode: one entry per matching line
				result, _, err := Handle(context.Background(), nil, GrepInput{Pattern: p.pattern, Path: path})
				if err != nil || result.IsError {
					t.Fatalf("content mode failed: err=%v result=%+v", err, result)
				}
				text := result.Content[0].(*mcp.TextContent).Text
				got := 0
				if want > 0 {
					got = strings.Count(text, ":")
				}
				if want == 0 && !strings.Contains(text, "No matches found") {
					t.Fatalf("expected no matches, got %q", text)
				}
				if want > 0 && got != want {
					t.Fatalf("content mode found %d lines, want %d: %q", got, want, text)
				}
				// Only a TRAILING CR is a terminator. A CR-only file is one
				// line here -- the same as read, sloc and GNU grep -- so its
				// interior CRs are content and must survive; stripping them
				// would also desync grep's line numbers from read's.
				for _, out := range strings.Split(text, "\n") {
					if strings.HasSuffix(out, "\r") {
						t.Fatalf("displayed line keeps its terminator CR: %q", out)
					}
				}

				// count mode must agree with content mode
				result, _, err = Handle(context.Background(), nil, GrepInput{
					Pattern: p.pattern, Path: path, OutputMode: "count",
				})
				if err != nil || result.IsError {
					t.Fatalf("count mode failed: err=%v result=%+v", err, result)
				}
				countText := result.Content[0].(*mcp.TextContent).Text
				if want > 0 && !strings.HasSuffix(strings.TrimSpace(countText), fmt.Sprintf(":%d", want)) {
					t.Fatalf("count mode says %q, want %d", strings.TrimSpace(countText), want)
				}

				// files_with_matches must agree about whether the file matches
				_, out, err := Handle(context.Background(), nil, GrepInput{
					Pattern: p.pattern, Path: path, OutputMode: "files_with_matches",
				})
				if err != nil {
					t.Fatal(err)
				}
				if (out.Count > 0) != (want > 0) {
					t.Fatalf("files_with_matches says matched=%v, content mode found %d", out.Count > 0, want)
				}
			})
		}
	}
}

// The CR is stripped from displayed lines too -- left in, it makes the terminal
// overwrite whatever the agent prints next.
func TestHandleStripsCarriageReturnFromOutput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "crlf.txt")
	if err := os.WriteFile(path, []byte("hit one\r\nhit two\r\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	result, _, err := Handle(context.Background(), nil, GrepInput{Pattern: "hit", Path: path})
	if err != nil || result.IsError {
		t.Fatalf("grep failed: err=%v result=%+v", err, result)
	}
	text := result.Content[0].(*mcp.TextContent).Text
	if strings.Contains(text, "\r") {
		t.Fatalf("displayed lines still carry a CR: %q", text)
	}
	if !strings.Contains(text, "hit one") || !strings.Contains(text, "hit two") {
		t.Fatalf("matches missing: %q", text)
	}
}
