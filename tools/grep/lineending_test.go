package grep

import (
	"context"
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
