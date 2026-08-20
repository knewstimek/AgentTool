package fileinfo

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHandleReportsMixedLineEndings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mixed.txt")
	if err := os.WriteFile(path, []byte("a\r\nb\r\nc\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	result, out, err := Handle(context.Background(), nil, FileInfoInput{FilePath: path})
	if err != nil || result.IsError {
		t.Fatalf("Handle() failed: result=%+v err=%v", result, err)
	}
	if !strings.Contains(out.Result, "Line ending: Mixed (CRLF=2, LF=1, CR=0)") {
		t.Fatalf("unexpected output:\n%s", out.Result)
	}
}
