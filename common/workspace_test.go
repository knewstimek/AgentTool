package common

import (
	"path/filepath"
	"runtime"
	"testing"
)

func TestFileURIPath(t *testing.T) {
	got, err := FileURIPath("file:///tmp/a%20b")
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "windows" {
		if got != filepath.Clean(`\tmp\a b`) {
			t.Fatalf("FileURIPath() = %q", got)
		}
	} else if got != "/tmp/a b" {
		t.Fatalf("FileURIPath() = %q", got)
	}
}

func TestResolveRequestPathUsesConfiguredWorkspace(t *testing.T) {
	old := GetWorkspace()
	t.Cleanup(func() { SetWorkspace(old) })
	root := t.TempDir()
	SetWorkspace(root)
	got, err := ResolveRequestPath(t.Context(), nil, filepath.Join("src", "x.go"))
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(root, "src", "x.go"); got != want {
		t.Fatalf("ResolveRequestPath() = %q, want %q", got, want)
	}
}
