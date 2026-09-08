package common

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRootIgnoreRulesCombineGitignoreAndIgnore(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".gitignore"), []byte("git-only.txt\nshared.txt\nignored-dir/\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".ignore"), []byte("ignore-only.txt\n!shared.txt\n/root-only.txt\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	rules := LoadRootIgnoreRules(root)
	for _, tc := range []struct {
		path    string
		isDir   bool
		ignored bool
	}{
		{"git-only.txt", false, true},
		{"ignore-only.txt", false, true},
		{"nested/ignore-only.txt", false, true},
		{"shared.txt", false, false},
		{"root-only.txt", false, true},
		{"nested/root-only.txt", false, false},
		{"ignored-dir", true, true},
		{"ignored-dir/child.txt", false, false},
	} {
		if got := rules.Match(tc.path, tc.isDir); got != tc.ignored {
			t.Errorf("Match(%q, %t) = %t, want %t", tc.path, tc.isDir, got, tc.ignored)
		}
	}
	if !rules.MatchPath("ignored-dir/child.txt", false) {
		t.Fatal("MatchPath did not inherit an ignored parent directory")
	}
}
