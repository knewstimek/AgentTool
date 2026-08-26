package textdiff

import (
	"fmt"
	"strings"
	"testing"
)

func TestUnifiedKeepsLargeSparseInsertionsSeparate(t *testing.T) {
	before := make([]string, 7453)
	for i := range before {
		before[i] = fmt.Sprintf("line-%05d", i)
	}

	after := append([]string(nil), before...)
	for _, at := range []int{5362, 3394, 857} {
		block := make([]string, 7)
		for i := range block {
			block[i] = fmt.Sprintf("insert-%05d-%d", at, i)
		}
		after = append(after[:at], append(block, after[at:]...)...)
	}

	got := Unified("before", "after", before, after, 1)
	if hunks := strings.Count(got, "\n@@ "); hunks != 3 {
		t.Fatalf("hunk count = %d, want 3\n%s", hunks, got)
	}
	added, removed := countChangedLines(got)
	if added != 21 || removed != 0 {
		t.Fatalf("changed lines = +%d -%d, want +21 -0", added, removed)
	}
	if len(got) > 4000 {
		t.Fatalf("sparse diff unexpectedly expanded to %d bytes", len(got))
	}
}

func TestUnifiedStringsKeepsSparseReplacementsSeparate(t *testing.T) {
	before := make([]string, 6000)
	for i := range before {
		before[i] = fmt.Sprintf("line-%05d", i)
	}
	after := append([]string(nil), before...)
	for _, at := range []int{100, 3000, 5000} {
		after[at] += "-changed"
	}

	got := UnifiedStrings("before", "after", strings.Join(before, "\n")+"\n", strings.Join(after, "\n")+"\n", 3)
	if hunks := strings.Count(got, "\n@@ "); hunks != 3 {
		t.Fatalf("hunk count = %d, want 3\n%s", hunks, got)
	}
	added, removed := countChangedLines(got)
	if added != 3 || removed != 3 {
		t.Fatalf("changed lines = +%d -%d, want +3 -3", added, removed)
	}
}

func TestUnifiedFormatsEmptyRangesAtFileBoundaries(t *testing.T) {
	insert := Unified("before", "after", nil, []string{"new"}, 3)
	if !strings.Contains(insert, "@@ -0,0 +1,1 @@") {
		t.Fatalf("insertion range is not standard unified-diff form: %q", insert)
	}

	remove := Unified("before", "after", []string{"old"}, nil, 3)
	if !strings.Contains(remove, "@@ -1,1 +0,0 @@") {
		t.Fatalf("deletion range is not standard unified-diff form: %q", remove)
	}
}

func countChangedLines(diff string) (added, removed int) {
	for _, line := range strings.Split(diff, "\n") {
		if strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++") {
			added++
		}
		if strings.HasPrefix(line, "-") && !strings.HasPrefix(line, "---") {
			removed++
		}
	}
	return added, removed
}
