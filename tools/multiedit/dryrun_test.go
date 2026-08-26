package multiedit

import (
	"fmt"
	"strings"
	"testing"
)

func TestDryRunPreviewKeepsSparseReplacementsSeparate(t *testing.T) {
	before := make([]string, 6000)
	for i := range before {
		before[i] = fmt.Sprintf("line-%05d", i)
	}
	after := append([]string(nil), before...)
	for _, at := range []int{100, 3000, 5000} {
		after[at] += "-changed"
	}

	got := dryRunPreview(strings.Join(before, "\n")+"\n", strings.Join(after, "\n")+"\n", "large.txt")
	if hunks := strings.Count(got, "\n@@ "); hunks != 3 {
		t.Fatalf("hunk count = %d, want 3\n%s", hunks, got)
	}
	added, removed := multieditChangedLineCounts(got)
	if added != 3 || removed != 3 {
		t.Fatalf("changed lines = +%d -%d, want +3 -3", added, removed)
	}
}

func multieditChangedLineCounts(diff string) (added, removed int) {
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
