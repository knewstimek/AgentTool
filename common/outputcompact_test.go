package common

import (
	"strings"
	"testing"
	"time"
)

func TestCompactDiagnosticOutputExactRun(t *testing.T) {
	input := "build started\nwarning: stale cache\nwarning: stale cache\nwarning: stale cache\ndone\n"
	got := CompactDiagnosticOutput(input)
	if !got.Compacted || got.OmittedLines != 2 || got.Groups != 1 {
		t.Fatalf("unexpected stats: %+v", got)
	}
	if want := "warning: stale cache [x3]"; !strings.Contains(got.Text, want) {
		t.Fatalf("missing %q in %q", want, got.Text)
	}
}

func TestCompactDiagnosticOutputLeavesRepeatedDataAlone(t *testing.T) {
	input := "same data\nsame data\n"
	got := CompactDiagnosticOutput(input)
	if got.Compacted || got.Text != input {
		t.Fatalf("data output changed: %+v", got)
	}
}

func TestCompactDiagnosticOutputGroupsGitLineEndings(t *testing.T) {
	input := "warning: in the working copy of 'a.md', LF will be replaced by CRLF the next time Git touches it\n" +
		"warning: in the working copy of 'b.md', LF will be replaced by CRLF the next time Git touches it\n" +
		"warning: in the working copy of 'c.md', LF will be replaced by CRLF the next time Git touches it\n" +
		"warning: in the working copy of 'd.md', LF will be replaced by CRLF the next time Git touches it\n"
	got := CompactDiagnosticOutput(input)
	if !got.Compacted || got.OmittedLines != 3 || got.Groups != 1 {
		t.Fatalf("unexpected stats: %+v", got)
	}
	for _, want := range []string{"4 working-copy files", "'a.md'", "'c.md'", "(+1 more)"} {
		if !strings.Contains(got.Text, want) {
			t.Fatalf("missing %q in %q", want, got.Text)
		}
	}
	if strings.Contains(got.Text, "'d.md'") {
		t.Fatalf("fourth example was not folded: %q", got.Text)
	}
}

func TestRawOutputStoreEvictsAndExpires(t *testing.T) {
	now := time.Unix(100, 0)
	store := newRawOutputStore(1, 64, time.Minute)
	first := store.put("bash", "first", false, 5, now)
	second := store.put("bash", "second", false, 6, now.Add(time.Second))
	if first == "" || second == "" {
		t.Fatal("store did not issue output IDs")
	}
	if _, ok := store.get(first, now.Add(2*time.Second)); ok {
		t.Fatal("oldest record was not evicted")
	}
	if got, ok := store.get(second, now.Add(2*time.Second)); !ok || got.Content != "second" {
		t.Fatalf("newest record missing: %+v, %v", got, ok)
	}
	if _, ok := store.get(second, now.Add(2*time.Minute)); ok {
		t.Fatal("expired record was returned")
	}
}
