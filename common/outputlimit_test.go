package common

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestTruncateRunesKeepsUTF8Valid(t *testing.T) {
	got, truncated := TruncateRunes("가나다라마바사", 5, "…")
	if !truncated || got != "가나다라…" {
		t.Fatalf("got %q truncated=%v", got, truncated)
	}
	if !utf8.ValidString(got) {
		t.Fatal("truncation produced invalid UTF-8")
	}
}

func TestAppendWithinRuneBudgetIsAtomic(t *testing.T) {
	var sb strings.Builder
	used := 0
	if !AppendWithinRuneBudget(&sb, &used, "가나", 3) {
		t.Fatal("first fragment should fit")
	}
	if AppendWithinRuneBudget(&sb, &used, "다라", 3) {
		t.Fatal("second fragment should not fit")
	}
	if sb.String() != "가나" || used != 2 {
		t.Fatalf("partial fragment was appended: %q, used=%d", sb.String(), used)
	}
}
