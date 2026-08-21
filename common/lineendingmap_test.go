package common

import (
	"strings"
	"testing"
)

func TestLineEndingMapOrigOffset(t *testing.T) {
	content := "a\r\nbb\nccc\r\n"
	m := NewLineEndingMap(content)
	if m.Norm != "a\nbb\nccc\n" {
		t.Fatalf("Norm = %q", m.Norm)
	}
	// Every normalized offset must point at the same character in the original.
	for norm := 0; norm < len(m.Norm); norm++ {
		orig := m.OrigOffset(norm)
		want := m.Norm[norm]
		got := content[orig]
		if want == '\n' {
			// A normalized '\n' maps to the start of the original ending,
			// which is '\r' when that line ended with CRLF.
			if got != '\n' && got != '\r' {
				t.Fatalf("norm %d -> orig %d = %q, want a newline start", norm, orig, got)
			}
			continue
		}
		if got != want {
			t.Fatalf("norm %d -> orig %d = %q, want %q", norm, orig, got, want)
		}
	}
	if got := m.OrigOffset(len(m.Norm)); got != len(content) {
		t.Fatalf("end offset = %d, want %d", got, len(content))
	}
}

func TestLineEndingMapNoCarriageReturnIsIdentity(t *testing.T) {
	m := NewLineEndingMap("a\nb\n")
	if m.Norm != m.Original {
		t.Fatalf("Norm should alias the original for LF-only content")
	}
	if got := m.OrigOffset(3); got != 3 {
		t.Fatalf("OrigOffset = %d, want 3", got)
	}
}

func TestLineEndingMapLocalLineEnding(t *testing.T) {
	content := "crlf1\r\ncrlf2\r\nlf1\nlf2\ncrlf3\r\n"
	m := NewLineEndingMap(content)
	tests := []struct {
		name       string
		start, end int
		want       string
	}{
		{"inside CRLF region", 0, len("crlf1\ncrlf2"), "\r\n"},
		{"inside LF region", len("crlf1\ncrlf2\n"), len("crlf1\ncrlf2\nlf1\nlf2"), "\n"},
		{"single line in LF region", len("crlf1\ncrlf2\n"), len("crlf1\ncrlf2\nlf1"), "\n"},
		{"single line in CRLF region", 0, len("crlf1"), "\r\n"},
	}
	for _, tt := range tests {
		if got := m.LocalLineEnding(tt.start, tt.end); got != tt.want {
			t.Fatalf("%s: LocalLineEnding = %q, want %q", tt.name, got, tt.want)
		}
	}
}

func TestLineEndingMapOffsetQueriesGoingBackwards(t *testing.T) {
	// The translation cursor only walks forward, so a lower query must restart
	// it rather than return a stale offset.
	content := "a\r\nbb\r\nccc\r\n"
	m := NewLineEndingMap(content)
	if got := m.OrigOffset(len(m.Norm)); got != len(content) {
		t.Fatalf("end offset = %d, want %d", got, len(content))
	}
	if got := m.OrigOffset(0); got != 0 {
		t.Fatalf("offset 0 after a forward walk = %d, want 0", got)
	}
	if got := m.OrigOffset(2); got != 3 {
		t.Fatalf("offset 2 = %d, want 3", got)
	}
}

func TestLineEndingAroundBoundedLookaround(t *testing.T) {
	// No newline within the scan limit: the answer falls back instead of
	// scanning the whole file, which is what keeps many-match runs linear.
	content := strings.Repeat("x", localScanLimit*3) + "\r\n"
	if got := LineEndingAround(content, 0, 1, "\n"); got != "\n" {
		t.Fatalf("far-away newline should not be found, got %q", got)
	}
	// Within the limit it is still found.
	near := strings.Repeat("x", 10) + "\r\n"
	if got := LineEndingAround(near, 0, 1, "\n"); got != "\r\n" {
		t.Fatalf("nearby CRLF not found, got %q", got)
	}
}

func TestLineEndingAroundFallbacks(t *testing.T) {
	if got := LineEndingAround("no newline here", 0, 5, "\r\n"); got != "\r\n" {
		t.Fatalf("newline-free content should use the fallback, got %q", got)
	}
	// Last line without a terminator inherits the newline that started it.
	content := "a\r\nb"
	if got := LineEndingAround(content, 3, 4, "\n"); got != "\r\n" {
		t.Fatalf("unterminated last line = %q, want CRLF", got)
	}
	// Majority decides inside the span; ties go to the first one seen.
	if got := LineEndingAround("a\nb\nc\r\n", 0, 7, "\r\n"); got != "\n" {
		t.Fatalf("majority LF span = %q, want LF", got)
	}
	// Ties go to the first ending seen, in either order.
	if got := LineEndingAround("a\r\nb\n", 0, 5, "\n"); got != "\r\n" {
		t.Fatalf("CRLF-first tie = %q, want CRLF", got)
	}
	if got := LineEndingAround("a\nb\r\n", 0, 5, "\r\n"); got != "\n" {
		t.Fatalf("LF-first tie = %q, want LF", got)
	}
}
