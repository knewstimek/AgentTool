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

// A long line must resolve to its own terminator no matter how far away it is.
// A bounded lookaround gets this wrong: the file is CRLF-dominant, so the edit
// would take CRLF while sitting on an LF-terminated line.
func TestLineEndingAroundResolvesLongLinesExactly(t *testing.T) {
	const far = 40000
	content := "# h1\r\n# h2\r\n# h3\r\n" +
		strings.Repeat(" ", far) + "MARK" + strings.Repeat(" ", far) + "\n"
	markAt := strings.Index(content, "MARK")
	if got := LineEndingAround(content, markAt, markAt+4, "\r\n"); got != "\n" {
		t.Fatalf("long LF-terminated line resolved as %q, want LF", got)
	}
	// Same shape, CRLF-terminated long line inside an LF-dominant file.
	content2 := "a\nb\nc\n" + strings.Repeat(" ", far) + "MARK" + strings.Repeat(" ", far) + "\r\n"
	markAt2 := strings.Index(content2, "MARK")
	if got := LineEndingAround(content2, markAt2, markAt2+4, "\n"); got != "\r\n" {
		t.Fatalf("long CRLF-terminated line resolved as %q, want CRLF", got)
	}
}

// Queries arrive in increasing order during a splice; the cursor must answer
// each one exactly while only ever moving forward.
func TestLineEndingCursorSequentialQueries(t *testing.T) {
	content := "AAA\r\nBBB\nCCC\nDDD\rEEE"
	c := NewLineEndingCursor(content)
	for _, tc := range []struct {
		needle string
		want   string
	}{
		{"AAA", "\r\n"},
		{"BBB", "\n"},
		{"CCC", "\n"},
		{"DDD", "\r"},
		{"EEE", "\r"}, // unterminated last line inherits the newline that opened it
	} {
		at := strings.Index(content, tc.needle)
		if got := c.At(at, at+len(tc.needle)); got != tc.want {
			t.Fatalf("At(%q) = %q, want %q", tc.needle, got, tc.want)
		}
	}
	// A backwards query restarts the walk instead of reusing a stale hit.
	if got := c.At(0, 3); got != "\r\n" {
		t.Fatalf("backwards query = %q, want CRLF", got)
	}
}

// Ties are resolved by first appearance among the tied forms -- not by the
// first newline in the span, which may belong to a losing form.
func TestLineEndingAroundTieAmongMajorityForms(t *testing.T) {
	content := "a\nb\rc\r\nd\re\r\n" // LF=1, CR=2, CRLF=2; first CR precedes first CRLF
	if got := LineEndingAround(content, 0, len(content), "\n"); got != "\r" {
		t.Fatalf("tied majority resolved as %q, want CR", got)
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
