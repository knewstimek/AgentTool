//go:build windows

package common

import (
	"strings"
	"testing"
)

// Console output encoding is per-process, not per-shell: git-bash emits UTF-8
// for its builtins while a native exe it launches writes ANSI code page bytes.
func TestDecodeConsoleOutput(t *testing.T) {
	utf8Hangul := "활성 코드 페이지\n"
	// "활성 코드 페이지: 949" as emitted by chcp.com under CP949.
	cp949Line := []byte{
		0xC8, 0xB0, 0xBC, 0xBA, 0x20, 0xC4, 0xDA, 0xB5, 0xE5, 0x20,
		0xC6, 0xE4, 0xC0, 0xCC, 0xC1, 0xF6, 0x3A, 0x20, 0x39, 0x34, 0x39, 0x0A,
	}

	t.Run("ascii untouched", func(t *testing.T) {
		in := "plain ascii output\nsecond line\n"
		if got := DecodeConsoleOutput([]byte(in)); got != in {
			t.Errorf("got %q, want %q", got, in)
		}
	})

	t.Run("utf8 preserved", func(t *testing.T) {
		if got := DecodeConsoleOutput([]byte(utf8Hangul)); got != utf8Hangul {
			t.Errorf("got %q, want %q", got, utf8Hangul)
		}
	})

	if getSystemCodePage() != 949 {
		t.Skip("remaining cases need CP949 as the system code page")
	}

	t.Run("acp decoded", func(t *testing.T) {
		got := DecodeConsoleOutput(cp949Line)
		if !strings.Contains(got, "활성 코드 페이지") {
			t.Errorf("got %q, want decoded Hangul", got)
		}
	})

	// The case a whole-buffer verdict cannot serve: one command, both encodings.
	t.Run("mixed lines", func(t *testing.T) {
		mixed := append([]byte(utf8Hangul), cp949Line...)
		got := DecodeConsoleOutput(mixed)
		if strings.Count(got, "활성 코드 페이지") != 2 {
			t.Errorf("got %q, want both lines decoded", got)
		}
	})
}
