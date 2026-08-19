package common

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// maxEchoRunes caps the non-ASCII echo so a large translated block cannot
// balloon the response. Enough to eyeball a few phrases, not a whole file.
const maxEchoRunes = 100

// ReplacementCharWarning reports U+FFFD in text an agent is about to write.
//
// U+FFFD is what a decoder leaves behind when it gives up on a byte sequence,
// and it is unrecoverable: the original character's identity is gone, so the
// only fix is to send the text again. It reaches this tool when a multi-byte
// character was split upstream -- a known Claude Code streaming failure on CJK
// (anthropics/claude-code#43858) -- and without a warning it lands in the file
// and surfaces weeks later. Genuine text practically never contains one.
//
// Returns an empty string when the text is clean.
func ReplacementCharWarning(text string) string {
	count := strings.Count(text, string(utf8.RuneError))
	if count == 0 {
		return ""
	}

	line := 1
	for _, r := range text {
		if r == utf8.RuneError {
			break
		}
		if r == '\n' {
			line++
		}
	}
	return fmt.Sprintf("⚠ %d replacement char(s) U+FFFD in the text written, first at line %d. "+
		"These were corrupted before reaching this tool and the original characters cannot be "+
		"recovered -- re-send that text.", count, line)
}

// NonASCIIEcho returns the non-ASCII runs in text, joined by ", ".
//
// It exists so an agent that composed a string as \uXXXX escapes sees the
// actual characters it produced. Hangul fills U+AC00..U+D7A3 solid, so one
// wrong hex digit still yields a perfectly valid character (설 vs 섥) and no
// validation can catch it -- but rendered back as text, the wrong glyph is
// obvious. Only the non-ASCII runs are echoed; surrounding
// code would add tokens without adding anything to check.
//
// Returns an empty string when text is pure ASCII.
func NonASCIIEcho(text string) string {
	var runs []string
	// Whole words, not bare non-ASCII characters. Scripts that write words
	// entirely outside ASCII (CJK, Cyrillic, Arabic) would read fine either
	// way, but Latin ones mix within a word -- echoing just the "e" of "cafe"
	// gives nothing to check. Adjacent non-ASCII words are joined so a phrase
	// stays a phrase; an ASCII word or a line break ends the run.
	for _, line := range strings.Split(text, "\n") {
		var cur []string
		flush := func() {
			if len(cur) > 0 {
				runs = append(runs, strings.Join(cur, " "))
				cur = nil
			}
		}
		for _, word := range strings.FieldsFunc(line, unicode.IsSpace) {
			if hasNonASCII(word) {
				cur = append(cur, word)
				continue
			}
			flush()
		}
		flush()
	}
	if len(runs) == 0 {
		return ""
	}

	joined := strings.Join(runs, ", ")
	if utf8.RuneCountInString(joined) > maxEchoRunes {
		truncated := []rune(joined)[:maxEchoRunes]
		return string(truncated) + "..."
	}
	return joined
}

func hasNonASCII(s string) bool {
	for _, r := range s {
		if r > unicode.MaxASCII {
			return true
		}
	}
	return false
}

// TextGuardNotice combines both checks into the suffix a write-side tool
// appends to its result. Empty when there is nothing worth saying.
func TextGuardNotice(text string) string {
	var sb strings.Builder
	if echo := NonASCIIEcho(text); echo != "" {
		sb.WriteString("\nnon-ASCII written: ")
		sb.WriteString(echo)
	}
	if warn := ReplacementCharWarning(text); warn != "" {
		sb.WriteString("\n")
		sb.WriteString(warn)
	}
	return sb.String()
}
