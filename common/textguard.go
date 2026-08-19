package common

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	// maxEchoRunes caps the non-ASCII echo so a large translated block cannot
	// balloon the response. Enough to eyeball a few phrases, not a whole file.
	maxEchoRunes = 100
	// longWordRunes: past this length a space-delimited token is not a word --
	// a minified JS line, a one-line JSON, a long URL -- and echoing it whole
	// spends the cap on ASCII that needs no checking.
	longWordRunes = 24
	// contextRunes kept either side of a non-ASCII stretch inside such a token.
	contextRunes = 4
)

// ReplacementCharCount returns how many U+FFFD are in text and the 1-based line
// of the first one (0 when there are none).
//
// U+FFFD is what a decoder leaves behind when it gives up on a byte sequence,
// and it is unrecoverable: the original character's identity is gone, so the
// only fix is to send the text again. It reaches this tool when a multi-byte
// character was split upstream -- a known Claude Code streaming failure on CJK
// (anthropics/claude-code#43858) -- and unflagged it lands in the file and
// surfaces weeks later. Genuine text practically never contains one.
func ReplacementCharCount(text string) (count, line int) {
	count = strings.Count(text, string(utf8.RuneError))
	if count == 0 {
		return 0, 0
	}
	line = 1
	for _, r := range text {
		if r == utf8.RuneError {
			break
		}
		if r == '\n' {
			line++
		}
	}
	return count, line
}

// ReplacementCharWarning formats ReplacementCharCount for a caller whose text
// maps to file lines. Callers whose text does not (multiedit concatenates its
// edits) should use ReplacementCharCount and name their own location.
func ReplacementCharWarning(text string) string {
	count, line := ReplacementCharCount(text)
	if count == 0 {
		return ""
	}
	return fmt.Sprintf("%s %d replacement char(s) U+FFFD in the text written, first at line %d. "+
		"These were corrupted before reaching this tool and the original characters cannot be "+
		"recovered -- re-send that text.", WarnSign, count, line)
}

// invisibleName names a non-ASCII character that renders as nothing, or as an
// ordinary space. Echoing these back cannot work -- a no-break space looks
// exactly like a space, and a zero-width space looks like nothing at all -- so
// they are counted instead. Returns "" for characters the echo can show.
//
// U+200D (ZWJ) is deliberately absent: it is load-bearing inside emoji
// sequences, where flagging it would be noise on every family or flag emoji.
func invisibleName(r rune) string {
	switch r {
	case 0x00A0:
		return "U+00A0 no-break space"
	case 0x1680:
		return "U+1680 ogham space mark"
	case 0x2028:
		return "U+2028 line separator"
	case 0x2029:
		return "U+2029 paragraph separator"
	case 0x202F:
		return "U+202F narrow no-break space"
	case 0x205F:
		return "U+205F medium mathematical space"
	case 0x3000:
		return "U+3000 ideographic space"
	case 0x200B:
		return "U+200B zero-width space"
	case 0x200C:
		return "U+200C zero-width non-joiner"
	case 0xFEFF:
		return "U+FEFF zero-width no-break space"
	}
	if r >= 0x2000 && r <= 0x200A {
		return fmt.Sprintf("U+%04X unicode space", r)
	}
	return ""
}

// InvisibleCharNotice counts characters that look like ASCII space or like
// nothing, so a stray no-break space in code is reported rather than silently
// written. Returns "" when there are none.
func InvisibleCharNotice(text string) string {
	counts := make(map[string]int)
	var order []string
	for _, r := range text {
		name := invisibleName(r)
		if name == "" {
			continue
		}
		if counts[name] == 0 {
			order = append(order, name)
		}
		counts[name]++
	}
	if len(order) == 0 {
		return ""
	}
	parts := make([]string, 0, len(order))
	for _, name := range order {
		parts = append(parts, fmt.Sprintf("%d x %s", counts[name], name))
	}
	return "invisible char(s) written: " + strings.Join(parts, ", ") +
		" -- these render as a space or as nothing, so check they are intended"
}

// NonASCIIEcho returns the non-ASCII words in text, joined by ", ".
//
// It exists so an agent that composed a string as \uXXXX escapes sees the
// actual characters it produced. Hangul fills U+AC00..U+D7A3 solid, so one
// wrong hex digit still yields a perfectly valid character (설 vs 섥) and no
// validation can catch it -- but rendered back as text, the wrong glyph is
// obvious.
//
// Whole words, not bare non-ASCII runs: scripts that write words entirely
// outside ASCII (CJK, Cyrillic, Arabic) read fine either way, but Latin ones
// mix within a word, and echoing just the "e" of "cafe" gives nothing to check.
// Adjacent non-ASCII words are joined so a phrase stays a phrase; an ASCII word
// or a line break ends the run.
//
// Returns "" when text is pure ASCII.
func NonASCIIEcho(text string) string {
	var runs []string
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
				cur = append(cur, condenseLongWord(word))
				continue
			}
			flush()
		}
		flush()
	}
	if len(runs) == 0 {
		return ""
	}
	return truncateEcho(strings.Join(runs, ", "))
}

// condenseLongWord keeps only the non-ASCII stretches of an over-long token,
// with a little context each side. Without this one minified line -- where the
// whole line is a single space-free "word" -- fills the cap with ASCII and
// pushes the text that actually needs checking out of the output.
func condenseLongWord(word string) string {
	runes := []rune(word)
	if len(runes) <= longWordRunes {
		return word
	}
	var parts []string
	for i := 0; i < len(runes); {
		if runes[i] <= unicode.MaxASCII {
			i++
			continue
		}
		start := i
		for i < len(runes) && runes[i] > unicode.MaxASCII {
			i++
		}
		lo, hi := start-contextRunes, i+contextRunes
		if lo < 0 {
			lo = 0
		}
		if hi > len(runes) {
			hi = len(runes)
		}
		parts = append(parts, string(runes[lo:hi]))
	}
	return strings.Join(parts, "..")
}

// truncateEcho caps the echo without splitting a grapheme cluster.
//
// Cutting on a rune boundary alone would render a different character than the
// one written -- a family emoji becomes a lone person, a flag becomes a letter
// -- which is precisely the failure this echo exists to expose. The total is
// reported so the cap is not mistaken for the whole text.
func truncateEcho(s string) string {
	runes := []rune(s)
	if len(runes) <= maxEchoRunes {
		return s
	}
	cut := safeCutIndex(runes, maxEchoRunes)
	return fmt.Sprintf("%s... (%d of %d runes)", string(runes[:cut]), cut, len(runes))
}

// safeCutIndex walks back from n until the cut does not sever a rune from one
// it binds to.
func safeCutIndex(runes []rune, n int) int {
	if n >= len(runes) {
		return len(runes)
	}
	for n > 0 {
		dropped, kept := runes[n], runes[n-1]
		bound := dropped == zeroWidthJoiner || kept == zeroWidthJoiner ||
			dropped == variationSelector15 || dropped == variationSelector16 ||
			unicode.Is(unicode.Mn, dropped) ||
			(isRegionalIndicator(kept) && isRegionalIndicator(dropped))
		if !bound {
			break
		}
		n--
	}
	return n
}

const (
	zeroWidthJoiner     = 0x200D
	variationSelector15 = 0xFE0E
	variationSelector16 = 0xFE0F
)

func isRegionalIndicator(r rune) bool {
	return r >= 0x1F1E6 && r <= 0x1F1FF
}

// NonASCIICount returns how many non-ASCII runes text contains, so a caller
// can decide whether echoing them is worth the tokens.
func NonASCIICount(text string) int {
	n := 0
	for _, r := range text {
		if r > unicode.MaxASCII {
			n++
		}
	}
	return n
}

func hasNonASCII(s string) bool {
	for _, r := range s {
		if r > unicode.MaxASCII {
			return true
		}
	}
	return false
}

// WarnSign is the marker EncodingWarning already uses, kept identical so all
// tool warnings read the same. Exported for callers that format their own
// location (multiedit names an edit index rather than a line).
const WarnSign = "⚠"

// TextGuardNotice is the suffix a write-side tool appends to its result:
// what non-ASCII was written, what was written but cannot be seen, and whether
// any of it arrived already corrupted. Empty when there is nothing to say.
func TextGuardNotice(text string) string {
	var sb strings.Builder
	if echo := NonASCIIEcho(text); echo != "" {
		sb.WriteString("\nnon-ASCII written: ")
		sb.WriteString(echo)
	}
	if notice := InvisibleCharNotice(text); notice != "" {
		sb.WriteString("\n")
		sb.WriteString(notice)
	}
	if warn := ReplacementCharWarning(text); warn != "" {
		sb.WriteString("\n")
		sb.WriteString(warn)
	}
	return sb.String()
}
