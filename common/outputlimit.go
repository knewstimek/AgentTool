package common

import (
	"strings"
	"unicode/utf8"
)

// TruncateRunes limits text by Unicode code points rather than bytes so tool
// output never contains a broken UTF-8 sequence. The caller supplies the
// suffix because different tools need different continuation guidance.
func TruncateRunes(text string, maxRunes int, suffix string) (string, bool) {
	if maxRunes < 0 || utf8.RuneCountInString(text) <= maxRunes {
		return text, false
	}
	if maxRunes == 0 {
		return "", true
	}
	runes := []rune(text)
	if len([]rune(suffix)) >= maxRunes {
		return string(runes[:maxRunes]), true
	}
	keep := maxRunes - len([]rune(suffix))
	return string(runes[:keep]) + suffix, true
}

// AppendWithinRuneBudget appends text only when the complete fragment fits.
// Keeping result records atomic lets callers report an exact continuation
// offset instead of cutting a row, variable, or symbol in half.
func AppendWithinRuneBudget(sb *strings.Builder, used *int, text string, maxRunes int) bool {
	n := utf8.RuneCountInString(text)
	if maxRunes > 0 && *used+n > maxRunes {
		return false
	}
	sb.WriteString(text)
	*used += n
	return true
}
