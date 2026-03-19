package edit

import (
	"fmt"
	"strings"
)

// ReplaceResult holds the result of a replacement operation.
type ReplaceResult struct {
	Content    string
	MatchCount int
	Applied    bool
	Message    string
}

// Replace replaces oldStr with newStr in content.
// Attempts automatic conversion to match the file's indentation style.
// If forceStyle is true, newStr's indentation is force-converted to fileStyle even on direct match.
func Replace(content, oldStr, newStr string, replaceAll bool, fileStyle IndentStyle, forceStyle bool) ReplaceResult {
	// Line ending normalization: convert \n in old_string to match the file's line endings
	lineEnding := "\n"
	if strings.Contains(content, "\r\n") {
		lineEnding = "\r\n"
	}

	// Match line endings of old_string/new_string to the file
	normalizedOld := normalizeLineEnding(oldStr, lineEnding)
	normalizedNew := normalizeLineEnding(newStr, lineEnding)

	// 1st pass: direct match with original string
	count := strings.Count(content, normalizedOld)
	if count > 0 {
		finalNew := normalizedNew
		// forceStyle: force-convert newStr to fileStyle when indent_style is explicitly specified
		if forceStyle {
			newStyle := DetectIndentOfString(newStr)
			if newStyle.UseTabs != fileStyle.UseTabs || newStyle.IndentSize != fileStyle.IndentSize {
				finalNew = ConvertIndent(normalizedNew, newStyle, fileStyle)
			}
		}
		return applyReplace(content, normalizedOld, finalNew, count, replaceAll)
	}

	// 2nd pass: match after indent conversion (spaces -> tabs or tabs -> spaces)
	srcStyle := DetectIndentOfString(oldStr)
	if srcStyle.UseTabs != fileStyle.UseTabs {
		convertedOld := ConvertIndent(normalizedOld, srcStyle, fileStyle)
		convertedNew := ConvertIndent(normalizedNew, srcStyle, fileStyle)

		count = strings.Count(content, convertedOld)
		if count > 0 {
			return applyReplace(content, convertedOld, convertedNew, count, replaceAll)
		}
	}

	// 3rd pass: force conversion when file uses tabs but old_string has spaces
	if fileStyle.UseTabs && HasLeadingSpaces(normalizedOld) {
		convertedOld := SpacesToTabs(normalizedOld, fileStyle.IndentSize)
		convertedNew := SpacesToTabs(normalizedNew, fileStyle.IndentSize)

		count = strings.Count(content, convertedOld)
		if count > 0 {
			return applyReplace(content, convertedOld, convertedNew, count, replaceAll)
		}
	}

	// 4th pass: brute-force indent sizes (2, 3, 4, 8) when auto-detection fails.
	// LLMs often use a different indent size than the file's actual tab stops,
	// causing deep nesting (6-7 levels) to mismatch after conversion.
	if fileStyle.UseTabs && HasLeadingSpaces(normalizedOld) {
		for _, trySize := range []int{2, 3, 4, 5, 6, 7, 8} {
			convertedOld := SpacesToTabs(normalizedOld, trySize)
			if convertedOld == normalizedOld {
				continue // no change, skip
			}
			count = strings.Count(content, convertedOld)
			if count > 0 {
				convertedNew := SpacesToTabs(normalizedNew, trySize)
				return applyReplace(content, convertedOld, convertedNew, count, replaceAll)
			}
		}
	}

	// 5th pass: reverse — file uses spaces but old_string has tabs
	if !fileStyle.UseTabs && hasLeadingTabs(normalizedOld) {
		for _, trySize := range []int{2, 3, 4, 5, 6, 7, 8} {
			convertedOld := TabsToSpaces(normalizedOld, trySize)
			count = strings.Count(content, convertedOld)
			if count > 0 {
				convertedNew := TabsToSpaces(normalizedNew, trySize)
				return applyReplace(content, convertedOld, convertedNew, count, replaceAll)
			}
		}
	}

	// 6th pass (diagnostic): normalize all leading whitespace line-by-line and
	// check whether the content exists with different indentation. This catches
	// the common case where old_string has the right content but wrong tab depth
	// (e.g. 2 tabs provided, file has 3 tabs). We do NOT auto-fix this — ambiguous
	// indentation replacement is risky — but we give an actionable error message.
	normContent := normalizeIndent(content)
	normOld := normalizeIndent(normalizedOld)
	if normOld != "" && strings.Contains(normContent, normOld) {
		return ReplaceResult{
			Applied: false,
			Message: "old_string not found: content exists in file but indentation differs (wrong number of tabs/spaces). Re-read the file to copy exact indentation.",
		}
	}

	return ReplaceResult{
		Applied: false,
		Message: "old_string not found in file",
	}
}

// normalizeIndent strips all leading whitespace from every line, preserving content.
// Used as a last-resort diagnostic to detect indentation mismatches.
func normalizeIndent(s string) string {
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		lines[i] = strings.TrimLeft(line, " \t")
	}
	return strings.Join(lines, "\n")
}

// applyReplace performs the actual replacement.
// If count > 1 and replaceAll is false, returns an error without replacing.
func applyReplace(content, oldStr, newStr string, count int, replaceAll bool) ReplaceResult {
	if !replaceAll && count > 1 {
		return ReplaceResult{
			Applied: false,
			Message: fmt.Sprintf("old_string found %d times. Use replace_all=true or provide more context to make it unique", count),
		}
	}

	var result string
	if replaceAll {
		result = strings.ReplaceAll(content, oldStr, newStr)
	} else {
		result = strings.Replace(content, oldStr, newStr, 1)
	}

	return ReplaceResult{
		Content:    result,
		MatchCount: count,
		Applied:    true,
		Message:    fmt.Sprintf("replaced %d occurrence(s)", count),
	}
}

// hasLeadingTabs returns true if any line in text starts with a tab.
func hasLeadingTabs(text string) bool {
	for _, line := range strings.Split(text, "\n") {
		if len(line) > 0 && line[0] == '\t' {
			return true
		}
	}
	return false
}

func normalizeLineEnding(s, target string) string {
	// First normalize all line endings to \n
	s = strings.ReplaceAll(s, "\r\n", "\n")
	// Convert to target line ending
	if target == "\r\n" {
		s = strings.ReplaceAll(s, "\n", "\r\n")
	}
	return s
}
