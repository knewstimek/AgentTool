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

	// 1st pass: direct match with original string.
	// When old_string has leading whitespace, require line-boundary alignment
	// (match must start at position 0 or immediately after '\n').
	// This prevents a shallowly-indented old_string from matching as a
	// substring inside a more-deeply-indented line, which would produce
	// incorrect indentation in the replacement -- especially for multiline
	// new_string where only the first line would inherit the surrounding tabs.
	var count int
	if hasLeadingWhitespace(normalizedOld) {
		count = lineStartCount(content, normalizedOld)
	} else {
		count = strings.Count(content, normalizedOld)
	}
	if count > 0 {
		finalNew := normalizedNew
		// forceStyle: force-convert newStr to fileStyle when indent_style is explicitly specified
		if forceStyle {
			newStyle := DetectIndentOfString(newStr)
			if newStyle.UseTabs != fileStyle.UseTabs || newStyle.IndentSize != fileStyle.IndentSize {
				finalNew = ConvertIndent(normalizedNew, newStyle, fileStyle)
			}
		}
		if hasLeadingWhitespace(normalizedOld) {
			return applyLineStartReplace(content, normalizedOld, finalNew, count, replaceAll)
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

	// 6th pass: tab depth normalization.
	// Handles the case where both file and old_string use tabs but have different
	// base indentation depth (e.g. old_string has 2 tabs, file has 3 tabs).
	// Passes 2-4 only handle tabs<->spaces conversion, not depth differences.
	// Tries shifting old_string by 0-10 tabs, preserving relative indentation.
	if fileStyle.UseTabs && hasLeadingTabs(normalizedOld) {
		// minTabsNew is computed independently from minTabsOld so that tabDelta
		// captures the relative indent change between old and new. For example,
		// if old has min 2 tabs and new has min 3 tabs, new is always 1 level
		// deeper -- this relationship must be preserved when shifting to actual depth.
		//
		// Candidates are collected across all depths before picking the best one,
		// preferring unambiguous matches (count==1) over multiple matches, and
		// among equal ambiguity preferring depth closest to original minTabsOld.
		// This avoids incorrectly matching outer-scope code when the same snippet
		// appears at multiple indentation levels.
		minTabsOld := findMinLeadingTabs(normalizedOld)
		minTabsNew := findMinLeadingTabs(normalizedNew)
		tabDelta := minTabsNew - minTabsOld
		strippedOld := shiftTabs(normalizedOld, -minTabsOld)
		strippedNew := shiftTabs(normalizedNew, -minTabsNew)

		type candidate struct{ baseTabs, count int }
		var candidates []candidate
		for baseTabs := 0; baseTabs <= 10; baseTabs++ {
			if baseTabs == minTabsOld {
				continue // already tried this exact depth in pass 1
			}
			shiftedOld := shiftTabs(strippedOld, baseTabs)
			cnt := strings.Count(content, shiftedOld)
			if cnt > 0 {
				candidates = append(candidates, candidate{baseTabs, cnt})
			}
		}
		if len(candidates) > 0 {
			absDist := func(a, b int) int {
				if a > b {
					return a - b
				}
				return b - a
			}
			best := candidates[0]
			for _, c := range candidates[1:] {
				cUniq := c.count == 1
				bUniq := best.count == 1
				if cUniq && !bUniq {
					best = c
				} else if cUniq == bUniq {
					// Same uniqueness: prefer depth closest to original.
					if absDist(c.baseTabs, minTabsOld) < absDist(best.baseTabs, minTabsOld) {
						best = c
					}
				}
			}
			shiftedOld := shiftTabs(strippedOld, best.baseTabs)
			// Clamp newDepth to 0: when new_string is shallower than old_string
			// (negative tabDelta), the computed depth can go below zero if the
			// actual file depth is smaller than |tabDelta|. Top-level (0 tabs)
			// is the minimum valid indentation.
			newDepth := best.baseTabs + tabDelta
			if newDepth < 0 {
				newDepth = 0
			}
			shiftedNew := shiftTabs(strippedNew, newDepth)
			return applyReplace(content, shiftedOld, shiftedNew, best.count, replaceAll)
		}
	}

	// 7th pass (diagnostic only): normalize all leading whitespace line-by-line
	// and check whether the content exists with different indentation.
	// Covers remaining cases (e.g. spaces in old_string, tabs in file) not caught
	// by passes 2-6. Does NOT auto-fix -- gives an actionable error message instead.
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

// findMinLeadingTabs returns the minimum number of leading tabs across all
// non-empty, non-whitespace-only lines. Empty lines are ignored so that
// blank lines inside a block do not incorrectly reduce the minimum to 0.
func findMinLeadingTabs(s string) int {
	min := -1
	for _, line := range strings.Split(s, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		n := len(line) - len(strings.TrimLeft(line, "\t"))
		if min < 0 || n < min {
			min = n
		}
	}
	if min < 0 {
		return 0
	}
	return min
}

// shiftTabs adds (positive delta) or removes (negative delta) leading tabs
// from every line. Lines with fewer tabs than the removal amount get all
// their leading tabs stripped rather than going negative.
func shiftTabs(s string, delta int) string {
	if delta == 0 {
		return s
	}
	lines := strings.Split(s, "\n")
	prefix := ""
	if delta > 0 {
		prefix = strings.Repeat("\t", delta)
	}
	for i, line := range lines {
		if delta > 0 {
			lines[i] = prefix + line
		} else {
			toRemove := -delta
			tabCount := len(line) - len(strings.TrimLeft(line, "\t"))
			if tabCount < toRemove {
				toRemove = tabCount
			}
			lines[i] = line[toRemove:]
		}
	}
	return strings.Join(lines, "\n")
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

// hasLeadingWhitespace returns true if the first character of s is a tab or space.
// Used to decide whether line-boundary anchoring is needed in pass 1.
func hasLeadingWhitespace(s string) bool {
	return len(s) > 0 && (s[0] == '\t' || s[0] == ' ')
}

// lineStartIndices returns the start positions of all occurrences of sub in s
// that begin at a line boundary (position 0 or immediately after '\n').
func lineStartIndices(s, sub string) []int {
	var out []int
	for i := 0; i <= len(s)-len(sub); {
		idx := strings.Index(s[i:], sub)
		if idx < 0 {
			break
		}
		pos := i + idx
		if pos == 0 || s[pos-1] == '\n' {
			out = append(out, pos)
		}
		i = pos + len(sub)
	}
	return out
}

// lineStartCount counts occurrences of sub in s that start at a line boundary.
func lineStartCount(s, sub string) int {
	return len(lineStartIndices(s, sub))
}

// applyLineStartReplace is like applyReplace but only replaces occurrences
// of oldStr that start at a line boundary. count must equal lineStartCount(content, oldStr).
func applyLineStartReplace(content, oldStr, newStr string, count int, replaceAll bool) ReplaceResult {
	if !replaceAll && count > 1 {
		return ReplaceResult{
			Applied: false,
			Message: fmt.Sprintf("old_string found %d times. Use replace_all=true or provide more context to make it unique", count),
		}
	}
	indices := lineStartIndices(content, oldStr)
	if !replaceAll {
		indices = indices[:1]
	}
	var result strings.Builder
	prev := 0
	for _, idx := range indices {
		result.WriteString(content[prev:idx])
		result.WriteString(newStr)
		prev = idx + len(oldStr)
	}
	result.WriteString(content[prev:])
	return ReplaceResult{
		Content:    result.String(),
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
