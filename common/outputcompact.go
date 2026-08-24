package common

import (
	"fmt"
	"regexp"
	"strings"
)

// OutputCompaction describes a display-only transformation of command output.
// Text is compacted, while the caller remains responsible for preserving the
// original text when Compacted is true.
type OutputCompaction struct {
	Text         string
	Compacted    bool
	InputLines   int
	OutputLines  int
	OmittedLines int
	Groups       int
}

var gitWorkingCopyLineEndingWarning = regexp.MustCompile(
	`^warning: in the working copy of (.+), ((?:LF|CRLF) will be replaced by (?:LF|CRLF) the next time Git touches it)$`,
)

// NormalizeOutputView validates the display mode shared by command tools.
func NormalizeOutputView(view string) (string, error) {
	view = strings.ToLower(strings.TrimSpace(view))
	if view == "" {
		return "compact", nil
	}
	if view != "compact" && view != "raw" {
		return "", fmt.Errorf("output_view must be compact or raw")
	}
	return view, nil
}

// CompactDiagnosticOutput folds only diagnostic-looking repetition. It does
// not collapse arbitrary repeated program output, because duplicate data lines
// may be semantically meaningful. Known Git working-copy line-ending warnings
// are grouped by warning type while retaining a few representative paths.
func CompactDiagnosticOutput(text string) OutputCompaction {
	if text == "" {
		return OutputCompaction{Text: text}
	}

	// MCP text does not attach meaning to CRLF versus LF. Normalizing only the
	// compact display keeps grouping deterministic; the separately preserved
	// raw output remains byte-for-byte identical to this function's input.
	normalized := strings.ReplaceAll(text, "\r\n", "\n")
	trailingNewline := strings.HasSuffix(normalized, "\n")
	lines := strings.Split(normalized, "\n")
	if trailingNewline {
		lines = lines[:len(lines)-1]
	}

	out := make([]string, 0, len(lines))
	stats := OutputCompaction{InputLines: len(lines)}
	for i := 0; i < len(lines); {
		if path, message, ok := parseGitLineEndingWarning(lines[i]); ok {
			paths := []string{path}
			j := i + 1
			for j < len(lines) {
				nextPath, nextMessage, nextOK := parseGitLineEndingWarning(lines[j])
				if !nextOK || nextMessage != message {
					break
				}
				paths = append(paths, nextPath)
				j++
			}
			if len(paths) > 1 {
				out = append(out, formatGitLineEndingGroup(message, paths))
				stats.Groups++
				stats.OmittedLines += len(paths) - 1
				i = j
				continue
			}
		}

		j := i + 1
		for j < len(lines) && lines[j] == lines[i] {
			j++
		}
		count := j - i
		if count > 1 && isDiagnosticLine(lines[i]) {
			out = append(out, fmt.Sprintf("%s [x%d]", lines[i], count))
			stats.Groups++
			stats.OmittedLines += count - 1
		} else {
			out = append(out, lines[i:j]...)
		}
		i = j
	}

	stats.OutputLines = len(out)
	stats.Compacted = stats.Groups > 0
	stats.Text = strings.Join(out, "\n")
	if trailingNewline {
		stats.Text += "\n"
	}
	return stats
}

func parseGitLineEndingWarning(line string) (path, message string, ok bool) {
	matches := gitWorkingCopyLineEndingWarning.FindStringSubmatch(strings.TrimSpace(line))
	if len(matches) != 3 {
		return "", "", false
	}
	return matches[1], matches[2], true
}

func formatGitLineEndingGroup(message string, paths []string) string {
	const maxExamples = 3
	examples := paths
	if len(examples) > maxExamples {
		examples = examples[:maxExamples]
	}
	result := fmt.Sprintf("warning: %s for %d working-copy files: %s", message, len(paths), strings.Join(examples, ", "))
	if len(paths) > len(examples) {
		result += fmt.Sprintf(" ... (+%d more)", len(paths)-len(examples))
	}
	return result
}

func isDiagnosticLine(line string) bool {
	line = strings.ToLower(strings.TrimSpace(line))
	for _, prefix := range []string{
		"warning:", "warn:", "error:", "fatal:", "note:",
		"[warning]", "[warn]", "[error]", "[fatal]", "[note]",
	} {
		if strings.HasPrefix(line, prefix) {
			return true
		}
	}
	for _, marker := range []string{": warning:", ": warn:", ": error:", ": fatal:", ": note:"} {
		if strings.Contains(line, marker) {
			return true
		}
	}
	return false
}
