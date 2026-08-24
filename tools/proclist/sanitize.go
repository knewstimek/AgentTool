package proclist

import (
	"regexp"
	"strings"
)

var inlineEnvPattern = regexp.MustCompile(`(?i)\b(PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|APIKEY|CREDENTIAL|ACCESS_KEY|SIGNING_KEY)=(\S+)`)

// Go RE2 does not support backreferences, so quoted values use separate
// patterns for double and single quotes.
var quotedArgPatternDQ = regexp.MustCompile(`(?i)(--(?:password|passwd|pass|token|secret|key|api-key|apikey|auth|credential|access-token|client-secret))([ \t\r\n]+)"[^"]*"`)
var quotedArgPatternSQ = regexp.MustCompile(`(?i)(--(?:password|passwd|pass|token|secret|key|api-key|apikey|auth|credential|access-token|client-secret))([ \t\r\n]+)'[^']*'`)

var urlCredentialPattern = regexp.MustCompile(`://([^:@/]+):([^@]+)@`)
var bearerPattern = regexp.MustCompile(`(?i)(Bearer|Basic)([ \t\r\n]+)(\S+)`)
var sensitiveEqualPattern = regexp.MustCompile(`(?i)(--(?:password|passwd|pass|token|secret|key|api-key|apikey|auth|credential|access-token|client-secret)=)(\S+)`)
var sensitiveFollowingArgPattern = regexp.MustCompile(`(?i)(--(?:password|passwd|pass|token|secret|key|api-key|apikey|auth|credential|access-token|client-secret))([ \t\r\n]+)([^\s"'][^\s]*)`)

// SanitizeCommandLine masks sensitive arguments and normalizes a command line
// to a single space-separated display string.
func SanitizeCommandLine(cmdline string) string {
	if cmdline == "" {
		return cmdline
	}
	return strings.Join(strings.Fields(SanitizeOutput(cmdline)), " ")
}

// SanitizeOutput masks the same sensitive values as SanitizeCommandLine while
// preserving whitespace and line boundaries. It is suitable for stdout/stderr,
// where collapsing lines would change the program output and diagnostics.
func SanitizeOutput(output string) string {
	if output == "" {
		return output
	}

	result := urlCredentialPattern.ReplaceAllString(output, "://$1:***@")
	result = bearerPattern.ReplaceAllString(result, "${1}${2}***")
	result = quotedArgPatternDQ.ReplaceAllString(result, "${1}${2}***")
	result = quotedArgPatternSQ.ReplaceAllString(result, "${1}${2}***")
	result = inlineEnvPattern.ReplaceAllString(result, "${1}=***")
	result = sensitiveEqualPattern.ReplaceAllString(result, "${1}***")
	result = sensitiveFollowingArgPattern.ReplaceAllString(result, "${1}${2}***")
	return result
}
