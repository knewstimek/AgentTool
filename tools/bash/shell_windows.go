//go:build windows

package bash

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"agent-tool/common"
)

// detectShell finds the best available shell on Windows.
// Priority: pwsh (7+) > git-bash > powershell (5.1) > cmd.exe
//
// Git-bash is preferred over PowerShell 5.1 because PS 5.1 doesn't support
// && / || operators, GOOS=linux env syntax, or other bash conventions that
// AI agents commonly use. PS 5.1 parsing failures can also cause sentinel
// hangs that are difficult to recover from.
func detectShell() (string, []string, shellKind) {
	// PowerShell 7+ (pwsh.exe) — supports && / || natively, best of both worlds
	if path, err := exec.LookPath("pwsh.exe"); err == nil {
		return path, psArgs(), kindPwsh
	}

	// Git bash — most Windows developers have Git installed.
	// Handles &&, ||, env vars, Unix paths natively — no parsing surprises.
	gitPaths := []string{
		filepath.Join(os.Getenv("ProgramFiles"), "Git", "bin", "bash.exe"),
		filepath.Join(os.Getenv("ProgramFiles(x86)"), "Git", "bin", "bash.exe"),
		filepath.Join(os.Getenv("LOCALAPPDATA"), "Programs", "Git", "bin", "bash.exe"),
	}
	for _, p := range gitPaths {
		if _, err := os.Stat(p); err == nil {
			return p, []string{}, kindGitBash
		}
	}

	// Windows PowerShell 5.1 — does NOT support && / ||.
	// Chain operators are auto-transformed (see chainops.go), but other PS
	// parsing edge cases can still cause sentinel hangs.
	if path, err := exec.LookPath("powershell.exe"); err == nil {
		return path, psArgs(), kindPowerShell
	}

	// Fallback: cmd.exe
	return "cmd.exe", []string{"/Q"}, kindCmd
}

// psArgs returns PowerShell arguments with an init script that sets
// UTF-8 encoding and enhances PATH with common tool directories.
func psArgs() []string {
	var init strings.Builder
	init.WriteString("[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; ")
	init.WriteString("$OutputEncoding = [System.Text.Encoding]::UTF8; ")
	init.WriteString("function prompt {''}; ") // suppress prompt to reduce echo noise
	init.WriteString(`$__p = @("$env:USERPROFILE\bin","$env:USERPROFILE\scoop\shims","$env:USERPROFILE\.cargo\bin","C:\ProgramData\chocolatey\bin"); `)
	init.WriteString(`foreach($d in $__p){if(Test-Path $d){$env:PATH += ";$d"}}`)

	return []string{"-NoProfile", "-NoLogo", "-NoExit", "-Command", init.String()}
}

// startShellSession starts a new interactive shell process.
func startShellSession(key string, cwd string) (*shellSession, error) {
	shell, args, kind := detectShell()
	cmd := exec.Command(shell, args...)

	if cwd != "" {
		cmd.Dir = cwd
	}

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("stdin pipe: %w", err)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		stdin.Close()
		return nil, fmt.Errorf("stdout pipe: %w", err)
	}

	// Merge stderr into stdout for simplicity
	cmd.Stderr = cmd.Stdout

	if err := cmd.Start(); err != nil {
		stdin.Close()
		return nil, fmt.Errorf("start shell: %w", err)
	}

	now := time.Now()
	return &shellSession{
		cmd:       cmd,
		stdin:     stdin,
		stdoutR:   bufio.NewReaderSize(stdout, 64*1024),
		key:       key,
		shellKind: kind,
		createdAt: now,
		lastUsed:  now,
	}, nil
}

// decodeOutput converts shell output to UTF-8.
// PowerShell and git bash output UTF-8 directly; cmd.exe needs console decoding.
func decodeOutput(kind shellKind, raw string) string {
	if kind == kindCmd {
		return common.DecodeConsoleOutput([]byte(raw))
	}
	return raw
}

// findGitBash returns the path to git bash if installed, empty string otherwise.
func findGitBash() string {
	for _, p := range []string{
		filepath.Join(os.Getenv("ProgramFiles"), "Git", "bin", "bash.exe"),
		filepath.Join(os.Getenv("ProgramFiles(x86)"), "Git", "bin", "bash.exe"),
		filepath.Join(os.Getenv("LOCALAPPDATA"), "Programs", "Git", "bin", "bash.exe"),
	} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// buildPSChainOps converts parsed chain segments to PowerShell equivalents.
//
//	"cmd1 && cmd2"  →  "$global:LASTEXITCODE=0; cmd1; if($global:LASTEXITCODE -eq 0){ cmd2 }"
//	"cmd1 || cmd2"  →  "$global:LASTEXITCODE=0; cmd1; if($global:LASTEXITCODE -ne 0){ cmd2 }"
func buildPSChainOps(parsed chainParse) string {
	var result strings.Builder
	// Initialize $LASTEXITCODE to 0 so the first "if" check works even when
	// the first command is a PS cmdlet (which doesn't set $LASTEXITCODE).
	result.WriteString("$global:LASTEXITCODE=0; ")
	result.WriteString(parsed.Segments[0].Text)

	for i := 0; i < len(parsed.Segments)-1; i++ {
		op := parsed.Segments[i].Op
		next := parsed.Segments[i+1].Text
		if op == "&&" {
			result.WriteString("; if($global:LASTEXITCODE -eq 0){ ")
		} else {
			result.WriteString("; if($global:LASTEXITCODE -ne 0){ ")
		}
		result.WriteString(next)
		result.WriteString(" }")
	}

	return result.String()
}

// delegateToGitBash wraps a command for execution via git-bash from PowerShell.
// Uses PS single-quotes so PowerShell treats the entire string as a literal —
// no backtick, dollar, or backslash interpretation. Bash -c receives the
// command exactly as-is since PS single-quoted strings are verbatim.
func delegateToGitBash(command, gbPath string) string {
	// In PS single-quotes, the only special char is ' itself (escaped as '').
	escaped := strings.ReplaceAll(command, "'", "''")
	return fmt.Sprintf("& '%s' -c '%s'", gbPath, escaped)
}

// delegateToCmdExe wraps a command for execution via cmd.exe from PowerShell.
// NOTE: cmd.exe still interprets its own special chars (%VAR%, ^, &, >, <, |)
// after receiving the string. This is a known limitation of the cmd.exe fallback;
// prefer git-bash when available.
func delegateToCmdExe(command string) string {
	escaped := strings.ReplaceAll(command, "'", "''")
	return fmt.Sprintf("& cmd /c '%s'", escaped)
}

// delegateToExternalShell wraps a command for execution via git-bash or cmd.exe.
// Prefer git-bash (handles Unix paths, UTF-8), fall back to cmd.exe.
func delegateToExternalShell(command string) string {
	if gb := findGitBash(); gb != "" {
		return delegateToGitBash(command, gb)
	}
	return delegateToCmdExe(command)
}

// wrapWithTokenize wraps a command in a PS Tokenize pre-validation wrapper.
// The command is Base64-encoded so PowerShell never directly parses the raw text.
// PSParser::Tokenize checks syntax before Invoke-Expression executes it.
// If parse errors are found, an error message is shown and $LASTEXITCODE=1,
// but the sentinel ALWAYS runs because the wrapper itself is always valid PS syntax.
// This prevents sentinel hangs from ANY PS 5.1 parsing failure, not just && / ||.
func wrapWithTokenize(command string) string {
	b64 := base64.StdEncoding.EncodeToString([]byte(command))
	var w strings.Builder
	w.WriteString("$__b64='")
	w.WriteString(b64)
	w.WriteString("'; ")
	w.WriteString("$__cmd=[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($__b64)); ")
	w.WriteString("$__e=$null; ")
	w.WriteString("[void][System.Management.Automation.PSParser]::Tokenize($__cmd,[ref]$__e); ")
	w.WriteString("if($__e.Count -gt 0){ ")
	// Use string concatenation instead of expandable string to avoid
	// quote injection if error message contains double quotes.
	w.WriteString("Write-Host ('PS syntax error: ' + $__e[0].Message); ")
	w.WriteString("$global:LASTEXITCODE=1 ")
	// Reset $LASTEXITCODE before execution so the sentinel's $null check
	// can fall back to $? for PS cmdlets that don't set $LASTEXITCODE.
	w.WriteString("}else{ $global:LASTEXITCODE=$null; Invoke-Expression $__cmd }")
	return w.String()
}

// buildSentinelCmd wraps a command with exit code capture and sentinel marker.
func buildSentinelCmd(kind shellKind, command string, sentinel string) string {
	switch kind {
	case kindPwsh:
		// PowerShell 7+ supports && and || natively.
		// Use newline to separate command from sentinel (same heredoc/here-string fix as bash).
		return fmt.Sprintf(
			"%s\n$__ec = $LASTEXITCODE; if ($null -eq $__ec) { $__ec = if ($?) {0} else {1} }; Write-Host \"\"; Write-Host \"%s$__ec%s\"",
			command, sentinel, sentinelSuffix,
		)
	case kindPowerShell:
		// PowerShell 5.1: && / || cause a parse error that kills the entire line
		// including the sentinel, causing the reader to hang forever.
		// Parse once, then choose strategy based on result.
		// handler.go also emits a warning so the agent learns to use ; instead.
		userCmd := command
		parsed := parseChainOps(command)
		if parsed.NeedsDelegation() {
			// Command contains && / || inside $() or () — PS 5.1 can't parse
			// these even as subexpressions. Delegate the whole command.
			userCmd = delegateToExternalShell(command)
		} else if parsed.HasChainOps() {
			if parsed.HasEmptySegment() {
				// Syntax errors like "&& cmd" — still can't pass raw to PS 5.1.
				userCmd = delegateToExternalShell(command)
			} else {
				// Simple top-level chain: transform to PS equivalents.
				userCmd = buildPSChainOps(parsed)
			}
		}
		// Wrap with Tokenize pre-validation as a safety net against ANY PS 5.1
		// parse failure (not just && / ||). The Base64 + Tokenize wrapper ensures
		// the sentinel always runs even if the command has unexpected syntax.
		userCmd = wrapWithTokenize(userCmd)
		return fmt.Sprintf(
			"%s\n$__ec = $LASTEXITCODE; if ($null -eq $__ec) { $__ec = if ($?) {0} else {1} }; Write-Host \"\"; Write-Host \"%s$__ec%s\"",
			userCmd, sentinel, sentinelSuffix,
		)
	case kindGitBash:
		// Use newline (not ;) to separate user command from sentinel.
		// Semicolon breaks heredocs: "EOF; EXIT_CODE=..." is not a valid heredoc terminator.
		return fmt.Sprintf(
			"%s\nEXIT_CODE=$?; echo \"\"; echo \"%s${EXIT_CODE}%s\"",
			command, sentinel, sentinelSuffix,
		)
	default: // kindCmd
		// Capture exit code in a temp var to avoid %sentinelSuffix being parsed as env var
		return fmt.Sprintf(
			"%s & set __ec=%%ERRORLEVEL%% & echo. & echo %s%%__ec%%%s",
			command, sentinel, sentinelSuffix,
		)
	}
}
