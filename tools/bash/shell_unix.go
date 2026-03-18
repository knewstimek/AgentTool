//go:build !windows

package bash

import (
	"bufio"
	"fmt"
	"os/exec"
	"time"
)


// shellCommand returns the shell binary for Unix.
func shellCommand() (string, []string) {
	// Prefer bash, fallback to sh
	for _, sh := range []string{"/bin/bash", "/usr/bin/bash", "/bin/sh"} {
		if _, err := exec.LookPath(sh); err == nil {
			return sh, []string{}
		}
	}
	return "/bin/sh", []string{}
}

// startShellSession starts a new interactive shell process.
func startShellSession(key string, cwd string) (*shellSession, error) {
	shell, args := shellCommand()
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
		createdAt: now,
		lastUsed:  now,
	}, nil
}

// decodeOutput returns the output as-is on Unix (UTF-8).
func decodeOutput(_ shellKind, raw string) string {
	return raw
}

// buildSentinelCmd wraps a command with exit code capture and sentinel marker.
func buildSentinelCmd(_ shellKind, command string, sentinel string) string {
	// Use newline (not ;) to separate user command from sentinel.
	// Semicolon breaks heredocs: "EOF; EXIT_CODE=..." is not recognized as heredoc terminator.
	// Newline ensures heredoc terminators, trailing comments, and backslash continuations
	// all resolve before the sentinel runs.
	return fmt.Sprintf("%s\nEXIT_CODE=$?; echo \"\"; echo \"%s${EXIT_CODE}%s\"", command, sentinel, sentinelSuffix)
}
