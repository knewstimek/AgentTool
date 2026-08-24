package ssh

import (
	"context"

	"agent-tool/common"

	gossh "golang.org/x/crypto/ssh"
)

// execResult holds the result of a remote command execution.
type execResult struct {
	Stdout          string
	Stderr          string
	ExitCode        int
	StdoutBytes     int64
	StderrBytes     int64
	StdoutTruncated bool
	StderrTruncated bool
}

// executeCommand runs a command on the remote server with timeout.
func executeCommand(ctx context.Context, client *gossh.Client, command string, maxOutputBytes int, outputMode string) (*execResult, error) {
	session, err := client.NewSession()
	if err != nil {
		return nil, err
	}
	defer session.Close()

	stdoutBuf := common.NewBoundedCaptureMode((maxOutputBytes+1)/2, outputMode)
	stderrBuf := common.NewBoundedCaptureMode(maxOutputBytes/2, outputMode)
	session.Stdout = stdoutBuf
	session.Stderr = stderrBuf

	// Run command in goroutine for timeout support
	done := make(chan error, 1)
	go func() {
		done <- session.Run(command)
	}()

	select {
	case <-ctx.Done():
		// Timeout — kill remote process and close session to unblock
		// the goroutine running session.Run (prevents goroutine leak).
		_ = session.Signal(gossh.SIGKILL)
		session.Close()
		<-done // wait for goroutine to exit
		return nil, ctx.Err()
	case err := <-done:
		stdout, stdoutBytes, stdoutTruncated := stdoutBuf.Result()
		stderr, stderrBytes, stderrTruncated := stderrBuf.Result()
		result := &execResult{
			Stdout:          stdout,
			Stderr:          stderr,
			ExitCode:        0,
			StdoutBytes:     stdoutBytes,
			StderrBytes:     stderrBytes,
			StdoutTruncated: stdoutTruncated,
			StderrTruncated: stderrTruncated,
		}
		if err != nil {
			if exitErr, ok := err.(*gossh.ExitError); ok {
				result.ExitCode = exitErr.ExitStatus()
			} else {
				return nil, err
			}
		}
		return result, nil
	}
}
