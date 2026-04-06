package procexec

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"agent-tool/common"
	"agent-tool/tools/proclist"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	maxTimeoutSec = 300
	maxOutputSize = 64 * 1024 // 64 KB
)

// dangerousEnvKeys are environment variable keys that could be used to hijack execution.
var dangerousEnvKeys = map[string]bool{
	"PATH":              true,
	"LD_PRELOAD":        true,
	"LD_LIBRARY_PATH":   true,
	"DYLD_LIBRARY_PATH": true,
	"DYLD_INSERT_LIBRARIES": true,
	"DYLD_FRAMEWORK_PATH":   true,
	"COMSPEC":           true, // Windows command interpreter
	"PATHEXT":           true, // Windows executable extensions
	"IFS":               true, // shell field separator
}

type ProcExecInput struct {
	Command    string   `json:"command" jsonschema:"Command to execute (required)"`
	Args       []string `json:"args,omitempty" jsonschema:"Command arguments"`
	Cwd        string   `json:"cwd,omitempty" jsonschema:"Working directory (default: current directory)"`
	Env        []string `json:"env,omitempty" jsonschema:"Environment variables in KEY=VALUE format. Inherits parent environment by default"`
	TimeoutSec interface{} `json:"timeout_sec,omitempty" jsonschema:"Timeout in seconds (default 30, max 300). Ignored for background/suspended execution"`
	Background interface{} `json:"background,omitempty" jsonschema:"Start process in background and return PID immediately: true or false. Default: false"`
	Suspended  interface{} `json:"suspended,omitempty" jsonschema:"Start process in suspended state. Windows: CREATE_SUSPENDED, Linux: SIGSTOP. Implies background=true: true or false. Default: false"`
}

type ProcExecOutput struct {
	PID      int    `json:"pid"`
	ExitCode int    `json:"exit_code,omitempty"`
	Stdout   string `json:"stdout,omitempty"`
	Stderr   string `json:"stderr,omitempty"`
	Status   string `json:"status"`
}

func Handle(ctx context.Context, req *mcp.CallToolRequest, input ProcExecInput) (*mcp.CallToolResult, ProcExecOutput, error) {
	// 1. Validate command
	if strings.TrimSpace(input.Command) == "" {
		return errorResult("command is required")
	}

	// 2. Validate timeout
	timeoutSec, ok := common.FlexInt(input.TimeoutSec)
	if !ok {
		return errorResult("timeout_sec must be an integer")
	}
	if timeoutSec < 0 {
		return errorResult("timeout_sec must be non-negative")
	}
	if timeoutSec == 0 {
		timeoutSec = 30
	}
	if timeoutSec > maxTimeoutSec {
		return errorResult(fmt.Sprintf("timeout_sec exceeds maximum (%d)", maxTimeoutSec))
	}

	// 3. Validate and resolve cwd
	if input.Cwd != "" {
		input.Cwd = filepath.Clean(input.Cwd)
		absPath, err := filepath.Abs(input.Cwd)
		if err != nil {
			return errorResult(fmt.Sprintf("invalid working directory: %v", err))
		}
		input.Cwd = absPath

		fi, err := os.Stat(input.Cwd)
		if err != nil {
			return errorResult(fmt.Sprintf("working directory not found: %s", input.Cwd))
		}
		if !fi.IsDir() {
			return errorResult(fmt.Sprintf("working directory is not a directory: %s", input.Cwd))
		}
	}

	// 4. Validate env format and block dangerous keys
	for _, e := range input.Env {
		if !strings.Contains(e, "=") {
			return errorResult(fmt.Sprintf("invalid env format (must be KEY=VALUE): %s", e))
		}
		key := strings.ToUpper(e[:strings.Index(e, "=")])
		if dangerousEnvKeys[key] {
			return errorResult(fmt.Sprintf("env key %q is blocked for security (could alter execution behavior)", key))
		}
	}

	// 5. Suspended implies background
	suspended := common.FlexBool(input.Suspended)
	background := common.FlexBool(input.Background) || suspended

	// 6. Execute
	if suspended {
		return execSuspended(input)
	}
	if background {
		return execBackground(input)
	}
	return execForeground(ctx, input, timeoutSec)
}

func execForeground(ctx context.Context, input ProcExecInput, timeoutSec int) (*mcp.CallToolResult, ProcExecOutput, error) {
	execCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSec)*time.Second)
	defer cancel()

	cmd := exec.CommandContext(execCtx, input.Command, input.Args...)
	if input.Cwd != "" {
		cmd.Dir = input.Cwd
	}
	if len(input.Env) > 0 {
		cmd.Env = mergeEnv(input.Env)
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &limitWriter{buf: &stdout, max: maxOutputSize}
	cmd.Stderr = &limitWriter{buf: &stderr, max: maxOutputSize}

	err := cmd.Run()

	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else if execCtx.Err() == context.DeadlineExceeded {
			return errorResult(fmt.Sprintf("process timed out after %d seconds", timeoutSec))
		} else {
			return errorResult(fmt.Sprintf("failed to execute: %v", err))
		}
	}

	pid := 0
	if cmd.Process != nil {
		pid = cmd.Process.Pid
	}

	out := ProcExecOutput{
		PID:      pid,
		ExitCode: exitCode,
		Stdout:   proclist.SanitizeCommandLine(stdout.String()),
		Stderr:   proclist.SanitizeCommandLine(stderr.String()),
		Status:   "completed",
	}

	var sb strings.Builder
	sb.WriteString("=== Process Execution ===\n")
	sb.WriteString(fmt.Sprintf("  Command: %s\n", formatCommand(input.Command, input.Args)))
	sb.WriteString(fmt.Sprintf("  PID: %d\n", out.PID))
	sb.WriteString(fmt.Sprintf("  Exit code: %d\n", out.ExitCode))
	sb.WriteString(fmt.Sprintf("  Status: %s\n", out.Status))

	if out.Stdout != "" {
		sb.WriteString(fmt.Sprintf("\n--- stdout ---\n%s", out.Stdout))
		if !strings.HasSuffix(out.Stdout, "\n") {
			sb.WriteString("\n")
		}
	}
	if out.Stderr != "" {
		sb.WriteString(fmt.Sprintf("\n--- stderr ---\n%s", out.Stderr))
		if !strings.HasSuffix(out.Stderr, "\n") {
			sb.WriteString("\n")
		}
	}

	result := sb.String()
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: result}},
		IsError: exitCode != 0,
	}, out, nil
}

func execBackground(input ProcExecInput) (*mcp.CallToolResult, ProcExecOutput, error) {
	cmd := exec.Command(input.Command, input.Args...)
	if input.Cwd != "" {
		cmd.Dir = input.Cwd
	}
	if len(input.Env) > 0 {
		cmd.Env = mergeEnv(input.Env)
	}

	// Detach stdout/stderr — background process
	cmd.Stdout = nil
	cmd.Stderr = nil

	if err := cmd.Start(); err != nil {
		return errorResult(fmt.Sprintf("failed to start: %v", err))
	}

	pid := cmd.Process.Pid
	// Release so we don't become the parent waiting for it
	cmd.Process.Release()

	out := ProcExecOutput{
		PID:    pid,
		Status: "running",
	}

	result := fmt.Sprintf("=== Process Execution ===\n  Command: %s\n  PID: %d\n  Status: running (background)\n",
		formatCommand(input.Command, input.Args), pid)
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: result}},
	}, out, nil
}

func execSuspended(input ProcExecInput) (*mcp.CallToolResult, ProcExecOutput, error) {
	pid, err := startSuspended(input.Command, input.Args, input.Cwd, input.Env)
	if err != nil {
		return errorResult(fmt.Sprintf("failed to start suspended: %v", err))
	}

	out := ProcExecOutput{
		PID:    pid,
		Status: "suspended",
	}

	result := fmt.Sprintf("=== Process Execution ===\n  Command: %s\n  PID: %d\n  Status: suspended\n  Use prockill with signal=cont to resume.\n",
		formatCommand(input.Command, input.Args), pid)
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: result}},
	}, out, nil
}

func Register(server *mcp.Server) {
	common.SafeAddTool(server, &mcp.Tool{
		Name: "procexec",
		Description: `Execute a command as a new process. Supports background execution and starting in suspended state.
WARNING: This tool executes arbitrary commands on the host system. Use with caution.
Use suspended=true to start a process in suspended state (Windows: CREATE_SUSPENDED, Linux: SIGSTOP).
Use prockill with signal=cont to resume a suspended process.`,
	}, Handle)
}

// mergeEnv merges user-specified env vars with the current environment.
// User vars override existing ones with the same key.
func mergeEnv(userEnv []string) []string {
	env := os.Environ()
	overrides := make(map[string]string)
	for _, e := range userEnv {
		idx := strings.Index(e, "=")
		if idx > 0 {
			overrides[strings.ToUpper(e[:idx])] = e
		}
	}

	var result []string
	for _, e := range env {
		idx := strings.Index(e, "=")
		if idx > 0 {
			key := strings.ToUpper(e[:idx])
			if _, overridden := overrides[key]; overridden {
				continue // will be added from overrides
			}
		}
		result = append(result, e)
	}
	for _, v := range overrides {
		result = append(result, v)
	}
	return result
}

func formatCommand(cmd string, args []string) string {
	parts := append([]string{cmd}, args...)
	return proclist.SanitizeCommandLine(strings.Join(parts, " "))
}

func errorResult(msg string) (*mcp.CallToolResult, ProcExecOutput, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		IsError: true,
	}, ProcExecOutput{}, nil
}

// limitWriter writes up to max bytes to buf, then silently discards the rest.
type limitWriter struct {
	buf *bytes.Buffer
	max int
}

func (w *limitWriter) Write(p []byte) (int, error) {
	remaining := w.max - w.buf.Len()
	if remaining <= 0 {
		return len(p), nil
	}
	if len(p) > remaining {
		w.buf.Write(p[:remaining])
		return len(p), nil
	}
	w.buf.Write(p)
	return len(p), nil
}
