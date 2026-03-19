package bash

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"agent-tool/common"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const defaultSessionID = "default"

type BashInput struct {
	Command    string `json:"command" jsonschema:"Shell command to execute"`
	Cwd        string `json:"cwd,omitempty" jsonschema:"Initial working directory (only used when creating a new session)"`
	SessionID  string `json:"session_id,omitempty" jsonschema:"Session identifier for persistent shell. Default: default"`
	TimeoutSec int    `json:"timeout_sec,omitempty" jsonschema:"Command timeout in seconds (default 120, max 600)"`
	Disconnect bool   `json:"disconnect,omitempty" jsonschema:"Close the shell session"`
}

type BashOutput struct {
	SessionID string `json:"session_id"`
	Output    string `json:"output"`
	ExitCode  int    `json:"exit_code"`
	IsNew     bool   `json:"is_new"`
}

func Handle(ctx context.Context, req *mcp.CallToolRequest, input BashInput) (*mcp.CallToolResult, BashOutput, error) {
	// Normalize session ID
	if input.SessionID == "" {
		input.SessionID = defaultSessionID
	}

	// Handle disconnect
	if input.Disconnect {
		removed := pool.remove(input.SessionID)
		msg := fmt.Sprintf("Session %q closed.", input.SessionID)
		if !removed {
			msg = fmt.Sprintf("Session %q not found.", input.SessionID)
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		}, BashOutput{SessionID: input.SessionID}, nil
	}

	// Validate command
	if strings.TrimSpace(input.Command) == "" {
		return errorResult("command is required")
	}

	// Validate timeout
	if input.TimeoutSec <= 0 {
		input.TimeoutSec = 120
	}
	if input.TimeoutSec > maxTimeoutSec {
		return errorResult(fmt.Sprintf("timeout_sec exceeds maximum (%d)", maxTimeoutSec))
	}

	// Normalize cwd (validation deferred to session creation)
	if input.Cwd != "" {
		input.Cwd = filepath.Clean(input.Cwd)
		absPath, err := filepath.Abs(input.Cwd)
		if err != nil {
			return errorResult(fmt.Sprintf("invalid working directory: %v", err))
		}
		input.Cwd = absPath
	}

	// Get or create session
	sess, isNew, err := pool.getOrCreate(input.SessionID, input.Cwd)
	if err != nil {
		return errorResult(fmt.Sprintf("failed to start shell: %v", err))
	}

	// cwd only applies to new sessions; existing sessions ignore it

	// Execute command
	result, err := executeCommand(ctx, sess, input.Command, input.TimeoutSec)
	if err != nil {
		// If session died, remove it from pool
		pool.remove(input.SessionID)
		return errorResult(fmt.Sprintf("execution failed: %v", err))
	}

	out := BashOutput{
		SessionID: input.SessionID,
		Output:    result.Output,
		ExitCode:  result.ExitCode,
		IsNew:     isNew,
	}

	// Format output
	var sb strings.Builder
	if isNew {
		sb.WriteString(fmt.Sprintf("[New session: %s (%s)]\n", input.SessionID, sess.shellKind))
		if sess.shellKind == kindPowerShell {
			sb.WriteString("[Warning: PowerShell 5.1 does not support && and ||. Use ; (semicolons) to chain commands.]\n")
		}
	}
	sb.WriteString(fmt.Sprintf("$ %s\n", input.Command))
	if result.Output != "" {
		sb.WriteString(result.Output)
		if !strings.HasSuffix(result.Output, "\n") {
			sb.WriteString("\n")
		}
	}
	sb.WriteString(fmt.Sprintf("[exit code: %d]", result.ExitCode))
	// Warn when chain operators were used in PS 5.1 (auto-transformed to prevent hang).
	// Uses quote-aware hasChainOps to avoid false warnings on: echo "a && b"
	if sess.shellKind == kindPowerShell && hasChainOps(input.Command) {
		sb.WriteString("\n[Warning: && / || were auto-transformed for PowerShell 5.1 compatibility. Use ; to chain commands.]")
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: sb.String()}},
		IsError: result.ExitCode != 0,
	}, out, nil
}

func Register(server *mcp.Server) {
	common.SafeAddTool(server, &mcp.Tool{
		Name: "bash",
		Description: `Execute shell commands with persistent session support.
Sessions maintain working directory, environment variables, and shell state across calls.
Use session_id to manage multiple independent shell sessions.
Use disconnect=true to close a session.
Platform: bash/sh on Unix, PowerShell/git-bash/cmd on Windows (auto-detected, best available).`,
	}, Handle)
}

func errorResult(msg string) (*mcp.CallToolResult, BashOutput, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		IsError: true,
	}, BashOutput{}, nil
}
