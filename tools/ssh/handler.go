package ssh

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"agent-tool/common"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	gossh "golang.org/x/crypto/ssh"
)

const (
	defaultPort       = 22
	defaultTimeoutSec = 30
	maxTimeoutSec     = 300
	dialTimeout       = 10 * time.Second
)

type SSHInput struct {
	// Resolved int values set by validateInput after FlexInt conversion.
	// Not exported in JSON; used internally after validation.
	PortInt       int `json:"-"`
	TimeoutSecInt int `json:"-"`
	JumpPortInt   int `json:"-"`

	Host           string      `json:"host,omitempty" jsonschema:"SSH server hostname or IP address (IPv4 or IPv6). Required for execute/start/disconnect; omit for status/tail/cancel"`
	Port           interface{} `json:"port,omitempty" jsonschema:"SSH port number. Default: 22"`
	User           string      `json:"user,omitempty" jsonschema:"SSH username. Required for execute/start/disconnect; omit for status/tail/cancel"`
	Password       string      `json:"password,omitempty" jsonschema:"Password for authentication"`
	KeyFile        string      `json:"key_file,omitempty" jsonschema:"Path to SSH private key file (e.g. ~/.ssh/id_rsa)"`
	Passphrase     string      `json:"passphrase,omitempty" jsonschema:"Passphrase for encrypted private key"`
	UseAgent       interface{} `json:"use_agent,omitempty" jsonschema:"Use SSH agent for authentication: true or false. Default: true if no other auth method specified"`
	Command        string      `json:"command,omitempty" jsonschema:"Command to execute on the remote server"`
	Operation      string      `json:"operation,omitempty" jsonschema:"Operation: execute (default), start, status, tail, cancel"`
	Background     bool        `json:"background,omitempty" jsonschema:"Start a background SSH job and return job_id immediately. Alias for operation=start"`
	JobID          string      `json:"job_id,omitempty" jsonschema:"Background SSH job ID for status, tail, or cancel"`
	TailLines      int         `json:"tail_lines,omitempty" jsonschema:"Lines returned by operation=tail. Default: 50, Max: 1000"`
	Disconnect     interface{} `json:"disconnect,omitempty" jsonschema:"Close the SSH session for this host (no command needed): true or false. Default: false"`
	HostKeyCheck   string      `json:"host_key_check,omitempty" jsonschema:"Host key verification: strict (requires known_hosts), tofu (trust on first use, default), none (insecure)"`
	TimeoutSec     interface{} `json:"timeout_sec,omitempty" jsonschema:"Command execution timeout in seconds. Default: 30, Max: 300"`
	MaxOutputChars int         `json:"max_output_chars,omitempty" jsonschema:"Maximum combined stdout/stderr bytes retained. Default: 32768, Max: 131072. Head and tail are preserved"`
	OutputMode     string      `json:"output_mode,omitempty" jsonschema:"Retained portion for large output: head_tail (default), head, or tail"`

	// Proxy Jump — connect through a bastion/jump host (like ssh -J).
	// Useful for reaching IPv6-only servers via an IPv4 bastion, or accessing
	// hosts in private networks.
	JumpHost       string      `json:"jump_host,omitempty" jsonschema:"Jump/bastion host for ProxyJump (hostname or IP). When set, connects through this host to reach the target"`
	JumpPort       interface{} `json:"jump_port,omitempty" jsonschema:"Jump host SSH port. Default: 22"`
	JumpUser       string      `json:"jump_user,omitempty" jsonschema:"Jump host username. Default: same as user"`
	JumpPassword   string      `json:"jump_password,omitempty" jsonschema:"Jump host password. Default: same as password"`
	JumpKeyFile    string      `json:"jump_key_file,omitempty" jsonschema:"Jump host SSH private key file. Default: same as key_file"`
	JumpPassphrase string      `json:"jump_passphrase,omitempty" jsonschema:"Jump host key passphrase. Default: same as passphrase"`
}

type SSHOutput struct {
	Result      string `json:"result"`
	ExitCode    int    `json:"exit_code"`
	Truncated   bool   `json:"truncated"`
	StdoutBytes int64  `json:"stdout_bytes,omitempty"`
	StderrBytes int64  `json:"stderr_bytes,omitempty"`
	JobID       string `json:"job_id,omitempty"`
	Status      string `json:"status,omitempty"`
}

func Handle(ctx context.Context, req *mcp.CallToolRequest, input SSHInput) (*mcp.CallToolResult, SSHOutput, error) {
	op := strings.ToLower(strings.TrimSpace(input.Operation))
	if op == "" {
		if input.Background {
			op = "start"
		} else {
			op = "execute"
		}
	}
	if op == "status" || op == "tail" || op == "cancel" {
		return handleJobOperation(op, input)
	}
	if op != "execute" && op != "start" {
		return errorResult("operation must be execute, start, status, tail, or cancel")
	}
	// 1. Validate input
	if err := validateInput(&input); err != nil {
		return errorResult(err.Error())
	}

	// SSRF policy: cloud metadata always blocked. Private IPs allowed by default
	// (configurable via set_config allow_ssh_private). Warning shown on every
	// private IP access to help detect prompt injection attacks.
	resolvedIP, ssrfWarning, ssrfErr := common.CheckHostSSRF(ctx, input.Host, common.GetAllowSSHPrivate(), "ssh")
	if ssrfErr != nil {
		return errorResult(ssrfErr.Error())
	}
	// Also check jump host — prevents SSRF via ProxyJump to cloud metadata
	jumpResolvedIP := ""
	if input.JumpHost != "" {
		var jumpWarning string
		var jumpErr error
		jumpResolvedIP, jumpWarning, jumpErr = common.CheckHostSSRF(ctx, input.JumpHost, common.GetAllowSSHPrivate(), "ssh")
		if jumpErr != nil {
			return errorResult(fmt.Sprintf("jump_host: %s", jumpErr.Error()))
		}
		if jumpWarning != "" && ssrfWarning == "" {
			ssrfWarning = jumpWarning
		}
	}

	key := sessionKey(input)

	// 2. Handle disconnect
	if common.FlexBool(input.Disconnect) {
		removed := pool.remove(key)
		var msg string
		if removed {
			msg = fmt.Sprintf("SSH session closed: %s@%s:%d", input.User, input.Host, input.PortInt)
		} else {
			msg = fmt.Sprintf("No active session for %s@%s:%d", input.User, input.Host, input.PortInt)
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		}, SSHOutput{Result: msg}, nil
	}

	// 3. Command is required for non-disconnect calls
	if input.Command == "" {
		return errorResult("command is required (use disconnect=true to close session)")
	}

	// 4. Get or create SSH connection
	// Use resolved IP for dialing to prevent DNS rebinding attacks —
	// the hostname was already verified by CheckHostSSRF above.
	client, isNew, err := pool.getOrCreate(key, func() (*dialResult, error) {
		return dial(input, resolvedIP, jumpResolvedIP)
	})
	if err != nil {
		return errorResult(fmt.Sprintf("SSH connection failed: %s", sanitizeError(err, input)))
	}
	if op == "start" {
		job, err := startSSHJob(client, input.Command, input.MaxOutputChars, input.OutputMode)
		if err != nil {
			return errorResult(fmt.Sprintf("failed to start SSH job: %s", sanitizeError(err, input)))
		}
		msg := fmt.Sprintf("SSH background job started.\njob_id: %s\nstatus: running\nUse operation=status or operation=tail with this job_id; use operation=cancel to stop it.", job.id)
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: msg}}}, SSHOutput{Result: msg, JobID: job.id, Status: "running"}, nil
	}

	// 5. Execute command with timeout
	timeout := time.Duration(input.TimeoutSecInt) * time.Second
	execCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	result, err := executeCommand(execCtx, client, input.Command, input.MaxOutputChars, input.OutputMode)
	if err != nil {
		// If connection is broken, remove from pool
		if isConnectionError(err) {
			pool.remove(key)
		}
		return errorResult(fmt.Sprintf("command execution failed: %s", sanitizeError(err, input)))
	}

	// 6. Format output
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("=== SSH: %s@%s:%d ===\n", input.User, input.Host, input.PortInt))
	if input.JumpHost != "" {
		sb.WriteString(fmt.Sprintf("[via jump host: %s@%s:%d]\n", input.JumpUser, input.JumpHost, input.JumpPortInt))
	}
	if isNew {
		sb.WriteString("[New session established]\n")
	} else {
		sb.WriteString("[Reusing existing session]\n")
	}
	displayCommand, _ := common.TruncateRunes(input.Command, 500, "… [command abbreviated]")
	sb.WriteString(fmt.Sprintf("$ %s\n\n", displayCommand))

	if result.Stdout != "" {
		sb.WriteString(result.Stdout)
		if !strings.HasSuffix(result.Stdout, "\n") {
			sb.WriteString("\n")
		}
	}
	if result.Stderr != "" {
		sb.WriteString("\n[STDERR]\n")
		sb.WriteString(result.Stderr)
		if !strings.HasSuffix(result.Stderr, "\n") {
			sb.WriteString("\n")
		}
	}
	if result.ExitCode != 0 {
		sb.WriteString(fmt.Sprintf("\n[Exit code: %d]", result.ExitCode))
	}
	truncated := result.StdoutTruncated || result.StderrTruncated
	if truncated {
		sb.WriteString(fmt.Sprintf("\n[output truncated: stdout_bytes=%d; stderr_bytes=%d; retained_bytes=%d; output_mode=%s]", result.StdoutBytes, result.StderrBytes, input.MaxOutputChars, input.OutputMode))
	}

	output := sb.String()
	if ssrfWarning != "" {
		output = ssrfWarning + "\n\n" + output
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: output}},
		IsError: result.ExitCode != 0,
	}, SSHOutput{Result: output, ExitCode: result.ExitCode, Truncated: truncated, StdoutBytes: result.StdoutBytes, StderrBytes: result.StderrBytes}, nil
}

func handleJobOperation(op string, input SSHInput) (*mcp.CallToolResult, SSHOutput, error) {
	if strings.TrimSpace(input.JobID) == "" {
		return errorResult("job_id is required for status, tail, or cancel")
	}
	job, ok := getSSHJob(strings.TrimSpace(input.JobID))
	if !ok {
		return errorResult("SSH job not found or expired")
	}
	if op == "cancel" {
		if err := job.cancel(); err != nil {
			return errorResult(err.Error())
		}
	}
	snap := job.snapshot()
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("job_id: %s\nstatus: %s\n", snap.ID, snap.Status))
	if !snap.FinishedAt.IsZero() {
		sb.WriteString(fmt.Sprintf("exit_code: %d\n", snap.ExitCode))
	}
	sb.WriteString(fmt.Sprintf("stdout_bytes: %d\nstderr_bytes: %d\n", snap.StdoutBytes, snap.StderrBytes))
	if snap.StdoutTruncated || snap.StderrTruncated {
		sb.WriteString("truncated: true (head and tail retained)\n")
	}
	if snap.Error != "" {
		sb.WriteString("error: " + snap.Error + "\n")
	}
	if op == "tail" {
		lines := input.TailLines
		if lines == 0 {
			lines = 50
		}
		if lines < 1 || lines > 1000 {
			return errorResult("tail_lines must be between 1 and 1000")
		}
		if snap.Stdout != "" {
			sb.WriteString("\n--- stdout tail ---\n" + lastLines(snap.Stdout, lines) + "\n")
		}
		if snap.Stderr != "" {
			sb.WriteString("\n--- stderr tail ---\n" + lastLines(snap.Stderr, lines) + "\n")
		}
	}
	result := sb.String()
	return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: result}},
			IsError: snap.Status == "failed",
		}, SSHOutput{
			Result: result, JobID: snap.ID, Status: snap.Status, ExitCode: snap.ExitCode,
			Truncated:   snap.StdoutTruncated || snap.StderrTruncated,
			StdoutBytes: snap.StdoutBytes, StderrBytes: snap.StderrBytes,
		}, nil
}

func Register(server *mcp.Server) {
	common.SafeAddTool(server, &mcp.Tool{
		Name: "ssh",
		Description: `Execute commands on a remote server via SSH.
Supports password and key-based authentication. SSH agent is used as fallback on Unix.
Sessions are pooled only when host, user, authentication identity, host-key policy, and jump route all match.
Idle sessions expire after 30 minutes. Foreground output defaults to 32768 bytes and reports truncation explicitly; output_mode selects head_tail, head, or tail retention.
For long commands, use background=true (or operation=start), then poll with operation=status/tail and job_id; operation=cancel stops the job.
Supports IPv6 addresses and ProxyJump (jump_host) for reaching servers through bastion hosts.`,
	}, Handle)
}

// dial establishes a new SSH connection, optionally through a jump host.
// resolvedIP/jumpResolvedIP are pre-resolved addresses from SSRF checks —
// using them prevents DNS rebinding between check and connect.
// Returns a dialResult containing the client and any agent connection that
// must be closed when the session is removed from the pool.
func dial(input SSHInput, resolvedIP, jumpResolvedIP string) (*dialResult, error) {
	auth, err := buildAuthMethods(input)
	if err != nil {
		return nil, err
	}

	hostKeyCallback, err := buildHostKeyCallback(input.HostKeyCheck)
	if err != nil {
		if auth.agentConn != nil {
			auth.agentConn.Close()
		}
		return nil, err
	}

	config := &gossh.ClientConfig{
		User:            input.User,
		Auth:            auth.methods,
		HostKeyCallback: hostKeyCallback,
		Timeout:         dialTimeout,
	}

	// Use resolved IP for actual connection to prevent DNS rebinding.
	// Fall back to hostname if no resolved IP (e.g., pool re-dial from GetClient).
	dialHost := input.Host
	if resolvedIP != "" {
		dialHost = resolvedIP
	}
	targetAddr := formatAddr(dialHost, input.PortInt)

	// Direct connection (no jump host)
	if input.JumpHost == "" {
		client, err := gossh.Dial("tcp", targetAddr, config)
		if err != nil {
			if auth.agentConn != nil {
				auth.agentConn.Close()
			}
			return nil, err
		}
		return &dialResult{client: client, agentConn: auth.agentConn}, nil
	}

	// ProxyJump: connect through jump host
	jumpClient, jumpAgentConn, err := dialJumpHost(input, jumpResolvedIP)
	if err != nil {
		if auth.agentConn != nil {
			auth.agentConn.Close()
		}
		return nil, fmt.Errorf("jump host connection failed: %w", err)
	}

	// Open a TCP tunnel through the jump host to the target
	tunnelConn, err := jumpClient.Dial("tcp", targetAddr)
	if err != nil {
		jumpClient.Close()
		if jumpAgentConn != nil {
			jumpAgentConn.Close()
		}
		if auth.agentConn != nil {
			auth.agentConn.Close()
		}
		return nil, fmt.Errorf("failed to tunnel through jump host to %s: %w", targetAddr, err)
	}

	// Establish SSH over the tunnel
	ncc, chans, reqs, err := gossh.NewClientConn(tunnelConn, targetAddr, config)
	if err != nil {
		tunnelConn.Close()
		jumpClient.Close()
		if jumpAgentConn != nil {
			jumpAgentConn.Close()
		}
		if auth.agentConn != nil {
			auth.agentConn.Close()
		}
		return nil, fmt.Errorf("SSH handshake through tunnel failed: %w", err)
	}

	client := gossh.NewClient(ncc, chans, reqs)

	// Wrap the jump client so it is closed when the session is removed.
	// We use a jumpCloser that closes both the final client's underlying
	// jump connection and any agent sockets.
	return &dialResult{
		client:    client,
		agentConn: auth.agentConn,
		jumpCleanup: func() {
			jumpClient.Close()
			if jumpAgentConn != nil {
				jumpAgentConn.Close()
			}
		},
	}, nil
}

// dialJumpHost establishes an SSH connection to the jump/bastion host.
// jumpResolvedIP is the pre-resolved address from SSRF check.
func dialJumpHost(input SSHInput, jumpResolvedIP string) (*gossh.Client, net.Conn, error) {
	jumpInput := SSHInput{
		Host:       input.JumpHost,
		PortInt:    input.JumpPortInt,
		User:       input.JumpUser,
		Password:   input.JumpPassword,
		KeyFile:    input.JumpKeyFile,
		Passphrase: input.JumpPassphrase,
		UseAgent:   input.UseAgent,
	}

	jumpAuth, err := buildAuthMethods(jumpInput)
	if err != nil {
		return nil, nil, err
	}

	jumpHostKeyCb, err := buildHostKeyCallback(input.HostKeyCheck)
	if err != nil {
		if jumpAuth.agentConn != nil {
			jumpAuth.agentConn.Close()
		}
		return nil, nil, err
	}

	jumpConfig := &gossh.ClientConfig{
		User:            input.JumpUser,
		Auth:            jumpAuth.methods,
		HostKeyCallback: jumpHostKeyCb,
		Timeout:         dialTimeout,
	}

	// Use resolved IP for jump host to prevent DNS rebinding
	jumpDialHost := input.JumpHost
	if jumpResolvedIP != "" {
		jumpDialHost = jumpResolvedIP
	}
	jumpAddr := formatAddr(jumpDialHost, input.JumpPortInt)
	client, err := gossh.Dial("tcp", jumpAddr, jumpConfig)
	if err != nil {
		if jumpAuth.agentConn != nil {
			jumpAuth.agentConn.Close()
		}
		return nil, nil, err
	}

	return client, jumpAuth.agentConn, nil
}

// formatAddr formats a host:port address string, handling IPv6 bracket notation.
func formatAddr(host string, port int) string {
	// IPv6 addresses need brackets: [::1]:22
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		return fmt.Sprintf("[%s]:%d", host, port)
	}
	return fmt.Sprintf("%s:%d", host, port)
}

// validateInput checks and normalizes input fields.
func validateInput(input *SSHInput) error {
	// Host
	input.Host = strings.TrimSpace(input.Host)
	if input.Host == "" {
		return fmt.Errorf("host is required")
	}
	if containsUnsafe(input.Host) {
		return fmt.Errorf("invalid characters in host")
	}

	// User
	input.User = strings.TrimSpace(input.User)
	if input.User == "" {
		return fmt.Errorf("user is required")
	}
	if containsUnsafe(input.User) {
		return fmt.Errorf("invalid characters in user")
	}

	// Port
	port, ok := common.FlexInt(input.Port)
	if !ok {
		return fmt.Errorf("port must be an integer")
	}
	if port == 0 {
		port = defaultPort
	}
	if port < 1 || port > 65535 {
		return fmt.Errorf("invalid port: must be 1-65535")
	}
	input.PortInt = port

	// Timeout
	timeoutSec, ok := common.FlexInt(input.TimeoutSec)
	if !ok {
		return fmt.Errorf("timeout_sec must be an integer")
	}
	if timeoutSec <= 0 {
		timeoutSec = defaultTimeoutSec
	}
	if timeoutSec > maxTimeoutSec {
		return fmt.Errorf("timeout_sec exceeds maximum (%d)", maxTimeoutSec)
	}
	input.TimeoutSecInt = timeoutSec
	if input.MaxOutputChars == 0 {
		input.MaxOutputChars = common.DefaultOutputChars
	}
	if input.MaxOutputChars < 1024 || input.MaxOutputChars > common.HardOutputChars {
		return fmt.Errorf("max_output_chars must be between 1024 and %d", common.HardOutputChars)
	}
	input.OutputMode = strings.ToLower(strings.TrimSpace(input.OutputMode))
	if input.OutputMode == "" {
		input.OutputMode = "head_tail"
	}
	if input.OutputMode != "head_tail" && input.OutputMode != "head" && input.OutputMode != "tail" {
		return fmt.Errorf("output_mode must be head_tail, head, or tail")
	}

	// Host key check
	input.HostKeyCheck = strings.ToLower(strings.TrimSpace(input.HostKeyCheck))
	if input.HostKeyCheck == "" {
		input.HostKeyCheck = "tofu"
	}
	if input.HostKeyCheck != "strict" && input.HostKeyCheck != "tofu" && input.HostKeyCheck != "none" {
		return fmt.Errorf("invalid host_key_check: must be strict, tofu, or none")
	}

	// Expand ~ in key_file
	if input.KeyFile != "" {
		input.KeyFile = strings.TrimSpace(input.KeyFile)
		input.KeyFile = expandTilde(input.KeyFile)
	}

	// Jump host validation
	if input.JumpHost != "" {
		input.JumpHost = strings.TrimSpace(input.JumpHost)
		if containsUnsafe(input.JumpHost) {
			return fmt.Errorf("invalid characters in jump_host")
		}
		jumpPort, ok := common.FlexInt(input.JumpPort)
		if !ok {
			return fmt.Errorf("jump_port must be an integer")
		}
		if jumpPort == 0 {
			jumpPort = defaultPort
		}
		if jumpPort < 1 || jumpPort > 65535 {
			return fmt.Errorf("invalid jump_port: must be 1-65535")
		}
		input.JumpPortInt = jumpPort
		if input.JumpUser == "" {
			input.JumpUser = input.User
		}
		if containsUnsafe(input.JumpUser) {
			return fmt.Errorf("invalid characters in jump_user")
		}
		// Default jump auth to main auth
		if input.JumpPassword == "" {
			input.JumpPassword = input.Password
		}
		if input.JumpKeyFile == "" {
			input.JumpKeyFile = input.KeyFile
		} else {
			input.JumpKeyFile = strings.TrimSpace(input.JumpKeyFile)
			input.JumpKeyFile = expandTilde(input.JumpKeyFile)
		}
		if input.JumpPassphrase == "" {
			input.JumpPassphrase = input.Passphrase
		}
	}

	return nil
}

// expandTilde expands ~/path to the user's home directory.
func expandTilde(path string) string {
	if path == "~" {
		// Bare "~" — return home directory directly.
		// Must be handled separately: path[2:] would panic on a 1-char string.
		home, err := os.UserHomeDir()
		if err == nil {
			return home
		}
	} else if strings.HasPrefix(path, "~/") || strings.HasPrefix(path, `~\`) {
		home, err := os.UserHomeDir()
		if err == nil {
			return filepath.Join(home, path[2:])
		}
	}
	return path
}

// containsUnsafe checks for characters that shouldn't appear in host/user.
func containsUnsafe(s string) bool {
	return strings.ContainsAny(s, "\x00\n\r\t;|&`$\\\"'")
}

// SanitizeError removes sensitive data (passwords, passphrases) from error messages.
// Exported for use by other packages (e.g. sftp).
func SanitizeError(err error, input SSHInput) string {
	return sanitizeError(err, input)
}

// sanitizeError removes sensitive data from error messages.
func sanitizeError(err error, input SSHInput) string {
	msg := err.Error()
	for _, secret := range []string{
		input.Password, input.Passphrase,
		input.JumpPassword, input.JumpPassphrase,
	} {
		if secret != "" {
			msg = strings.ReplaceAll(msg, secret, "***")
		}
	}
	return msg
}

// isConnectionError checks if the error indicates a broken connection.
func isConnectionError(err error) bool {
	if err == nil {
		return false
	}
	if _, ok := err.(*net.OpError); ok {
		return true
	}
	// Use errors.Is for precise EOF detection instead of broad string matching
	// that could false-positive on unrelated error messages containing "EOF".
	if errors.Is(err, io.EOF) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "connection reset") ||
		strings.Contains(msg, "broken pipe") ||
		strings.Contains(msg, "connection refused")
}

func errorResult(msg string) (*mcp.CallToolResult, SSHOutput, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		IsError: true,
	}, SSHOutput{Result: msg}, nil
}
