package sftp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"agent-tool/common"
	"agent-tool/tools/ssh"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	gosftp "github.com/pkg/sftp"
)

type SFTPInput struct {
	// SSH connection parameters (same as ssh tool, minus Command/Disconnect/TimeoutSec)
	Host         string `json:"host" jsonschema:"SSH server hostname or IP address (IPv4 or IPv6),required"`
	Port         int    `json:"port,omitempty" jsonschema:"SSH port number. Default: 22"`
	User         string `json:"user" jsonschema:"SSH username,required"`
	Password     string `json:"password,omitempty" jsonschema:"Password for authentication"`
	KeyFile      string `json:"key_file,omitempty" jsonschema:"Path to SSH private key file (e.g. ~/.ssh/id_rsa)"`
	Passphrase   string `json:"passphrase,omitempty" jsonschema:"Passphrase for encrypted private key"`
	UseAgent     interface{} `json:"use_agent,omitempty" jsonschema:"Use SSH agent for authentication: true or false. Default: true if no other auth method specified"`
	HostKeyCheck string `json:"host_key_check,omitempty" jsonschema:"Host key verification: strict, tofu (default), none"`

	// Proxy Jump
	JumpHost       string `json:"jump_host,omitempty" jsonschema:"Jump/bastion host for ProxyJump (hostname or IP)"`
	JumpPort       int    `json:"jump_port,omitempty" jsonschema:"Jump host SSH port. Default: 22"`
	JumpUser       string `json:"jump_user,omitempty" jsonschema:"Jump host username. Default: same as user"`
	JumpPassword   string `json:"jump_password,omitempty" jsonschema:"Jump host password. Default: same as password"`
	JumpKeyFile    string `json:"jump_key_file,omitempty" jsonschema:"Jump host SSH private key file. Default: same as key_file"`
	JumpPassphrase string `json:"jump_passphrase,omitempty" jsonschema:"Jump host key passphrase. Default: same as passphrase"`

	// SFTP operation
	Operation string `json:"operation" jsonschema:"SFTP operation: upload, download, upload_async, download_async, status, cancel, ls, stat, mkdir, rm, chmod, rename,required"`

	// File paths
	LocalPath  string `json:"local_path,omitempty" jsonschema:"Local file path (for upload/download)"`
	RemotePath string `json:"remote_path,omitempty" jsonschema:"Remote file/directory path"`

	// Operation-specific
	Recursive  interface{} `json:"recursive,omitempty" jsonschema:"Recursive operation (mkdir: create parents, rm: remove directory tree): true or false. Default: false"`
	Mode       string `json:"mode,omitempty" jsonschema:"File permission mode in octal (e.g. 0755). Used by chmod"`
	NewPath    string `json:"new_path,omitempty" jsonschema:"New remote path (for rename operation)"`
	Overwrite  interface{} `json:"overwrite,omitempty" jsonschema:"Overwrite existing file on upload/download: true or false. Default: false"`
	TransferID string `json:"transfer_id,omitempty" jsonschema:"Transfer ID for status/cancel operations (returned by upload_async/download_async)"`
}

type SFTPOutput struct {
	Result string `json:"result"`
}

var validOperations = map[string]bool{
	"upload": true, "download": true, "ls": true, "stat": true,
	"mkdir": true, "rm": true, "chmod": true, "rename": true,
	"upload_async": true, "download_async": true, "status": true, "cancel": true,
}

func Handle(ctx context.Context, req *mcp.CallToolRequest, input SFTPInput) (*mcp.CallToolResult, SFTPOutput, error) {
	// SSRF policy: cloud metadata always blocked. Private IPs allowed by default
	// (configurable via set_config allow_ssh_private). Warning shown on every
	// private IP access to help detect prompt injection attacks.
	if strings.TrimSpace(input.Host) != "" {
		// Use "ssh" as toolName so error message references allow_ssh_private (not allow_sftp_private)
		_, _, ssrfErr := common.CheckHostSSRF(ctx, input.Host, common.GetAllowSSHPrivate(), "ssh")
		if ssrfErr != nil {
			return errorResult(ssrfErr.Error())
		}
		// Also check jump host — prevents SSRF via ProxyJump to cloud metadata
		if input.JumpHost != "" {
			_, _, jumpErr := common.CheckHostSSRF(ctx, input.JumpHost, common.GetAllowSSHPrivate(), "ssh")
			if jumpErr != nil {
				return errorResult(fmt.Sprintf("jump_host: %s", jumpErr.Error()))
			}
		}
	}

	// Validate operation
	op := strings.ToLower(strings.TrimSpace(input.Operation))
	if !validOperations[op] {
		return errorResult("invalid operation: must be upload, download, upload_async, download_async, status, cancel, ls, stat, mkdir, rm, chmod, or rename")
	}
	input.Operation = op

	// Async operations don't need SFTP client upfront
	switch op {
	case "upload_async":
		id, err := startAsyncUpload(input)
		if err != nil {
			return errorResult(fmt.Sprintf("upload_async failed: %v", err))
		}
		msg := fmt.Sprintf("Upload started in background.\nTransfer ID: %s\nLocal: %s\nRemote: %s\n\nUse operation=status with transfer_id=%q to check progress.\nUse operation=cancel with transfer_id=%q to cancel.", id, input.LocalPath, input.RemotePath, id, id)
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		}, SFTPOutput{Result: msg}, nil

	case "download_async":
		id, err := startAsyncDownload(input)
		if err != nil {
			return errorResult(fmt.Sprintf("download_async failed: %v", err))
		}
		msg := fmt.Sprintf("Download started in background.\nTransfer ID: %s\nRemote: %s\nLocal: %s\n\nUse operation=status with transfer_id=%q to check progress.\nUse operation=cancel with transfer_id=%q to cancel.", id, input.RemotePath, input.LocalPath, id, id)
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		}, SFTPOutput{Result: msg}, nil

	case "status":
		result, err := opStatus(input)
		if err != nil {
			return errorResult(fmt.Sprintf("status failed: %v", err))
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: result}},
		}, SFTPOutput{Result: result}, nil

	case "cancel":
		result, err := opCancel(input)
		if err != nil {
			return errorResult(fmt.Sprintf("cancel failed: %v", err))
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: result}},
		}, SFTPOutput{Result: result}, nil
	}

	// Synchronous operations need SSH + SFTP client
	sshInput := toSSHInput(input)
	sshClient, isNew, err := ssh.GetClient(sshInput)
	if err != nil {
		return errorResult(fmt.Sprintf("SSH connection failed: %s", ssh.SanitizeError(err, sshInput)))
	}

	// Create SFTP client
	sftpClient, err := gosftp.NewClient(sshClient)
	if err != nil {
		if isConnectionBroken(err) {
			ssh.RemoveClient(input.Host, input.Port, input.User)
		}
		return errorResult(fmt.Sprintf("SFTP subsystem failed: %v", err))
	}
	defer sftpClient.Close()

	// Dispatch operation
	var result string
	switch op {
	case "upload":
		result, err = opUpload(sftpClient, input)
	case "download":
		result, err = opDownload(sftpClient, input)
	case "ls":
		result, err = opLs(sftpClient, input)
	case "stat":
		result, err = opStat(sftpClient, input)
	case "mkdir":
		result, err = opMkdir(sftpClient, input)
	case "rm":
		result, err = opRm(sftpClient, input)
	case "chmod":
		result, err = opChmod(sftpClient, input)
	case "rename":
		result, err = opRename(sftpClient, input)
	}

	if err != nil {
		if isConnectionBroken(err) {
			ssh.RemoveClient(input.Host, input.Port, input.User)
		}
		return errorResult(fmt.Sprintf("%s failed: %v", op, err))
	}

	// Update session lastUsed
	ssh.TouchClient(input.Host, input.Port, input.User)

	// Format output
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("=== SFTP: %s@%s:%d [%s] ===\n", input.User, input.Host, input.Port, op))
	if isNew {
		sb.WriteString("[New session established]\n")
	} else {
		sb.WriteString("[Reusing existing session]\n")
	}
	sb.WriteString("\n")
	sb.WriteString(result)

	output := sb.String()
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: output}},
	}, SFTPOutput{Result: output}, nil
}

func Register(server *mcp.Server) {
	common.SafeAddTool(server, &mcp.Tool{
		Name: "sftp",
		Description: `Transfer files and manage remote filesystems over SSH (SFTP protocol).
Reuses SSH session pool — same authentication and session reuse as the ssh tool.
Operations: upload (local to remote), download (remote to local), ls, stat, mkdir, rm, chmod, rename.
Async operations: upload_async, download_async (returns transfer_id immediately), status (check progress), cancel.
Max file transfer size: 2 GB. Use overwrite=true to replace existing files.
Recursive delete is limited to 10,000 items for safety.`,
	}, Handle)
}

// toSSHInput converts SFTP connection parameters to ssh.SSHInput for pool reuse.
func toSSHInput(input SFTPInput) ssh.SSHInput {
	return ssh.SSHInput{
		Host:           input.Host,
		Port:           input.Port,
		User:           input.User,
		Password:       input.Password,
		KeyFile:        input.KeyFile,
		Passphrase:     input.Passphrase,
		UseAgent:       input.UseAgent,
		HostKeyCheck:   input.HostKeyCheck,
		JumpHost:       input.JumpHost,
		JumpPort:       input.JumpPort,
		JumpUser:       input.JumpUser,
		JumpPassword:   input.JumpPassword,
		JumpKeyFile:    input.JumpKeyFile,
		JumpPassphrase: input.JumpPassphrase,
	}
}

// isConnectionBroken checks if an error indicates a broken SSH connection.
func isConnectionBroken(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.EOF) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "connection reset") ||
		strings.Contains(msg, "broken pipe") ||
		strings.Contains(msg, "connection refused")
}

func errorResult(msg string) (*mcp.CallToolResult, SFTPOutput, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		IsError: true,
	}, SFTPOutput{Result: msg}, nil
}
