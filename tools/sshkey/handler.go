package sshkey

import (
	"context"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"agent-tool/common"
	sshtool "agent-tool/tools/ssh"

	"github.com/kayrus/putty"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	gossh "golang.org/x/crypto/ssh"
)

const maxPrivateKeyBytes = 1024 * 1024

const (
	maxPPKArgonMemoryKiB = 256 * 1024
	maxPPKArgonPasses    = 64
	maxPPKArgonThreads   = 16
	maxPPKArgonWorkKiB   = 2 * 1024 * 1024
)

type Input struct {
	Operation        string      `json:"operation,omitempty" jsonschema:"Operation: convert (default)"`
	InputPath        string      `json:"input_path,omitempty" jsonschema:"Private key file to convert. Relative paths use workspace/MCP root"`
	OutputPath       string      `json:"output_path,omitempty" jsonschema:"Destination private key file. Relative paths use workspace/MCP root"`
	OutputFormat     string      `json:"output_format,omitempty" jsonschema:"Output format: ppk, pem, openssh, pkcs8"`
	InputPassphrase  string      `json:"input_passphrase,omitempty" jsonschema:"Passphrase for an encrypted input key"`
	OutputPassphrase string      `json:"output_passphrase,omitempty" jsonschema:"Passphrase for ppk or openssh output. Empty writes an unencrypted key"`
	Comment          string      `json:"comment,omitempty" jsonschema:"Key comment. PPK comments cannot contain line breaks"`
	Overwrite        interface{} `json:"overwrite,omitempty" jsonschema:"Overwrite an existing output file: true or false. Default: false"`
}

type Output struct {
	Result       string `json:"result"`
	InputFormat  string `json:"input_format,omitempty"`
	OutputFormat string `json:"output_format,omitempty"`
	Algorithm    string `json:"algorithm,omitempty"`
	Fingerprint  string `json:"fingerprint,omitempty"`
	OutputPath   string `json:"output_path,omitempty"`
	Encrypted    bool   `json:"encrypted"`
}

func Handle(ctx context.Context, req *mcp.CallToolRequest, input Input) (*mcp.CallToolResult, Output, error) {
	operation := strings.ToLower(strings.TrimSpace(input.Operation))
	if operation == "" {
		operation = "convert"
	}
	if operation != "convert" {
		return errorResult(fmt.Sprintf("unsupported operation %q (supported: convert)", operation))
	}
	if strings.TrimSpace(input.InputPath) == "" {
		return errorResult("input_path is required")
	}
	if strings.TrimSpace(input.OutputPath) == "" {
		return errorResult("output_path is required")
	}
	format := strings.ToLower(strings.TrimSpace(input.OutputFormat))
	if format == "" {
		return errorResult("output_format is required (supported: ppk, pem, openssh, pkcs8)")
	}

	inputPath, err := common.ResolveRequestPath(ctx, req, input.InputPath)
	if err != nil {
		return errorResult(fmt.Sprintf("cannot resolve input_path: %v", err))
	}
	outputPath, err := common.ResolveRequestPath(ctx, req, input.OutputPath)
	if err != nil {
		return errorResult(fmt.Sprintf("cannot resolve output_path: %v", err))
	}
	if err := validateInputFile(inputPath); err != nil {
		return errorResult(err.Error())
	}
	if err := validateOutputFile(outputPath, common.FlexBool(input.Overwrite)); err != nil {
		return errorResult(err.Error())
	}

	raw, err := os.ReadFile(inputPath)
	if err != nil {
		return errorResult(fmt.Sprintf("failed to read input key: %v", err))
	}
	inputFormat, sourceComment := identifyInput(raw)
	if err := validatePPKCost(raw); err != nil {
		return errorResult(err.Error())
	}
	cryptoKey, err := sshtool.ParseRawPrivateKey(raw, input.InputPassphrase)
	if err != nil {
		return errorResult(fmt.Sprintf("failed to parse input key: %v", err))
	}
	comment := input.Comment
	if comment == "" {
		comment = sourceComment
	}
	encoded, err := marshalPrivateKey(cryptoKey, format, input.OutputPassphrase, comment)
	if err != nil {
		return errorResult(err.Error())
	}
	if err := writePrivateKeyFile(outputPath, encoded, common.FlexBool(input.Overwrite)); err != nil {
		return errorResult(fmt.Sprintf("failed to write output key: %v", err))
	}

	signer, err := gossh.NewSignerFromKey(cryptoKey)
	if err != nil {
		return errorResult(fmt.Sprintf("failed to inspect converted key: %v", err))
	}
	algorithm := signer.PublicKey().Type()
	fingerprint := gossh.FingerprintSHA256(signer.PublicKey())
	encrypted := input.OutputPassphrase != ""
	msg := fmt.Sprintf("Converted SSH private key: %s -> %s\nalgorithm: %s\nfingerprint: %s\noutput_path: %s\nencrypted: %t\npermissions: 0600",
		inputFormat, format, algorithm, fingerprint, outputPath, encrypted)
	out := Output{Result: msg, InputFormat: inputFormat, OutputFormat: format, Algorithm: algorithm, Fingerprint: fingerprint, OutputPath: outputPath, Encrypted: encrypted}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: msg}}}, out, nil
}

func validatePPKCost(raw []byte) error {
	k, err := putty.New(raw)
	if err != nil || k.Version < 3 || k.Encryption == "none" {
		return nil
	}
	if k.Argon2Memory > maxPPKArgonMemoryKiB || k.Argon2Passes > maxPPKArgonPasses || k.Argon2Parallelism > maxPPKArgonThreads ||
		uint64(k.Argon2Memory)*uint64(k.Argon2Passes) > maxPPKArgonWorkKiB {
		return fmt.Errorf("PPK Argon2 parameters exceed safe conversion limits (memory_kib<=%d, passes<=%d, parallelism<=%d, memory_kib*passes<=%d)",
			maxPPKArgonMemoryKiB, maxPPKArgonPasses, maxPPKArgonThreads, maxPPKArgonWorkKiB)
	}
	return nil
}

func validateInputFile(path string) error {
	if !common.GetAllowSymlinks() {
		if fi, err := os.Lstat(path); err == nil && fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("input key is a symlink; enable allow_symlinks to permit it")
		}
	}
	fi, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("input key not found: %s", path)
		}
		return fmt.Errorf("cannot access input key: %v", err)
	}
	if fi.IsDir() {
		return fmt.Errorf("input_path is a directory: %s", path)
	}
	if fi.Size() > maxPrivateKeyBytes {
		return fmt.Errorf("input key is too large (%d bytes, max %d)", fi.Size(), maxPrivateKeyBytes)
	}
	return nil
}

func validateOutputFile(path string, overwrite bool) error {
	if fi, err := os.Lstat(path); err == nil {
		if fi.IsDir() {
			return fmt.Errorf("output_path is a directory: %s", path)
		}
		if fi.Mode()&os.ModeSymlink != 0 && !common.GetAllowSymlinks() {
			return fmt.Errorf("output key is a symlink; enable allow_symlinks to permit it")
		}
		if !overwrite {
			return fmt.Errorf("output file already exists: %s (use overwrite=true to replace)", path)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("cannot access output_path: %v", err)
	}
	return nil
}

func identifyInput(raw []byte) (format, comment string) {
	if k, err := putty.New(raw); err == nil {
		return fmt.Sprintf("ppk-v%d", k.Version), k.Comment
	}
	if block, _ := pem.Decode(raw); block != nil {
		switch block.Type {
		case "OPENSSH PRIVATE KEY":
			return "openssh", ""
		case "PRIVATE KEY", "ENCRYPTED PRIVATE KEY":
			return "pkcs8", ""
		default:
			if strings.Contains(block.Type, "PRIVATE KEY") {
				return "pem", ""
			}
		}
	}
	return "unknown", ""
}

func writePrivateKeyFile(path string, data []byte, overwrite bool) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	if !overwrite {
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		ok := false
		defer func() {
			_ = f.Close()
			if !ok {
				_ = os.Remove(path)
			}
		}()
		if _, err := f.Write(data); err != nil {
			return err
		}
		if err := f.Sync(); err != nil {
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
		ok = true
		return os.Chmod(path, 0o600)
	}

	tmp, err := os.CreateTemp(dir, ".agent-tool-ssh-key-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if runtime.GOOS != "windows" {
		return os.Rename(tmpPath, path)
	}
	return replaceFileWindowsSafe(tmpPath, path)
}

func replaceFileWindowsSafe(source, destination string) error {
	if _, err := os.Lstat(destination); os.IsNotExist(err) {
		if err := os.Rename(source, destination); err != nil {
			return err
		}
		return os.Chmod(destination, 0o600)
	}
	backup, err := os.CreateTemp(filepath.Dir(destination), ".agent-tool-ssh-key-backup-*.tmp")
	if err != nil {
		return err
	}
	backupPath := backup.Name()
	if err := backup.Close(); err != nil {
		_ = os.Remove(backupPath)
		return err
	}
	if err := os.Remove(backupPath); err != nil {
		return err
	}
	if err := os.Rename(destination, backupPath); err != nil {
		return err
	}
	if err := os.Rename(source, destination); err != nil {
		if rollbackErr := os.Rename(backupPath, destination); rollbackErr != nil {
			return fmt.Errorf("replace failed: %v; original remains at %s because rollback failed: %v", err, backupPath, rollbackErr)
		}
		return err
	}
	if err := os.Remove(backupPath); err != nil {
		return fmt.Errorf("output was replaced but backup cleanup failed for %s: %w", backupPath, err)
	}
	return os.Chmod(destination, 0o600)
}

func Register(server *mcp.Server) {
	common.SafeAddTool(server, &mcp.Tool{
		Name: "ssh_key",
		Description: `Converts local SSH private-key files without exposing key material in tool output.
Supported output formats: PuTTY PPK v3, traditional PEM, modern OpenSSH, and PKCS#8 PEM.
Input format is auto-detected and may be PEM, PKCS#8, OpenSSH, or PPK. RSA, ECDSA, Ed25519, and DSA keys are supported where the target format permits them.
PPK and OpenSSH outputs support output_passphrase. Legacy encrypted PEM is intentionally not generated.
Writes with permission 0600, refuses overwrite by default, and uses safe replacement when overwrite=true.`,
	}, Handle)
}

func errorResult(msg string) (*mcp.CallToolResult, Output, error) {
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: msg}}, IsError: true}, Output{Result: msg}, nil
}
