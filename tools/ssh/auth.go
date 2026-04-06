package ssh

import (
	"fmt"
	"net"
	"os"

	"agent-tool/common"

	"github.com/kayrus/putty"
	gossh "golang.org/x/crypto/ssh"
)

// authResult holds authentication methods and any agent connection that must
// be closed when the SSH session ends.
type authResult struct {
	methods   []gossh.AuthMethod
	agentConn net.Conn // nil if SSH agent not used
}

// buildAuthMethods builds SSH authentication methods from input parameters.
// Priority: key_file → password → SSH agent (fallback).
// The caller must close authResult.agentConn (if non-nil) when the session ends.
func buildAuthMethods(input SSHInput) (*authResult, error) {
	result := &authResult{}

	// 1. Key file
	if input.KeyFile != "" {
		keyBytes, err := os.ReadFile(input.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read key file %s: %w", input.KeyFile, err)
		}
		signer, err := parseKey(keyBytes, input.Passphrase)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}
		result.methods = append(result.methods, gossh.PublicKeys(signer))
	}

	// 2. Password
	if input.Password != "" {
		result.methods = append(result.methods, gossh.Password(input.Password))
	}

	// 3. SSH Agent (explicit request or fallback when no other auth)
	if common.FlexBool(input.UseAgent) || len(result.methods) == 0 {
		agentAuth, agentConn, err := getAgentAuth()
		if err == nil && agentAuth != nil {
			result.methods = append(result.methods, agentAuth)
			result.agentConn = agentConn
		}
	}

	if len(result.methods) == 0 {
		return nil, fmt.Errorf("no authentication method available: provide key_file, password, or ensure SSH agent is running")
	}

	return result, nil
}

// parseKey parses a private key, trying PEM format first, then PPK (PuTTY) format.
// PPK fallback allows users to use PuTTY-generated keys directly without conversion.
func parseKey(keyBytes []byte, passphrase string) (gossh.Signer, error) {
	// Try PEM format first (most common: OpenSSH, ssh-keygen output)
	if passphrase != "" {
		signer, err := gossh.ParsePrivateKeyWithPassphrase(keyBytes, []byte(passphrase))
		if err == nil {
			return signer, nil
		}
	} else {
		signer, err := gossh.ParsePrivateKey(keyBytes)
		if err == nil {
			return signer, nil
		}
	}

	// Fallback: try PPK (PuTTY) format
	ppkKey, err := putty.New(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("key is neither valid PEM nor PPK format: %w", err)
	}

	// Check if the key is encrypted but no passphrase was provided
	if ppkKey.Encryption != "none" && passphrase == "" {
		return nil, fmt.Errorf("PPK key is encrypted but no passphrase provided")
	}

	// ParseRawPrivateKey handles decryption internally via the password parameter.
	// Supports RSA, DSA, ECDSA, and Ed25519.
	var password []byte
	if passphrase != "" {
		password = []byte(passphrase)
	}
	cryptoKey, err := ppkKey.ParseRawPrivateKey(password)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PPK private key: %w", err)
	}

	signer, err := gossh.NewSignerFromKey(cryptoKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create SSH signer from PPK key: %w", err)
	}
	return signer, nil
}
