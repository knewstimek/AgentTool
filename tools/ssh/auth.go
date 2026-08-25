package ssh

import (
	"bytes"
	"crypto/x509"
	"errors"
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

// parseKey parses an OpenSSH/PEM or PPK (PuTTY) private key. Keep the error
// from the parser that recognized the input: replacing it with the PPK
// fallback error hides actionable failures such as a missing passphrase.
func parseKey(keyBytes []byte, passphrase string) (gossh.Signer, error) {
	// A UTF-8 BOM is not part of the PEM armor, but Windows editors commonly add
	// one to otherwise valid text files. Removing it does not alter key data.
	keyBytes = bytes.TrimPrefix(keyBytes, []byte{0xef, 0xbb, 0xbf})

	if len(bytes.TrimSpace(keyBytes)) == 0 {
		return nil, errors.New("private key file is empty")
	}
	if bytes.HasPrefix(keyBytes, []byte{0xff, 0xfe}) || bytes.HasPrefix(keyBytes, []byte{0xfe, 0xff}) {
		return nil, errors.New("private key file is UTF-16 encoded; save it as UTF-8 or ASCII")
	}
	if !bytes.Contains(keyBytes, []byte{'\n'}) && bytes.Contains(keyBytes, []byte(`\n`)) {
		return nil, errors.New(`private key contains escaped \n text instead of line breaks`)
	}
	if !bytes.Contains(keyBytes, []byte{'\n'}) && bytes.Contains(keyBytes, []byte{'\r'}) {
		return nil, errors.New("private key uses bare-CR line endings; save it with LF or CRLF line endings")
	}
	publicKey, _, _, _, publicKeyErr := gossh.ParseAuthorizedKey(keyBytes)
	if (publicKeyErr == nil && publicKey != nil) ||
		bytes.Contains(keyBytes, []byte("-----BEGIN PUBLIC KEY-----")) ||
		bytes.Contains(keyBytes, []byte("-----BEGIN SSH2 PUBLIC KEY-----")) {
		return nil, errors.New("key_file contains an SSH public key; provide the matching private key file (usually the path without .pub)")
	}

	// ssh.ParsePrivateKey supports PEM-armored OpenSSH keys, including Ed25519.
	// If a stale profile passphrase is supplied for a plaintext key, accept the
	// key after verifying that it parses without a passphrase.
	var pemErr error
	if passphrase != "" {
		var signer gossh.Signer
		signer, pemErr = gossh.ParsePrivateKeyWithPassphrase(keyBytes, []byte(passphrase))
		if pemErr == nil {
			return signer, nil
		}
		if signer, err := gossh.ParsePrivateKey(keyBytes); err == nil {
			return signer, nil
		}
	} else {
		var signer gossh.Signer
		signer, pemErr = gossh.ParsePrivateKey(keyBytes)
		if pemErr == nil {
			return signer, nil
		}
	}

	// Fallback: try PPK (PuTTY) format
	ppkKey, ppkErr := putty.New(keyBytes)
	if ppkErr != nil {
		return nil, privateKeyParseError(keyBytes, passphrase, pemErr, ppkErr)
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

func privateKeyParseError(keyBytes []byte, passphrase string, pemErr, ppkErr error) error {
	var missingPassphrase *gossh.PassphraseMissingError
	if errors.As(pemErr, &missingPassphrase) {
		return errors.New("OpenSSH/PEM private key is encrypted; passphrase is required")
	}
	if passphrase != "" && errors.Is(pemErr, x509.IncorrectPasswordError) {
		return errors.New("failed to decrypt OpenSSH/PEM private key: incorrect passphrase")
	}
	if bytes.Contains(keyBytes, []byte("-----BEGIN OPENSSH PRIVATE KEY-----")) {
		return fmt.Errorf("failed to parse OpenSSH private key: %w", pemErr)
	}
	if bytes.Contains(keyBytes, []byte("-----BEGIN ")) && bytes.Contains(keyBytes, []byte("PRIVATE KEY-----")) {
		return fmt.Errorf("failed to parse PEM private key: %w", pemErr)
	}
	return fmt.Errorf("unsupported or malformed private key (OpenSSH/PEM: %v; PPK: %v)", pemErr, ppkErr)
}
