package ssh

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"strings"
	"testing"

	gossh "golang.org/x/crypto/ssh"
)

func makeOpenSSHEd25519Key(t *testing.T, passphrase string) ([]byte, ed25519.PrivateKey) {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	var block *pem.Block
	if passphrase == "" {
		block, err = gossh.MarshalPrivateKey(privateKey, "agent-tool-test")
	} else {
		block, err = gossh.MarshalPrivateKeyWithPassphrase(privateKey, "agent-tool-test", []byte(passphrase))
	}
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(block), privateKey
}

func requireEd25519Signer(t *testing.T, signer gossh.Signer) {
	t.Helper()
	if signer == nil || signer.PublicKey().Type() != gossh.KeyAlgoED25519 {
		t.Fatalf("signer type = %v, want %s", signer, gossh.KeyAlgoED25519)
	}
}

func TestParseKeyOpenSSHEd25519(t *testing.T) {
	plain, _ := makeOpenSSHEd25519Key(t, "")
	encrypted, _ := makeOpenSSHEd25519Key(t, "correct-passphrase")

	tests := []struct {
		name       string
		key        []byte
		passphrase string
	}{
		{name: "plaintext", key: plain},
		{name: "plaintext CRLF", key: bytes.ReplaceAll(plain, []byte("\n"), []byte("\r\n"))},
		{name: "plaintext UTF-8 BOM", key: append([]byte{0xef, 0xbb, 0xbf}, plain...)},
		{name: "plaintext with stale passphrase", key: plain, passphrase: "unused-profile-value"},
		{name: "encrypted", key: encrypted, passphrase: "correct-passphrase"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signer, err := parseKey(tt.key, tt.passphrase)
			if err != nil {
				t.Fatal(err)
			}
			requireEd25519Signer(t, signer)
		})
	}
}

func TestParseKeyReportsActionableOpenSSHErrors(t *testing.T) {
	encrypted, privateKey := makeOpenSSHEd25519Key(t, "correct-passphrase")
	publicKey, err := gossh.NewPublicKey(privateKey.Public())
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name       string
		key        []byte
		passphrase string
		want       string
		notWant    string
	}{
		{name: "empty file", key: nil, want: "file is empty", notWant: "PPK"},
		{name: "missing passphrase", key: encrypted, want: "passphrase is required", notWant: "PPK"},
		{name: "incorrect passphrase", key: encrypted, passphrase: "wrong-passphrase", want: "incorrect passphrase", notWant: "PPK"},
		{name: "public key", key: gossh.MarshalAuthorizedKey(publicKey), want: "SSH public key", notWant: "PPK"},
		{name: "PEM public key", key: []byte("-----BEGIN PUBLIC KEY-----\ninvalid\n-----END PUBLIC KEY-----\n"), want: "SSH public key", notWant: "PPK"},
		{name: "escaped newlines", key: bytes.ReplaceAll(encrypted, []byte("\n"), []byte(`\n`)), want: `escaped \n text`, notWant: "PPK"},
		{name: "bare CR", key: bytes.ReplaceAll(encrypted, []byte("\n"), []byte("\r")), want: "bare-CR", notWant: "PPK"},
		{name: "UTF-16", key: append([]byte{0xff, 0xfe}, encrypted...), want: "UTF-16", notWant: "PPK"},
		{name: "malformed OpenSSH", key: []byte("-----BEGIN OPENSSH PRIVATE KEY-----\ninvalid\n-----END OPENSSH PRIVATE KEY-----\n"), want: "failed to parse OpenSSH private key", notWant: "neither valid PEM nor PPK"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseKey(tt.key, tt.passphrase)
			if err == nil {
				t.Fatal("parseKey unexpectedly succeeded")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %q, want substring %q", err, tt.want)
			}
			if tt.notWant != "" && strings.Contains(err.Error(), tt.notWant) {
				t.Fatalf("error = %q, unwanted substring %q", err, tt.notWant)
			}
		})
	}
}
