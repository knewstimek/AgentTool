package sshkey

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"agent-tool/common"
	sshtool "agent-tool/tools/ssh"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	gossh "golang.org/x/crypto/ssh"
)

func TestHandleEncryptedRoundTrip(t *testing.T) {
	dir := t.TempDir()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := gossh.MarshalPrivateKeyWithPassphrase(key, "source", []byte("input-secret"))
	if err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(dir, "source.key")
	ppkPath := filepath.Join(dir, "converted.ppk")
	pemPath := filepath.Join(dir, "converted.pem")
	if err := os.WriteFile(source, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}

	result, out, err := Handle(t.Context(), nil, Input{
		InputPath: source, OutputPath: ppkPath, OutputFormat: "ppk",
		InputPassphrase: "input-secret", OutputPassphrase: "output-secret",
	})
	if err != nil || result.IsError {
		t.Fatalf("OpenSSH -> PPK failed: result=%v out=%+v err=%v", result, out, err)
	}
	if !out.Encrypted || out.InputFormat != "openssh" || out.OutputFormat != "ppk" {
		t.Fatalf("unexpected output: %+v", out)
	}
	if strings.Contains(out.Result, "input-secret") || strings.Contains(out.Result, "output-secret") {
		t.Fatal("result exposed a passphrase")
	}
	ppkBytes, err := os.ReadFile(ppkPath)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := sshtool.ParseRawPrivateKey(ppkBytes, "output-secret")
	if err != nil {
		t.Fatalf("cannot parse output PPK: %v", err)
	}
	assertSamePublicKey(t, key, parsed)

	result, out, err = Handle(t.Context(), nil, Input{
		InputPath: ppkPath, OutputPath: pemPath, OutputFormat: "pem",
		InputPassphrase: "output-secret",
	})
	if err != nil || result.IsError {
		t.Fatalf("PPK -> PEM failed: result=%v out=%+v err=%v", result, out, err)
	}
	if out.InputFormat != "ppk-v3" || out.Encrypted {
		t.Fatalf("unexpected output: %+v", out)
	}
	pemBytes, err := os.ReadFile(pemPath)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err = gossh.ParseRawPrivateKey(pemBytes)
	if err != nil {
		t.Fatalf("cannot parse output PEM: %v", err)
	}
	assertSamePublicKey(t, key, parsed)
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(pemPath)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("output mode = %v", fi.Mode().Perm())
		}
	}
}

func TestHandleOverwriteReplacesDestination(t *testing.T) {
	dir := t.TempDir()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := gossh.MarshalPrivateKey(key, "source")
	if err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(dir, "source.key")
	destination := filepath.Join(dir, "existing.ppk")
	if err := os.WriteFile(source, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, []byte("old data"), 0o600); err != nil {
		t.Fatal(err)
	}
	result, _, err := Handle(t.Context(), nil, Input{InputPath: source, OutputPath: destination, OutputFormat: "ppk", Overwrite: true})
	if err != nil || result.IsError {
		t.Fatalf("overwrite failed: result=%v err=%v", result, err)
	}
	converted, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := sshtool.ParseRawPrivateKey(converted, "")
	if err != nil {
		t.Fatal(err)
	}
	assertSamePublicKey(t, key, parsed)
}

func TestHandleRefusesOverwriteAndPreservesDestination(t *testing.T) {
	dir := t.TempDir()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := gossh.MarshalPrivateKey(key, "source")
	if err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(dir, "source.key")
	destination := filepath.Join(dir, "existing.ppk")
	if err := os.WriteFile(source, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, []byte("keep me"), 0o600); err != nil {
		t.Fatal(err)
	}

	result, _, err := Handle(t.Context(), nil, Input{InputPath: source, OutputPath: destination, OutputFormat: "ppk"})
	if err != nil || !result.IsError {
		t.Fatalf("expected tool error, result=%v err=%v", result, err)
	}
	got, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "keep me" {
		t.Fatalf("destination was modified: %q", got)
	}
}

func TestHandleWrongPassphraseCreatesNoOutput(t *testing.T) {
	dir := t.TempDir()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := gossh.MarshalPrivateKeyWithPassphrase(key, "source", []byte("right"))
	if err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(dir, "source.key")
	destination := filepath.Join(dir, "output.ppk")
	if err := os.WriteFile(source, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	result, _, err := Handle(t.Context(), nil, Input{InputPath: source, OutputPath: destination, OutputFormat: "ppk", InputPassphrase: "wrong"})
	if err != nil || !result.IsError {
		t.Fatalf("expected tool error, result=%v err=%v", result, err)
	}
	if _, err := os.Stat(destination); !os.IsNotExist(err) {
		t.Fatalf("output exists after parse failure: %v", err)
	}
}

func TestHandleRejectsExcessivePPKCost(t *testing.T) {
	dir := t.TempDir()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := marshalPPKv3(key, []byte("secret"), "test")
	if err != nil {
		t.Fatal(err)
	}
	encoded = []byte(strings.Replace(string(encoded), "Argon2-Memory: 8192", "Argon2-Memory: 4294967295", 1))
	source := filepath.Join(dir, "hostile.ppk")
	destination := filepath.Join(dir, "output.pem")
	if err := os.WriteFile(source, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	result, _, err := Handle(t.Context(), nil, Input{InputPath: source, OutputPath: destination, OutputFormat: "pem", InputPassphrase: "secret"})
	if err != nil || !result.IsError {
		t.Fatalf("expected safe-limit error, result=%v err=%v", result, err)
	}
	text := result.Content[0].(*mcp.TextContent).Text
	if !strings.Contains(text, "exceed safe conversion limits") {
		t.Fatalf("unexpected error: %s", text)
	}
	if _, err := os.Stat(destination); !os.IsNotExist(err) {
		t.Fatalf("output exists after rejected PPK: %v", err)
	}
}

func TestRegister(t *testing.T) {
	server := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "test"}, nil)
	Register(server)
	if _, ok := common.RegisteredSafeTool(server, "ssh_key"); !ok {
		t.Fatal("ssh_key SafeAddTool registration not found")
	}
}
