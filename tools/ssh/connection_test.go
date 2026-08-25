package ssh

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLocalConnectionProfileAndConnectionIDReuse(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "connections.json")
	data := []byte(`{"connections":{"dev":{"host":"127.0.0.1","port":2222,"user":"builder","key_file":"~/.ssh/id_test","trusted":true}}}`)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AGENT_TOOL_CONNECTION_PROFILE_FILE", path)

	first := SSHInput{ConnectionProfile: "dev"}
	id, err := ResolveConnection(&first)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(id, "conn_") || first.Host != "127.0.0.1" || first.User != "builder" || !first.TrustedProfile {
		t.Fatalf("profile was not resolved: id=%q input=%+v", id, first)
	}

	second := SSHInput{ConnectionID: id}
	secondID, err := ResolveConnection(&second)
	if err != nil {
		t.Fatal(err)
	}
	if secondID != id || second.Host != first.Host || second.User != first.User || !second.TrustedProfile {
		t.Fatalf("connection handle was not reused: id=%q input=%+v", secondID, second)
	}

	again := SSHInput{ConnectionProfile: "dev"}
	againID, err := ResolveConnection(&again)
	if err != nil || againID != id {
		t.Fatalf("same profile should reuse its handle: id=%q err=%v", againID, err)
	}
}

func TestTrustedPrivateWarningIsOncePerPooledSession(t *testing.T) {
	input := SSHInput{Host: "127.0.0.1", User: "builder", HostKeyCheck: "none", TrustedProfile: true}
	if err := validateInput(&input); err != nil {
		t.Fatal(err)
	}
	key := sessionKey(input)
	pool.mu.Lock()
	pool.sessions[key] = &sessionEntry{}
	pool.mu.Unlock()
	t.Cleanup(func() {
		pool.mu.Lock()
		delete(pool.sessions, key)
		pool.mu.Unlock()
	})

	warning := "private address warning"
	if got := PrivateWarningForConnection(input, warning); got != warning {
		t.Fatalf("first warning = %q", got)
	}
	if got := PrivateWarningForConnection(input, warning); got != "" {
		t.Fatalf("second warning = %q", got)
	}

	input.TrustedProfile = false
	if got := PrivateWarningForConnection(input, warning); got != warning {
		t.Fatalf("untrusted warning should not be suppressed: %q", got)
	}
}
