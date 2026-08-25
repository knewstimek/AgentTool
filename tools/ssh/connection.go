package ssh

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"time"
)

const (
	connectionHandleTTL  = 30 * time.Minute
	maxConnectionHandles = 64
)

// ConnectionProfile is the non-command portion of an SSH/SFTP request. Local
// profile files may contain secrets and must not be checked into source control.
type ConnectionProfile struct {
	Host           string      `json:"host"`
	Port           interface{} `json:"port,omitempty"`
	User           string      `json:"user"`
	Password       string      `json:"password,omitempty"`
	KeyFile        string      `json:"key_file,omitempty"`
	Passphrase     string      `json:"passphrase,omitempty"`
	UseAgent       interface{} `json:"use_agent,omitempty"`
	HostKeyCheck   string      `json:"host_key_check,omitempty"`
	JumpHost       string      `json:"jump_host,omitempty"`
	JumpPort       interface{} `json:"jump_port,omitempty"`
	JumpUser       string      `json:"jump_user,omitempty"`
	JumpPassword   string      `json:"jump_password,omitempty"`
	JumpKeyFile    string      `json:"jump_key_file,omitempty"`
	JumpPassphrase string      `json:"jump_passphrase,omitempty"`
	Trusted        bool        `json:"trusted,omitempty"`
}

type connectionProfileFile struct {
	Connections map[string]ConnectionProfile `json:"connections"`
	Profiles    map[string]ConnectionProfile `json:"profiles"`
}

type connectionHandle struct {
	profile  ConnectionProfile
	lastUsed time.Time
}

var connectionHandles = struct {
	sync.Mutex
	items map[string]connectionHandle
}{items: make(map[string]connectionHandle)}

// ResolveConnection fills omitted connection fields from a local profile or
// an opaque in-process connection handle. Explicit request fields override
// local profile defaults. The returned handle can be reused by SSH and SFTP.
func ResolveConnection(input *SSHInput) (string, error) {
	if input == nil {
		return "", fmt.Errorf("connection input is required")
	}
	profileName := strings.TrimSpace(input.ConnectionProfile)
	handleID := strings.TrimSpace(input.ConnectionID)
	if profileName != "" && handleID != "" {
		return "", fmt.Errorf("use either connection_profile or connection_id, not both")
	}
	hasOverrides := hasExplicitConnectionFields(*input)
	if handleID != "" && hasOverrides {
		return "", fmt.Errorf("connection_id cannot be combined with host/user/auth/jump overrides")
	}

	var base ConnectionProfile
	var err error
	if handleID != "" {
		base, err = loadConnectionHandle(handleID)
		if err != nil {
			return "", err
		}
	} else if profileName != "" {
		base, err = loadLocalConnectionProfile(profileName)
		if err != nil {
			return "", err
		}
	}
	if profileName != "" && hasOverrides {
		// Redirecting a trusted profile must not inherit warning suppression.
		base.Trusted = false
	}
	applyProfileDefaults(input, base)
	if base.Trusted {
		input.TrustedProfile = true
	}

	if handleID == "" {
		handleID, err = rememberConnection(*input)
		if err != nil {
			return "", err
		}
	}
	input.ResolvedConnectionID = handleID
	return handleID, nil
}

func hasExplicitConnectionFields(input SSHInput) bool {
	return input.Host != "" || input.Port != nil || input.User != "" || input.Password != "" ||
		input.KeyFile != "" || input.Passphrase != "" || input.UseAgent != nil || input.HostKeyCheck != "" ||
		input.JumpHost != "" || input.JumpPort != nil || input.JumpUser != "" || input.JumpPassword != "" ||
		input.JumpKeyFile != "" || input.JumpPassphrase != ""
}

func loadLocalConnectionProfile(name string) (ConnectionProfile, error) {
	path := strings.TrimSpace(os.Getenv("AGENT_TOOL_CONNECTION_PROFILE_FILE"))
	if path == "" {
		configDir, err := os.UserConfigDir()
		if err != nil {
			return ConnectionProfile{}, fmt.Errorf("cannot locate local connection profile directory: %w", err)
		}
		path = filepath.Join(configDir, "agent-tool", "connections.json")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ConnectionProfile{}, fmt.Errorf("cannot read local connection profiles %s: %w", path, err)
	}
	var file connectionProfileFile
	if err := json.Unmarshal(data, &file); err != nil {
		return ConnectionProfile{}, fmt.Errorf("invalid local connection profile file %s: %w", path, err)
	}
	profiles := file.Connections
	if len(profiles) == 0 {
		profiles = file.Profiles
	}
	profile, ok := profiles[name]
	if !ok {
		return ConnectionProfile{}, fmt.Errorf("connection_profile %q not found in %s", name, path)
	}
	return profile, nil
}

func rememberConnection(input SSHInput) (string, error) {
	profile := profileFromInput(input)
	now := time.Now()
	connectionHandles.Lock()
	defer connectionHandles.Unlock()
	pruneConnectionHandlesLocked(now)
	for id, entry := range connectionHandles.items {
		if reflect.DeepEqual(entry.profile, profile) {
			entry.lastUsed = now
			connectionHandles.items[id] = entry
			return id, nil
		}
	}

	var random [12]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", fmt.Errorf("cannot create connection_id: %w", err)
	}
	id := "conn_" + hex.EncodeToString(random[:])
	if len(connectionHandles.items) >= maxConnectionHandles {
		var oldestID string
		var oldest time.Time
		for candidate, entry := range connectionHandles.items {
			if oldestID == "" || entry.lastUsed.Before(oldest) {
				oldestID, oldest = candidate, entry.lastUsed
			}
		}
		delete(connectionHandles.items, oldestID)
	}
	connectionHandles.items[id] = connectionHandle{profile: profile, lastUsed: now}
	return id, nil
}

func loadConnectionHandle(id string) (ConnectionProfile, error) {
	connectionHandles.Lock()
	defer connectionHandles.Unlock()
	now := time.Now()
	pruneConnectionHandlesLocked(now)
	entry, ok := connectionHandles.items[id]
	if !ok {
		return ConnectionProfile{}, fmt.Errorf("connection_id %q not found or expired", id)
	}
	entry.lastUsed = now
	connectionHandles.items[id] = entry
	return entry.profile, nil
}

func pruneConnectionHandlesLocked(now time.Time) {
	for id, entry := range connectionHandles.items {
		if now.Sub(entry.lastUsed) > connectionHandleTTL {
			delete(connectionHandles.items, id)
		}
	}
}

func profileFromInput(input SSHInput) ConnectionProfile {
	return ConnectionProfile{
		Host: input.Host, Port: input.Port, User: input.User, Password: input.Password,
		KeyFile: input.KeyFile, Passphrase: input.Passphrase, UseAgent: input.UseAgent,
		HostKeyCheck: input.HostKeyCheck, JumpHost: input.JumpHost, JumpPort: input.JumpPort,
		JumpUser: input.JumpUser, JumpPassword: input.JumpPassword,
		JumpKeyFile: input.JumpKeyFile, JumpPassphrase: input.JumpPassphrase,
		Trusted: input.TrustedProfile,
	}
}

func applyProfileDefaults(input *SSHInput, profile ConnectionProfile) {
	if input.Host == "" {
		input.Host = profile.Host
	}
	if input.Port == nil {
		input.Port = profile.Port
	}
	if input.User == "" {
		input.User = profile.User
	}
	if input.Password == "" {
		input.Password = profile.Password
	}
	if input.KeyFile == "" {
		input.KeyFile = profile.KeyFile
	}
	if input.Passphrase == "" {
		input.Passphrase = profile.Passphrase
	}
	if input.UseAgent == nil {
		input.UseAgent = profile.UseAgent
	}
	if input.HostKeyCheck == "" {
		input.HostKeyCheck = profile.HostKeyCheck
	}
	if input.JumpHost == "" {
		input.JumpHost = profile.JumpHost
	}
	if input.JumpPort == nil {
		input.JumpPort = profile.JumpPort
	}
	if input.JumpUser == "" {
		input.JumpUser = profile.JumpUser
	}
	if input.JumpPassword == "" {
		input.JumpPassword = profile.JumpPassword
	}
	if input.JumpKeyFile == "" {
		input.JumpKeyFile = profile.JumpKeyFile
	}
	if input.JumpPassphrase == "" {
		input.JumpPassphrase = profile.JumpPassphrase
	}
}
