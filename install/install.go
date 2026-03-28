package install

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

type agentConfig struct {
	name       string
	configPath string
	format     string // "json" or "toml"
	jsonKey    string // MCP servers key in JSON config
}

// getAgents returns the list of supported agents with their config paths.
func getAgents() (map[string]agentConfig, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get home directory: %w", err)
	}
	return map[string]agentConfig{
		"claude": {
			name:       "Claude Code",
			configPath: filepath.Join(home, ".claude", "settings.json"),
			format:     "json",
			jsonKey:    "mcpServers",
		},
		"cursor": {
			name:       "Cursor",
			configPath: filepath.Join(home, ".cursor", "mcp.json"),
			format:     "json",
			jsonKey:    "mcpServers",
		},
		"windsurf": {
			name:       "Windsurf",
			configPath: filepath.Join(home, ".codeium", "windsurf", "mcp_config.json"),
			format:     "json",
			jsonKey:    "mcpServers",
		},
		"codex": {
			name:       "Codex CLI",
			configPath: filepath.Join(home, ".codex", "config.toml"),
			format:     "toml",
		},
	}, nil
}

// ApproveLevel controls which tools are auto-approved during install.
type ApproveLevel int

const (
	ApproveFull ApproveLevel = iota // mcp__agent-tool__* (all tools, no popups)
	ApproveSafe                     // safe tools only (file/search/metadata)
	ApproveNone                     // no auto-approval (every call needs manual approval)
)

// approveLevel is set by Run() and used by permission functions.
var currentApproveLevel ApproveLevel

// Run executes the install command.
// If target is empty, registers with all detected agents.
func Run(target string, level ApproveLevel) error {
	currentApproveLevel = level
	agents, err := getAgents()
	if err != nil {
		return err
	}

	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}
	// Resolve symlinks
	exePath, err = filepath.EvalSymlinks(exePath)
	if err != nil {
		return fmt.Errorf("failed to resolve path: %w", err)
	}

	if target != "" {
		agent, ok := agents[strings.ToLower(target)]
		if !ok {
			return fmt.Errorf("unknown agent: %s (supported: claude, cursor, windsurf, codex)", target)
		}
		return installForAgent(agent, exePath)
	}

	// Try to install for all detected agents
	installed := 0
	for _, agent := range agents {
		dir := filepath.Dir(agent.configPath)
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			continue // this agent is not installed
		}
		if err := installForAgent(agent, exePath); err != nil {
			fmt.Fprintf(os.Stderr, "[%s] failed: %v\n", agent.name, err)
		} else {
			installed++
		}
	}

	if installed == 0 {
		fmt.Println("No agents detected. Specify a target: agent-tool install [claude|cursor|windsurf|codex]")
	}
	return nil
}

// Uninstall removes agent-tool from the specified agent (or all agents).
func Uninstall(target string) error {
	agents, err := getAgents()
	if err != nil {
		return err
	}

	if target != "" {
		agent, ok := agents[strings.ToLower(target)]
		if !ok {
			return fmt.Errorf("unknown agent: %s (supported: claude, cursor, windsurf, codex)", target)
		}
		return uninstallFromAgent(agent)
	}

	// Try to uninstall from all agents
	removed := 0
	for _, agent := range agents {
		if _, err := os.Stat(agent.configPath); os.IsNotExist(err) {
			continue
		}
		if err := uninstallFromAgent(agent); err != nil {
			fmt.Fprintf(os.Stderr, "[%s] failed: %v\n", agent.name, err)
		} else {
			removed++
		}
	}

	if removed == 0 {
		fmt.Println("No registered agents found.")
	}
	return nil
}

func uninstallFromAgent(agent agentConfig) error {
	// Claude Code: try 'claude mcp remove' first
	if agent.name == "Claude Code" {
		removeClaudePermission()
		if err := uninstallClaudeMCPRemove(); err == nil {
			return nil
		}
		fmt.Println("[Claude Code] 'claude' CLI not found. Removing from settings.json directly.")
	}

	switch agent.format {
	case "json":
		return uninstallJSON(agent)
	case "toml":
		return uninstallTOML(agent)
	default:
		return fmt.Errorf("unsupported config format: %s", agent.format)
	}
}

// uninstallClaudeMCPRemove removes agent-tool via the 'claude mcp remove' CLI command.
func uninstallClaudeMCPRemove() error {
	claudePath, err := exec.LookPath("claude")
	if err != nil {
		return err
	}

	cmd := exec.Command(claudePath, "mcp", "remove", "agent-tool")
	cmd.Stdin = nil // prevent blocking on interactive prompts
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("claude mcp remove failed: %w (%s)", err, strings.TrimSpace(string(out)))
	}

	fmt.Printf("[Claude Code] Unregistered (claude mcp remove)\n")
	return nil
}

func uninstallJSON(agent agentConfig) error {
	data, err := os.ReadFile(agent.configPath)
	if err != nil {
		return fmt.Errorf("failed to read config: %w", err)
	}

	var config map[string]any
	if err := json.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("failed to parse config: %w", err)
	}

	servers, ok := config[agent.jsonKey].(map[string]any)
	if !ok {
		fmt.Printf("[%s] agent-tool is not registered.\n", agent.name)
		return nil
	}

	if _, exists := servers["agent-tool"]; !exists {
		fmt.Printf("[%s] agent-tool is not registered.\n", agent.name)
		return nil
	}

	// Remove only the agent-tool key (preserve other MCP servers)
	delete(servers, "agent-tool")
	config[agent.jsonKey] = servers

	output, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to serialize JSON: %w", err)
	}

	if err := os.WriteFile(agent.configPath, output, 0644); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	fmt.Printf("[%s] Unregistered: %s\n", agent.name, agent.configPath)
	return nil
}

func uninstallTOML(agent agentConfig) error {
	data, err := os.ReadFile(agent.configPath)
	if err != nil {
		return fmt.Errorf("failed to read config: %w", err)
	}

	content := string(data)
	if !strings.Contains(content, "[mcp_servers.agent-tool]") {
		fmt.Printf("[%s] agent-tool is not registered.\n", agent.name)
		return nil
	}

	// Remove the section
	lines := strings.Split(content, "\n")
	var result []string
	skip := false
	for _, line := range lines {
		if strings.TrimSpace(line) == "[mcp_servers.agent-tool]" {
			skip = true
			continue
		}
		if skip {
			trimmed := strings.TrimSpace(line)
			// Detect actual section headers: starts with [ and ends with ], no = sign.
			// This avoids matching TOML array values like args = ["--flag"].
			if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") && !strings.Contains(trimmed, "=") {
				skip = false
			}
		}
		if !skip {
			result = append(result, line)
		}
	}

	content = strings.TrimRight(strings.Join(result, "\n"), "\n") + "\n"
	if err := os.WriteFile(agent.configPath, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	fmt.Printf("[%s] Unregistered: %s\n", agent.name, agent.configPath)
	return nil
}

func installForAgent(agent agentConfig, exePath string) error {
	// Claude Code: try 'claude mcp add' first (supports both CLI and VSCode extension)
	if agent.name == "Claude Code" {
		if err := installClaudeMCPAdd(exePath); err == nil {
			return nil
		}
		// claude CLI not found — fall back to direct settings.json modification
		fmt.Println("[Claude Code] 'claude' CLI not found. Registering in settings.json directly.")
	}

	switch agent.format {
	case "json":
		err := installJSON(agent, exePath)
		if err != nil {
			return err
		}
		// Also register permissions for Claude Code JSON fallback
		if agent.name == "Claude Code" {
			if perr := addClaudePermission(); perr != nil {
				fmt.Fprintf(os.Stderr, "[Claude Code] Failed to register permissions (manual approval needed): %v\n", perr)
			}
		}
		return nil
	case "toml":
		return installTOML(agent, exePath)
	default:
		return fmt.Errorf("unsupported config format: %s", agent.format)
	}
}

// installClaudeMCPAdd registers agent-tool via the 'claude mcp add' CLI command.
func installClaudeMCPAdd(exePath string) error {
	claudePath, err := exec.LookPath("claude")
	if err != nil {
		return err
	}

	normalizedPath := filepath.ToSlash(exePath)

	// Remove existing entry before re-registering (supports updates).
	// Ignore errors — remove may fail if entry doesn't exist.
	// Close stdin to prevent the CLI from blocking on interactive prompts.
	removeCmd := exec.Command(claudePath, "mcp", "remove", "agent-tool")
	removeCmd.Stdin = nil
	removeCmd.Run()

	// Update per-project MCP entries in ~/.claude.json.
	// The 'claude mcp' CLI doesn't manage per-project entries (projects.*.mcpServers),
	// so we update them directly to prevent stale binary paths from overriding global config.
	updateClaudeProjectMCPServers(normalizedPath)

	cmd := exec.Command(claudePath, "mcp", "add", "--scope", "user", "agent-tool", normalizedPath)
	cmd.Stdin = nil // prevent blocking on interactive prompts
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("claude mcp add failed: %w (%s)", err, strings.TrimSpace(string(out)))
	}

	// Register permissions in settings.json based on approve level
	if currentApproveLevel != ApproveNone {
		if err := addClaudePermission(); err != nil {
			fmt.Fprintf(os.Stderr, "[Claude Code] Failed to register permissions (manual approval needed): %v\n", err)
		} else {
			switch currentApproveLevel {
			case ApproveFull:
				fmt.Printf("[Claude Code] Tool permissions registered (permissions.allow: %s)\n", mcpPermissionEntry)
			case ApproveSafe:
				fmt.Printf("[Claude Code] Safe tool permissions registered (%d tools auto-approved, network/system tools require manual approval)\n", len(safePermissionEntries))
			}
		}
	} else {
		fmt.Println("[Claude Code] No auto-approval (all tool calls require manual approval)")
	}

	fmt.Printf("[Claude Code] Registered (claude mcp add)\n")
	return nil
}

// updateClaudeProjectMCPServers updates per-project MCP entries in ~/.claude.json.
// Claude Code stores per-project MCP servers under projects."path".mcpServers,
// which take priority over global mcpServers. Not managed by 'claude mcp' CLI.
func updateClaudeProjectMCPServers(newPath string) {
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}

	claudeJSON := filepath.Join(home, ".claude.json")
	data, err := os.ReadFile(claudeJSON)
	if err != nil {
		return
	}

	var config map[string]any
	if err := json.Unmarshal(data, &config); err != nil {
		return
	}

	projects, ok := config["projects"].(map[string]any)
	if !ok {
		return
	}

	updated := false
	for _, projVal := range projects {
		proj, ok := projVal.(map[string]any)
		if !ok {
			continue
		}
		servers, ok := proj["mcpServers"].(map[string]any)
		if !ok {
			continue
		}
		entry, ok := servers["agent-tool"].(map[string]any)
		if !ok {
			continue
		}
		oldCmd, _ := entry["command"].(string)
		if oldCmd != newPath {
			entry["command"] = newPath
			updated = true
		}
	}

	if updated {
		output, err := json.MarshalIndent(config, "", "  ")
		if err != nil {
			return
		}
		os.WriteFile(claudeJSON, output, 0644)
		fmt.Println("[Claude Code] Updated per-project MCP paths")
	}
}

// Permission levels for auto-approval:
// - "full": wildcard mcp__agent-tool__* (all tools, no popups)
// - "safe": only file/search tools auto-approved; network/system tools require manual approval
// - "none": no auto-approval (every tool call requires manual approval)

const mcpPermissionEntry = "mcp__agent-tool__*"

// safePermissionEntries lists tools that are safe to auto-approve.
// These only access local files, metadata, or read-only system info.
// Excluded (require manual approval): ssh, sftp, mysql, redis, httpreq,
// webfetch, download, bash, procexec, prockill, debug — these access networks,
// remote systems, or execute arbitrary commands.
var safePermissionEntries = []string{
	"mcp__agent-tool__read",
	"mcp__agent-tool__write",
	"mcp__agent-tool__edit",
	"mcp__agent-tool__grep",
	"mcp__agent-tool__glob",
	"mcp__agent-tool__multiread",
	"mcp__agent-tool__listdir",
	"mcp__agent-tool__diff",
	"mcp__agent-tool__patch",
	"mcp__agent-tool__checksum",
	"mcp__agent-tool__file_info",
	"mcp__agent-tool__compress",
	"mcp__agent-tool__decompress",
	"mcp__agent-tool__backup",
	"mcp__agent-tool__convert_encoding",
	"mcp__agent-tool__delete",
	"mcp__agent-tool__rename",
	"mcp__agent-tool__mkdir",
	"mcp__agent-tool__sloc",
	"mcp__agent-tool__copy",
	"mcp__agent-tool__regexreplace",
	"mcp__agent-tool__jsonquery",
	"mcp__agent-tool__yamlquery",
	"mcp__agent-tool__tomlquery",
	"mcp__agent-tool__sysinfo",
	"mcp__agent-tool__find_tools",
	"mcp__agent-tool__proclist",
	"mcp__agent-tool__envvar",
	// externalip excluded from safe: makes external HTTP requests
	// set_config excluded from safe: can change SSRF policy
	"mcp__agent-tool__agent_tool_help",
	"mcp__agent-tool__analyze",
	"mcp__agent-tool__codegraph",
}

// addClaudePermission adds agent-tool entries to ~/.claude/settings.json
// permissions.allow based on the current approve level.
func addClaudePermission() error {
	if currentApproveLevel == ApproveNone {
		return nil // user opted out of auto-approval
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	settingsPath := filepath.Join(home, ".claude", "settings.json")

	var config map[string]any

	data, err := os.ReadFile(settingsPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("failed to read settings.json: %w", err)
		}
		config = make(map[string]any)
	} else {
		if err := json.Unmarshal(data, &config); err != nil {
			return fmt.Errorf("failed to parse settings.json: %w", err)
		}
	}

	// Get permissions.allow array
	perms, _ := config["permissions"].(map[string]any)
	if perms == nil {
		perms = make(map[string]any)
	}

	allowList, _ := perms["allow"].([]any)

	// Remove all existing agent-tool entries first (clean slate)
	var cleaned []any
	for _, item := range allowList {
		s, ok := item.(string)
		if ok && strings.HasPrefix(s, "mcp__agent-tool__") {
			continue
		}
		cleaned = append(cleaned, item)
	}

	// Add entries based on approve level
	switch currentApproveLevel {
	case ApproveFull:
		cleaned = append(cleaned, mcpPermissionEntry)
	case ApproveSafe:
		for _, entry := range safePermissionEntries {
			cleaned = append(cleaned, entry)
		}
	}

	perms["allow"] = cleaned
	config["permissions"] = perms

	output, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to serialize JSON: %w", err)
	}

	return os.WriteFile(settingsPath, output, 0644)
}

// removeClaudePermission removes agent-tool permission entries from settings.json.
func removeClaudePermission() {
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}
	settingsPath := filepath.Join(home, ".claude", "settings.json")

	data, err := os.ReadFile(settingsPath)
	if err != nil {
		return
	}

	var config map[string]any
	if err := json.Unmarshal(data, &config); err != nil {
		return
	}

	perms, _ := config["permissions"].(map[string]any)
	if perms == nil {
		return
	}

	allowList, _ := perms["allow"].([]any)
	var cleaned []any
	for _, item := range allowList {
		s, ok := item.(string)
		if ok && strings.HasPrefix(s, "mcp__agent-tool") {
			continue
		}
		cleaned = append(cleaned, item)
	}

	perms["allow"] = cleaned
	config["permissions"] = perms

	output, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return
	}
	os.WriteFile(settingsPath, output, 0644)
}

func installJSON(agent agentConfig, exePath string) error {
	// Read existing config (create new if not found)
	var config map[string]any

	data, err := os.ReadFile(agent.configPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("failed to read config: %w", err)
		}
		config = make(map[string]any)
	} else {
		if err := json.Unmarshal(data, &config); err != nil {
			return fmt.Errorf("failed to parse config (JSON may be corrupted): %w", err)
		}
	}

	// Get mcpServers key (create if not exists)
	servers, ok := config[agent.jsonKey].(map[string]any)
	if !ok {
		servers = make(map[string]any)
	}

	// Check if already registered
	if _, exists := servers["agent-tool"]; exists {
		fmt.Printf("[%s] Already registered. Updating.\n", agent.name)
	}

	// Normalize path to forward slashes (for JSON)
	normalizedPath := filepath.ToSlash(exePath)

	// Register agent-tool server
	servers["agent-tool"] = map[string]any{
		"type":    "stdio",
		"command": normalizedPath,
		"args":    []string{},
		"env":     map[string]any{},
	}
	config[agent.jsonKey] = servers

	// Create directory if needed
	if err := os.MkdirAll(filepath.Dir(agent.configPath), 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Write pretty-printed JSON
	output, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to serialize JSON: %w", err)
	}

	if err := os.WriteFile(agent.configPath, output, 0644); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	fmt.Printf("[%s] Registered: %s\n", agent.name, agent.configPath)
	return nil
}

func installTOML(agent agentConfig, exePath string) error {
	normalizedPath := exePath
	if runtime.GOOS == "windows" {
		// Use forward slashes in TOML to avoid backslash escaping
		normalizedPath = filepath.ToSlash(exePath)
	}

	var entry string
	if agent.name == "Codex CLI" && runtime.GOOS == "windows" {
		// Codex on Windows: wrap with cmd /c to redirect stderr to NUL.
		// Codex's MCP client has a bug (Issue #7155) where the stderr pipe
		// blocks when the server writes to stderr, causing "Transport closed"
		// errors. Redirecting to NUL eliminates the pipe buffer entirely.
		entry = fmt.Sprintf("\n[mcp_servers.agent-tool]\ncommand = \"cmd\"\nargs = [\"/c\", %q]\nenabled = true\n",
			normalizedPath+" 2>NUL")
	} else {
		entry = fmt.Sprintf("\n[mcp_servers.agent-tool]\ncommand = %q\nargs = []\nenabled = true\n", normalizedPath)
	}

	// Read existing file
	data, err := os.ReadFile(agent.configPath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to read config: %w", err)
	}

	content := string(data)

	// Check if already registered
	if strings.Contains(content, "[mcp_servers.agent-tool]") {
		// Update existing entry: find and replace the section
		lines := strings.Split(content, "\n")
		var result []string
		skip := false
		for _, line := range lines {
			if strings.TrimSpace(line) == "[mcp_servers.agent-tool]" {
				skip = true
				continue
			}
			// Detect actual section headers: starts with [ and ends with ], no = sign.
			// This avoids matching TOML array values like args = ["--flag"].
			if skip {
				trimmed := strings.TrimSpace(line)
				if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") && !strings.Contains(trimmed, "=") {
					skip = false
				}
			}
			if !skip {
				result = append(result, line)
			}
		}
		content = strings.Join(result, "\n")
		fmt.Printf("[%s] Already registered. Updating.\n", agent.name)
	}

	// Append entry
	content = strings.TrimRight(content, "\n") + "\n" + entry

	if err := os.MkdirAll(filepath.Dir(agent.configPath), 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	if err := os.WriteFile(agent.configPath, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	fmt.Printf("[%s] Registered: %s\n", agent.name, agent.configPath)
	return nil
}
