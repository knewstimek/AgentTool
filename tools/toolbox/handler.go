package toolbox

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"agent-tool/common"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const maxRawOutputChunkChars = common.HardOutputChars - 1024

type Spec struct {
	Name     string
	Group    string
	Register func()
}

type Manager struct {
	mu     sync.Mutex
	server *mcp.Server
	specs  map[string]Spec
	active map[string]bool
}

type Input struct {
	Operation      string         `json:"operation,omitempty" jsonschema:"Operation: list (default), describe, call, output, enable, disable, profile. Prefer describe/call because they work even when the MCP client ignores dynamic tool-list changes"`
	Tools          []string       `json:"tools,omitempty" jsonschema:"Individual tool names to enable or disable"`
	Groups         []string       `json:"groups,omitempty" jsonschema:"Tool groups to enable or disable: core, file, coding, system, remote, data, analysis, windows"`
	Profile        string         `json:"profile,omitempty" jsonschema:"Profile for operation=profile: core, coding, remote, analysis, full"`
	Tool           string         `json:"tool,omitempty" jsonschema:"Single tool name for operation=describe or call"`
	Arguments      map[string]any `json:"arguments,omitempty" jsonschema:"Target tool arguments for operation=call. Use operation=describe first when the schema is unknown"`
	OutputID       string         `json:"output_id,omitempty" jsonschema:"Preserved raw command output ID for operation=output"`
	OutputOffset   int            `json:"output_offset,omitempty" jsonschema:"Character offset for operation=output paging. Default: 0"`
	OutputMaxChars int            `json:"output_max_chars,omitempty" jsonschema:"Maximum raw-output characters returned by operation=output. Default: 32768, Max: 130048"`
}

type Output struct {
	Result  string   `json:"result"`
	Active  []string `json:"active"`
	Changed []string `json:"changed,omitempty"`
}

func NewManager(server *mcp.Server, specs []Spec) *Manager {
	m := &Manager{server: server, specs: make(map[string]Spec), active: make(map[string]bool)}
	for _, spec := range specs {
		m.specs[spec.Name] = spec
	}
	return m
}

func (m *Manager) EnableProfile(profile string) error {
	groups, ok := profileGroups(strings.ToLower(strings.TrimSpace(profile)))
	if !ok {
		return fmt.Errorf("unknown profile %q (use core, coding, remote, analysis, or full)", profile)
	}
	_, err := m.change(true, nil, groups)
	return err
}

func (m *Manager) RegisterTool() {
	common.SafeAddTool(m.server, &mcp.Tool{
		Name: "toolbox",
		Description: `Discover and call any AgentTool capability without loading every tool schema into the model context.
Use operation=describe with tool=<name> to fetch one tool's instructions and input schema, then operation=call with tool=<name> and arguments={...} to invoke it. This gateway works even when the MCP client ignores tools/list_changed.
Use operation=output with output_id=<raw_output_id> to retrieve bounded raw command output preserved after diagnostic compaction. Large records report next_offset for paging and expire after 30 minutes.
Use operation=list to see active and available tools. enable/disable/profile also expose direct tool bindings on clients that refresh dynamically.
Profiles: core (compact file/search tools), coding, remote, analysis, full.`,
	}, m.Handle)
}

func (m *Manager) Handle(ctx context.Context, req *mcp.CallToolRequest, input Input) (*mcp.CallToolResult, Output, error) {
	op := strings.ToLower(strings.TrimSpace(input.Operation))
	if op == "" {
		op = "list"
	}
	var changed []string
	var err error
	switch op {
	case "list":
	case "describe":
		return m.describe(input.Tool)
	case "call":
		return m.call(ctx, req, input.Tool, input.Arguments)
	case "output":
		return m.output(input.OutputID, input.OutputOffset, input.OutputMaxChars)
	case "enable":
		changed, err = m.change(true, input.Tools, input.Groups)
	case "disable":
		changed, err = m.change(false, input.Tools, input.Groups)
	case "profile":
		groups, ok := profileGroups(strings.ToLower(strings.TrimSpace(input.Profile)))
		if !ok {
			err = fmt.Errorf("unknown profile %q (use core, coding, remote, analysis, or full)", input.Profile)
			break
		}
		changed, err = m.change(true, nil, groups)
	default:
		err = fmt.Errorf("operation must be list, describe, call, output, enable, disable, or profile")
	}
	if err != nil {
		msg := err.Error()
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: msg}}, IsError: true}, Output{Result: msg}, nil
	}
	active, available := m.inventory()
	var sb strings.Builder
	sb.WriteString("Active tools: " + strings.Join(active, ", ") + "\n")
	if len(changed) > 0 {
		sb.WriteString("Changed: " + strings.Join(changed, ", ") + "\n")
	}
	sb.WriteString("Available by group:\n")
	groups := make([]string, 0, len(available))
	for group := range available {
		groups = append(groups, group)
	}
	sort.Strings(groups)
	for _, group := range groups {
		sb.WriteString(fmt.Sprintf("- %s: %s\n", group, strings.Join(available[group], ", ")))
	}
	sb.WriteString("Gateway: use operation=describe with tool=<name>, then operation=call with arguments={...}. This works even if newly enabled direct tools do not appear in the client.\n")
	result := sb.String()
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: result}}}, Output{Result: result, Active: active, Changed: changed}, nil
}

func (m *Manager) output(id string, offset, maxChars int) (*mcp.CallToolResult, Output, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return gatewayError("output_id is required for operation=output")
	}
	if offset < 0 {
		return gatewayError("output_offset must be non-negative")
	}
	if maxChars == 0 {
		maxChars = common.DefaultOutputChars
	}
	if maxChars < 1 || maxChars > maxRawOutputChunkChars {
		return gatewayError(fmt.Sprintf("output_max_chars must be between 1 and %d", maxRawOutputChunkChars))
	}
	record, ok := common.LoadRawOutput(id)
	if !ok {
		return gatewayError("raw output not found or expired")
	}
	runes := []rune(record.Content)
	if offset > len(runes) {
		return gatewayError(fmt.Sprintf("output_offset %d exceeds output length %d", offset, len(runes)))
	}
	end := offset + maxChars
	if end > len(runes) {
		end = len(runes)
	}
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Raw command output\noutput_id: %s\nsource: %s\n", record.ID, record.Source))
	sb.WriteString(fmt.Sprintf("created_at: %s\nexpires_at: %s\n", record.CreatedAt.UTC().Format(time.RFC3339), record.ExpiresAt.UTC().Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("original_bytes: %d\ntruncated: %t\nrange: %d:%d of %d characters\n", record.OriginalBytes, record.Truncated, offset, end, len(runes)))
	if end < len(runes) {
		sb.WriteString(fmt.Sprintf("next_offset: %d\n", end))
	}
	sb.WriteString("\n")
	sb.WriteString(string(runes[offset:end]))
	result := sb.String()
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: result}}}, Output{Result: result}, nil
}

func (m *Manager) describe(name string) (*mcp.CallToolResult, Output, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return gatewayError("tool is required for operation=describe")
	}
	changed, err := m.change(true, []string{name}, nil)
	if err != nil {
		return gatewayError(err.Error())
	}
	registration, ok := common.RegisteredSafeTool(m.server, name)
	if !ok {
		return gatewayError(fmt.Sprintf("tool %q registered without a SafeAddTool gateway handler", name))
	}
	schema, err := json.Marshal(registration.Tool.InputSchema)
	if err != nil {
		return gatewayError(fmt.Sprintf("cannot encode schema for %q: %v", name, err))
	}
	spec := m.specs[name]
	result := fmt.Sprintf("Tool: %s\nGroup: %s\nDescription:\n%s\nInput schema (JSON):\n%s\nCall through toolbox: operation=call, tool=%s, arguments={...}\n",
		name, spec.Group, registration.Tool.Description, schema, name)
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: result}}}, Output{
		Result: result, Changed: changed,
	}, nil
}

func (m *Manager) call(ctx context.Context, req *mcp.CallToolRequest, name string, arguments map[string]any) (*mcp.CallToolResult, Output, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return gatewayError("tool is required for operation=call")
	}
	if req == nil || req.Params == nil {
		return gatewayError("toolbox call requires an MCP tool request context")
	}
	if _, err := m.change(true, []string{name}, nil); err != nil {
		return gatewayError(err.Error())
	}
	registration, ok := common.RegisteredSafeTool(m.server, name)
	if !ok {
		return gatewayError(fmt.Sprintf("tool %q registered without a SafeAddTool gateway handler", name))
	}
	if arguments == nil {
		arguments = make(map[string]any)
	}
	rawArguments, err := json.Marshal(arguments)
	if err != nil {
		return gatewayError(fmt.Sprintf("cannot encode arguments for %q: %v", name, err))
	}
	forwarded := *req
	params := *req.Params
	params.Name = name
	params.Arguments = rawArguments
	forwarded.Params = &params
	result, err := registration.Handler(ctx, &forwarded)
	if err != nil {
		return gatewayError(fmt.Sprintf("%s gateway call failed: %v", name, err))
	}
	return result, Output{Result: fmt.Sprintf("called %s through toolbox", name)}, nil
}

func gatewayError(message string) (*mcp.CallToolResult, Output, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: message}},
		IsError: true,
	}, Output{Result: message}, nil
}

func (m *Manager) change(enable bool, names, groups []string) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	selected := make(map[string]bool)
	for _, name := range names {
		name = strings.TrimSpace(name)
		if _, ok := m.specs[name]; !ok {
			return nil, fmt.Errorf("unknown tool %q", name)
		}
		selected[name] = true
	}
	for _, group := range groups {
		group = strings.ToLower(strings.TrimSpace(group))
		found := false
		for name, spec := range m.specs {
			if spec.Group == group {
				selected[name] = true
				found = true
			}
		}
		if !found {
			return nil, fmt.Errorf("unknown or empty tool group %q", group)
		}
	}
	if len(selected) == 0 {
		return nil, fmt.Errorf("provide at least one tool or group")
	}
	ordered := make([]string, 0, len(selected))
	for name := range selected {
		ordered = append(ordered, name)
	}
	sort.Strings(ordered)
	changed := make([]string, 0, len(ordered))
	for _, name := range ordered {
		if enable && !m.active[name] {
			m.specs[name].Register()
			m.active[name] = true
			changed = append(changed, "+"+name)
		} else if !enable && m.active[name] {
			m.server.RemoveTools(name)
			delete(m.active, name)
			changed = append(changed, "-"+name)
		}
	}
	return changed, nil
}

func (m *Manager) inventory() ([]string, map[string][]string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	active := make([]string, 0, len(m.active)+1)
	active = append(active, "toolbox")
	available := make(map[string][]string)
	for name, spec := range m.specs {
		if m.active[name] {
			active = append(active, name)
		}
		available[spec.Group] = append(available[spec.Group], name)
	}
	sort.Strings(active)
	for group := range available {
		sort.Strings(available[group])
	}
	return active, available
}

func profileGroups(profile string) ([]string, bool) {
	switch profile {
	case "core", "":
		return []string{"core"}, true
	case "coding":
		return []string{"core", "file", "coding"}, true
	case "remote":
		return []string{"core", "remote"}, true
	case "analysis":
		return []string{"core", "analysis"}, true
	case "full":
		return []string{"core", "file", "coding", "system", "remote", "data", "analysis", "windows"}, true
	default:
		return nil, false
	}
}
