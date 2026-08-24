package toolbox

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"agent-tool/common"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

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
	Operation string   `json:"operation,omitempty" jsonschema:"Operation: list (default), enable, disable, profile"`
	Tools     []string `json:"tools,omitempty" jsonschema:"Individual tool names to enable or disable"`
	Groups    []string `json:"groups,omitempty" jsonschema:"Tool groups to enable or disable: core, file, coding, system, remote, data, analysis, windows"`
	Profile   string   `json:"profile,omitempty" jsonschema:"Profile for operation=profile: core, coding, remote, analysis, full"`
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
		Description: `Discover and dynamically enable AgentTool capabilities without loading every tool schema into the model context.
Use operation=list to see active and available tools. Enable only the group or tool needed for the current task.
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
		err = fmt.Errorf("operation must be list, enable, disable, or profile")
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
	result := sb.String()
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: result}}}, Output{Result: result, Active: active, Changed: changed}, nil
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
