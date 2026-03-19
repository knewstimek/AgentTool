package proclist

import (
	"context"
	"fmt"
	"strings"

	"agent-tool/common"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type ProcListInput struct {
	Filter string `json:"filter,omitempty" jsonschema:"Filter by process name (case-insensitive partial match)"`
	Port   int    `json:"port,omitempty" jsonschema:"Show only processes using this port number"`
}

type ProcListOutput struct {
	Result string `json:"result"`
}

func Handle(ctx context.Context, req *mcp.CallToolRequest, input ProcListInput) (*mcp.CallToolResult, ProcListOutput, error) {
	procs, err := listProcesses()
	if err != nil {
		return errorResult(fmt.Sprintf("failed to list processes: %v", err))
	}

	// Validate port range
	if input.Port > 65535 {
		return errorResult("invalid port number: must be between 1 and 65535")
	}

	// Port filtering
	var portEntries []PortEntry
	portPIDSet := map[int]PortEntry{}
	if input.Port > 0 {
		entries, err := ListPortPIDs()
		if err == nil {
			for _, e := range entries {
				if e.Port == input.Port {
					portPIDSet[e.PID] = e
					portEntries = append(portEntries, e)
				}
			}
		}
	}

	// Filtering
	filter := strings.ToLower(strings.TrimSpace(strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' {
			return -1
		}
		return r
	}, input.Filter)))
	totalCount := len(procs)
	var filtered []ProcessInfo

	for i := range procs {
		p := &procs[i]
		// Port filter
		if input.Port > 0 {
			if _, ok := portPIDSet[p.PID]; !ok {
				continue
			}
		}
		// Name filter
		if filter != "" && !strings.Contains(strings.ToLower(p.Name), filter) {
			continue
		}
		filtered = append(filtered, *p)
	}

	// Fetch command lines only for filtered results (wmic is slow on Windows, so only after filtering)
	enrichCommandLines(filtered)

	// Mask sensitive information in command lines
	for i := range filtered {
		filtered[i].CmdLine = SanitizeCommandLine(filtered[i].CmdLine)
	}

	// Output formatting
	var sb strings.Builder

	if input.Port > 0 {
		sb.WriteString(fmt.Sprintf("=== Processes on port %d ===\n\n", input.Port))
	} else {
		sb.WriteString("=== Process List ===\n\n")
	}

	sb.WriteString(fmt.Sprintf("  %-8s %-24s %-12s %s\n", "PID", "NAME", "MEM", "COMMAND"))
	sb.WriteString(strings.Repeat("-", 80) + "\n")

	for _, p := range filtered {
		mem := formatMemKB(p.MemKB)
		cmdline := p.CmdLine
		if cmdline == "" {
			cmdline = "[" + p.Name + "]"
		}
		// Truncate long command lines
		if len(cmdline) > 200 {
			cmdline = cmdline[:197] + "..."
		}
		sb.WriteString(fmt.Sprintf("  %-8d %-24s %-12s %s\n", p.PID, truncate(p.Name, 24), mem, cmdline))
	}

	// Append port information
	if input.Port > 0 && len(portEntries) > 0 {
		sb.WriteString(fmt.Sprintf("\nProtocol: %s", portEntries[0].Protocol))
		if portEntries[0].State != "" {
			sb.WriteString(fmt.Sprintf(", State: %s", portEntries[0].State))
		}
		sb.WriteString("\n")
	}

	sb.WriteString(fmt.Sprintf("\nTotal: %d processes shown", len(filtered)))
	if filter != "" || input.Port > 0 {
		sb.WriteString(fmt.Sprintf(" (filtered from %d)", totalCount))
	}
	sb.WriteString("\n")

	result := sb.String()
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: result}},
	}, ProcListOutput{Result: result}, nil
}

func Register(server *mcp.Server) {
	common.SafeAddTool(server, &mcp.Tool{
		Name: "proclist",
		Description: `Lists running processes with PID, name, command line, and memory usage.
Sensitive information in command-line arguments (passwords, tokens) is automatically masked.
Use filter to search by process name, or port to find processes using a specific port.`,
	}, Handle)
}

func formatMemKB(kb uint64) string {
	if kb == 0 {
		return "-"
	}
	if kb >= 1024*1024 {
		return fmt.Sprintf("%.1f GB", float64(kb)/(1024*1024))
	}
	if kb >= 1024 {
		return fmt.Sprintf("%.1f MB", float64(kb)/1024)
	}
	return fmt.Sprintf("%d KB", kb)
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

func errorResult(msg string) (*mcp.CallToolResult, ProcListOutput, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		IsError: true,
	}, ProcListOutput{Result: msg}, nil
}
