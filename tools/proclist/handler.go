package proclist

import (
	"context"
	"fmt"
	"strings"

	"agent-tool/common"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type ProcListInput struct {
	Filter         string      `json:"filter,omitempty" jsonschema:"Filter by process name (case-insensitive partial match)"`
	Port           interface{} `json:"port,omitempty" jsonschema:"Show only processes using this port number"`
	Offset         int         `json:"offset,omitempty" jsonschema:"Zero-based result offset. Default: 0"`
	MaxResults     int         `json:"max_results,omitempty" jsonschema:"Maximum processes returned per page. Default: 100, Max: 1000"`
	MaxOutputChars int         `json:"max_output_chars,omitempty" jsonschema:"Maximum returned text characters. Default: 32768, Max: 131072"`
}

type ProcListOutput struct {
	Result     string `json:"result"`
	Total      int    `json:"total"`
	Returned   int    `json:"returned"`
	HasMore    bool   `json:"has_more"`
	NextOffset int    `json:"next_offset,omitempty"`
	Truncated  bool   `json:"truncated"`
}

func Handle(ctx context.Context, req *mcp.CallToolRequest, input ProcListInput) (*mcp.CallToolResult, ProcListOutput, error) {
	port, ok := common.FlexInt(input.Port)
	if !ok {
		return errorResult("port must be an integer")
	}
	if input.Offset < 0 {
		return errorResult("offset must be non-negative")
	}
	if input.MaxResults == 0 {
		input.MaxResults = 100
	}
	if input.MaxResults < 1 || input.MaxResults > 1000 {
		return errorResult("max_results must be between 1 and 1000")
	}
	if input.MaxOutputChars == 0 {
		input.MaxOutputChars = common.DefaultOutputChars
	}
	if input.MaxOutputChars < 1024 || input.MaxOutputChars > common.HardOutputChars {
		return errorResult(fmt.Sprintf("max_output_chars must be between 1024 and %d", common.HardOutputChars))
	}

	procs, err := listProcesses()
	if err != nil {
		return errorResult(fmt.Sprintf("failed to list processes: %v", err))
	}

	// Validate port range
	if port > 65535 {
		return errorResult("invalid port number: must be between 1 and 65535")
	}

	// Port filtering
	var portEntries []PortEntry
	portPIDSet := map[int]PortEntry{}
	if port > 0 {
		entries, err := ListPortPIDs()
		if err == nil {
			for _, e := range entries {
				if e.Port == port {
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
		if port > 0 {
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

	matchedCount := len(filtered)
	start := input.Offset
	if start > matchedCount {
		start = matchedCount
	}
	end := start + input.MaxResults
	if end > matchedCount {
		end = matchedCount
	}
	page := filtered[start:end]

	// Fetch command lines only for this page (wmic is slow on Windows).
	enrichCommandLines(page)

	// Mask sensitive information in command lines
	for i := range page {
		page[i].CmdLine = SanitizeCommandLine(page[i].CmdLine)
	}

	// Output formatting
	var sb strings.Builder

	if port > 0 {
		sb.WriteString(fmt.Sprintf("=== Processes on port %d ===\n\n", port))
	} else {
		sb.WriteString("=== Process List ===\n\n")
	}

	sb.WriteString(fmt.Sprintf("  %-8s %-24s %-12s %s\n", "PID", "NAME", "MEM", "COMMAND"))
	sb.WriteString(strings.Repeat("-", 80) + "\n")

	used := len([]rune(sb.String()))
	returned := 0
	outputTruncated := false
	for _, p := range page {
		mem := formatMemKB(p.MemKB)
		cmdline := p.CmdLine
		if cmdline == "" {
			cmdline = "[" + p.Name + "]"
		}
		// Truncate long command lines
		if len(cmdline) > 200 {
			cmdline = cmdline[:197] + "..."
		}
		line := fmt.Sprintf("  %-8d %-24s %-12s %s\n", p.PID, truncate(p.Name, 24), mem, cmdline)
		if !common.AppendWithinRuneBudget(&sb, &used, line, input.MaxOutputChars-256) {
			outputTruncated = true
			break
		}
		returned++
	}

	// Append port information
	if port > 0 && len(portEntries) > 0 {
		sb.WriteString(fmt.Sprintf("\nProtocol: %s", portEntries[0].Protocol))
		if portEntries[0].State != "" {
			sb.WriteString(fmt.Sprintf(", State: %s", portEntries[0].State))
		}
		sb.WriteString("\n")
	}

	nextOffset := start + returned
	hasMore := nextOffset < matchedCount
	if outputTruncated {
		hasMore = true
	}
	sb.WriteString(fmt.Sprintf("\n[proclist: returned=%d; matched=%d; total_system=%d; has_more=%t", returned, matchedCount, totalCount, hasMore))
	if hasMore {
		sb.WriteString(fmt.Sprintf("; next_offset=%d", nextOffset))
	}
	if outputTruncated {
		sb.WriteString("; truncated=true")
	}
	sb.WriteString("]")
	if filter != "" || port > 0 {
		sb.WriteString(" (filtered)")
	}
	sb.WriteString("\n")

	result := sb.String()
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: result}},
	}, ProcListOutput{Result: result, Total: matchedCount, Returned: returned, HasMore: hasMore, NextOffset: nextOffset, Truncated: outputTruncated}, nil
}

func Register(server *mcp.Server) {
	common.SafeAddTool(server, &mcp.Tool{
		Name: "proclist",
		Description: `Lists running processes with PID, name, command line, and memory usage.
Sensitive information in command-line arguments (passwords, tokens) is automatically masked.
Use filter to search by process name, or port to find processes using a specific port.
Results are paged; continue with next_offset when has_more=true.`,
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
