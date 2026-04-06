package prockill

import (
	"context"
	"fmt"
	"os"
	"strings"

	"agent-tool/common"
	"agent-tool/tools/proclist"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type ProcKillInput struct {
	PID            int    `json:"pid,omitempty" jsonschema:"Process ID to kill"`
	Port           int    `json:"port,omitempty" jsonschema:"Kill process(es) using this port number"`
	Signal         string `json:"signal,omitempty" jsonschema:"Signal to send: kill (default), term, hup, int, stop (suspend), cont (resume). Windows uses NtSuspendProcess/NtResumeProcess for stop/cont"`
	Tree           interface{} `json:"tree,omitempty" jsonschema:"Kill the process and all its child processes (tree kill): true or false. Default: false"`
	IncludeZombies interface{} `json:"include_zombies,omitempty" jsonschema:"Linux only: send SIGCHLD to parent of zombie processes to trigger reaping: true or false. Default: false"`
	DryRun         interface{} `json:"dry_run,omitempty" jsonschema:"Preview which processes would be killed without actually killing them: true or false. Default: false"`
}

type ProcKillOutput struct {
	Result string `json:"result"`
}

func Handle(ctx context.Context, req *mcp.CallToolRequest, input ProcKillInput) (*mcp.CallToolResult, ProcKillOutput, error) {
	dryRun := common.FlexBool(input.DryRun)
	tree := common.FlexBool(input.Tree)
	includeZombies := common.FlexBool(input.IncludeZombies)

	// 1. Validate input
	if input.PID == 0 && input.Port == 0 {
		return errorResult("pid or port is required")
	}
	if input.PID < 0 {
		return errorResult("invalid pid: must be a positive integer")
	}
	if input.PID != 0 && input.Port != 0 {
		return errorResult("specify either pid or port, not both")
	}
	if input.Port < 0 || input.Port > 65535 {
		return errorResult("invalid port: must be 1-65535")
	}

	// Normalize signal
	input.Signal = strings.ToLower(strings.TrimSpace(input.Signal))
	if input.Signal == "" {
		input.Signal = "kill"
	}
	switch input.Signal {
	case "kill", "term", "hup", "int", "stop", "cont":
		// valid
	default:
		return errorResult("invalid signal: must be kill, term, hup, int, stop, or cont")
	}

	// 2. Resolve port → PIDs
	var targetPIDs []int
	if input.Port > 0 {
		entries, err := proclist.ListPortPIDs()
		if err != nil {
			return errorResult(fmt.Sprintf("failed to query port mappings: %v", err))
		}
		seen := map[int]bool{}
		for _, e := range entries {
			if e.Port == input.Port && !seen[e.PID] && e.PID > 0 {
				seen[e.PID] = true
				targetPIDs = append(targetPIDs, e.PID)
			}
		}
		if len(targetPIDs) == 0 {
			return errorResult(fmt.Sprintf("no process found using port %d", input.Port))
		}
	} else {
		targetPIDs = []int{input.PID}
	}

	// 3. Safety checks
	myPID := os.Getpid()
	for _, pid := range targetPIDs {
		if pid <= 1 {
			return errorResult(fmt.Sprintf("refusing to kill PID %d (system process)", pid))
		}
		if pid == myPID {
			return errorResult("refusing to kill self (agent-tool process)")
		}
	}

	// 4. Collect target info for display
	var sb strings.Builder
	sb.WriteString("=== Process Kill ===\n")

	if dryRun {
		switch input.Signal {
		case "stop":
			sb.WriteString("[dry_run] Would suspend the following processes:\n\n")
		case "cont":
			sb.WriteString("[dry_run] Would resume the following processes:\n\n")
		default:
			sb.WriteString("[dry_run] Would kill the following processes:\n\n")
		}
	}

	// Build full target list (with children if tree mode)
	type killTarget struct {
		pid      int
		isChild  bool
		parentID int
	}
	var targets []killTarget

	for _, pid := range targetPIDs {
		targets = append(targets, killTarget{pid: pid})
		if tree {
			for _, child := range getDescendants(pid) {
				if child != pid {
					targets = append(targets, killTarget{pid: child, isChild: true, parentID: pid})
				}
			}
		}
	}

	// Show target info
	sb.WriteString(fmt.Sprintf("  %-8s %-24s %-12s %s\n", "PID", "NAME", "MEM", "INFO"))
	sb.WriteString(strings.Repeat("-", 72) + "\n")

	for _, t := range targets {
		details, err := getProcessDetails(t.pid)
		name := "?"
		mem := "-"
		info := ""
		if err == nil {
			name = details.Name
			mem = formatMemKB(details.MemKB)
			if details.CmdLine != "" {
				info = proclist.SanitizeCommandLine(details.CmdLine)
				if len(info) > 120 {
					info = info[:117] + "..."
				}
			}
		}
		if t.isChild {
			info = fmt.Sprintf("(child of %d) %s", t.parentID, info)
		}
		sb.WriteString(fmt.Sprintf("  %-8d %-24s %-12s %s\n", t.pid, truncate(name, 24), mem, info))
	}

	if dryRun {
		dryVerb := "killed"
		if input.Signal == "stop" {
			dryVerb = "suspended"
		} else if input.Signal == "cont" {
			dryVerb = "resumed"
		}
		sb.WriteString(fmt.Sprintf("\nTotal: %d processes would be %s\n", len(targets), dryVerb))
		result := sb.String()
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: result}},
		}, ProcKillOutput{Result: result}, nil
	}

	// 5. Execute
	sb.WriteString("\n")
	killedCount := 0
	failedCount := 0

	// Determine action verb for output messages
	actionVerb := "killed"
	if input.Signal == "stop" {
		actionVerb = "suspended"
	} else if input.Signal == "cont" {
		actionVerb = "resumed"
	}

	isSuspendResume := input.Signal == "stop" || input.Signal == "cont"

	if tree && !isSuspendResume {
		for _, pid := range targetPIDs {
			killed, failed := killTreePlatform(pid, input.Signal)
			for _, kpid := range killed {
				sb.WriteString(fmt.Sprintf("  OK  PID %d %s\n", kpid, actionVerb))
				killedCount++
			}
			for fpid, ferr := range failed {
				sb.WriteString(fmt.Sprintf("  ERR PID %d — %v\n", fpid, ferr))
				failedCount++
			}
		}
	} else if tree && isSuspendResume {
		// Suspend/resume tree: apply to all descendants
		for _, pid := range targetPIDs {
			descendants := getDescendants(pid)
			for _, dpid := range descendants {
				if dpid <= 1 || dpid == myPID {
					continue
				}
				var err error
				if input.Signal == "stop" {
					err = suspendProcess(dpid)
				} else {
					err = resumeProcess(dpid)
				}
				if err != nil {
					sb.WriteString(fmt.Sprintf("  ERR PID %d — %v\n", dpid, err))
					failedCount++
				} else {
					sb.WriteString(fmt.Sprintf("  OK  PID %d %s\n", dpid, actionVerb))
					killedCount++
				}
			}
		}
	} else if isSuspendResume {
		for _, pid := range targetPIDs {
			var err error
			if input.Signal == "stop" {
				err = suspendProcess(pid)
			} else {
				err = resumeProcess(pid)
			}
			if err != nil {
				sb.WriteString(fmt.Sprintf("  ERR PID %d — %v\n", pid, err))
				failedCount++
			} else {
				sb.WriteString(fmt.Sprintf("  OK  PID %d %s\n", pid, actionVerb))
				killedCount++
			}
		}
	} else {
		for _, pid := range targetPIDs {
			if err := killSingle(pid, input.Signal); err != nil {
				sb.WriteString(fmt.Sprintf("  ERR PID %d — %v\n", pid, err))
				failedCount++
			} else {
				sb.WriteString(fmt.Sprintf("  OK  PID %d %s\n", pid, actionVerb))
				killedCount++
			}
		}
	}

	// 6. Zombie handling (Linux only)
	if includeZombies {
		for _, pid := range targetPIDs {
			report := handleZombies(pid)
			if report != "" {
				sb.WriteString("\n" + report)
			}
		}
	}

	sb.WriteString(fmt.Sprintf("\nResult: %d %s, %d failed\n", killedCount, actionVerb, failedCount))

	result := sb.String()
	isError := failedCount > 0 && killedCount == 0
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: result}},
		IsError: isError,
	}, ProcKillOutput{Result: result}, nil
}

func Register(server *mcp.Server) {
	common.SafeAddTool(server, &mcp.Tool{
		Name: "prockill",
		Description: `Kills, suspends, or resumes a process by PID or port number.
Supports tree kill (process + all children), signal selection (kill/term/hup/int/stop/cont).
Use signal=stop to suspend and signal=cont to resume a process.
On Linux, can detect and handle zombie processes by signaling their parent.
Use dry_run=true to preview which processes would be affected.
Safety: refuses to target PID 0/1 or the agent-tool process itself.`,
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

func errorResult(msg string) (*mcp.CallToolResult, ProcKillOutput, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		IsError: true,
	}, ProcKillOutput{Result: msg}, nil
}
