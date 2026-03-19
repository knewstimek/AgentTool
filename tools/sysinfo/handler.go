package sysinfo

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"time"

	"agent-tool/common"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type SysInfoInput struct {
	DurationSec int `json:"duration_sec" jsonschema:"Measurement duration in seconds (0=snapshot, max 20). CPU usage requires duration >= 1."`
}

type SysInfoOutput struct {
	Result string `json:"result"`
}

func Handle(ctx context.Context, req *mcp.CallToolRequest, input SysInfoInput) (*mcp.CallToolResult, SysInfoOutput, error) {
	if input.DurationSec < 0 {
		input.DurationSec = 0
	}
	if input.DurationSec > 20 {
		input.DurationSec = 20
	}

	var sb strings.Builder
	sb.WriteString("=== System Information ===\n\n")

	// OS / Arch
	sb.WriteString(fmt.Sprintf("OS: %s/%s\n", runtime.GOOS, runtime.GOARCH))
	sb.WriteString(fmt.Sprintf("CPU cores: %d (logical)\n", runtime.NumCPU()))

	// Memory info
	memTotal, memAvail, err := getMemoryInfo()
	if err == nil {
		sb.WriteString(fmt.Sprintf("RAM total: %s\n", formatBytes(memTotal)))
		sb.WriteString(fmt.Sprintf("RAM available: %s (%.1f%% free)\n",
			formatBytes(memAvail), float64(memAvail)/float64(memTotal)*100))
	}

	// Disk info
	disks, err := getDiskInfo()
	if err == nil && len(disks) > 0 {
		sb.WriteString("\nDisk:\n")
		for _, d := range disks {
			sb.WriteString(fmt.Sprintf("  %s: %s total, %s free (%.1f%% free)\n",
				d.Path, formatBytes(d.Total), formatBytes(d.Free),
				float64(d.Free)/float64(d.Total)*100))
		}
	}

	// Measure CPU usage (when duration_sec > 0)
	if input.DurationSec >= 1 {
		duration := time.Duration(input.DurationSec) * time.Second
		cpuPercent, err := measureCPU(duration)
		if err == nil {
			sb.WriteString(fmt.Sprintf("\nCPU usage: %.1f%% (measured over %ds)\n", cpuPercent, input.DurationSec))
		}
	}

	// Hostname
	hostname := getHostname()
	if hostname != "" {
		sb.WriteString(fmt.Sprintf("\nHostname: %s\n", hostname))
	}

	// Uptime
	uptime, err := getUptime()
	if err == nil {
		sb.WriteString(fmt.Sprintf("Uptime: %s\n", formatDuration(uptime)))
		// Calculate boot time
		bootTime := time.Now().Add(-uptime)
		sb.WriteString(fmt.Sprintf("Boot time: %s\n", bootTime.Format("2006-01-02 15:04:05")))
	}

	// Timezone
	zone, offset := time.Now().Zone()
	sb.WriteString(fmt.Sprintf("\nTimezone: %s (UTC%+d)\n", zone, offset/3600))

	// System locale/language
	locale := getLocale()
	if locale != "" {
		sb.WriteString(fmt.Sprintf("Locale: %s\n", locale))
	}

	// Go runtime version
	sb.WriteString(fmt.Sprintf("Go runtime: %s\n", runtime.Version()))

	result := sb.String()
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: result}},
	}, SysInfoOutput{Result: result}, nil
}

func Register(server *mcp.Server) {
	common.SafeAddTool(server, &mcp.Tool{
		Name:        "sysinfo",
		Description: "Returns system information: OS, CPU cores, RAM, disk space, CPU usage. Set duration_sec (1-20) to measure CPU usage over time.",
	}, Handle)
}

// DiskInfo represents disk usage information.
type DiskInfo struct {
	Path  string
	Total uint64
	Free  uint64
}

func formatBytes(b uint64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
		TB = GB * 1024
	)
	switch {
	case b >= TB:
		return fmt.Sprintf("%.1f TB", float64(b)/float64(TB))
	case b >= GB:
		return fmt.Sprintf("%.1f GB", float64(b)/float64(GB))
	case b >= MB:
		return fmt.Sprintf("%.1f MB", float64(b)/float64(MB))
	case b >= KB:
		return fmt.Sprintf("%.1f KB", float64(b)/float64(KB))
	default:
		return fmt.Sprintf("%d B", b)
	}
}

func formatDuration(d time.Duration) string {
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	mins := int(d.Minutes()) % 60
	if days > 0 {
		return fmt.Sprintf("%dd %dh %dm", days, hours, mins)
	}
	return fmt.Sprintf("%dh %dm", hours, mins)
}

func getHostname() string {
	name, err := getHostnameOS()
	if err != nil {
		return ""
	}
	return name
}
