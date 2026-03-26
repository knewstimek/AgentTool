package wintool

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"agent-tool/common"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// WintoolInput defines the parameters for the wintool MCP tool.
type WintoolInput struct {
	Operation string `json:"operation" jsonschema:"Operation: list, tree, find, inspect, screenshot, gettext, settext, click, type, send, show, move, close, focus,required"`

	// Target window (hex string, e.g. "0x1A2B3C")
	HWND string `json:"hwnd,omitempty" jsonschema:"Window handle in hex (e.g. '0x1A2B3C'). Required for most operations except list/find"`

	// find/list filters
	Title string `json:"title,omitempty" jsonschema:"Window title substring to search for (case-insensitive)"`
	Class string `json:"class,omitempty" jsonschema:"Window class name to search for"`
	PID   int    `json:"pid,omitempty" jsonschema:"Filter by process ID"`

	// click
	X      int    `json:"x,omitempty" jsonschema:"X coordinate (client-relative) for click"`
	Y      int    `json:"y,omitempty" jsonschema:"Y coordinate (client-relative) for click"`
	Button string `json:"button,omitempty" jsonschema:"Mouse button: left (default), right, middle. For click"`

	// type / settext / gettext
	Text string `json:"text,omitempty" jsonschema:"Text for type/settext operations"`

	// send (raw SendMessage/PostMessage)
	Msg    uint32 `json:"msg,omitempty" jsonschema:"Window message ID (e.g. 16 for WM_CLOSE, 274 for WM_SYSCOMMAND). For send"`
	WParam uint64 `json:"wparam,omitempty" jsonschema:"WPARAM value for send operation"`
	LParam int64  `json:"lparam,omitempty" jsonschema:"LPARAM value for send operation"`
	Post   bool   `json:"post,omitempty" jsonschema:"Use PostMessage instead of SendMessage (async). Default: false"`

	// show
	ShowCmd string `json:"show_cmd,omitempty" jsonschema:"Show command: show, hide, minimize, maximize, restore. For show"`

	// move
	MoveX  int `json:"move_x,omitempty" jsonschema:"New X position for move"`
	MoveY  int `json:"move_y,omitempty" jsonschema:"New Y position for move"`
	Width  int `json:"width,omitempty" jsonschema:"New width for move (0 = keep current)"`
	Height int `json:"height,omitempty" jsonschema:"New height for move (0 = keep current)"`

	// limits
	MaxResults int `json:"max_results,omitempty" jsonschema:"Maximum number of results. Default: 100, Max: 1000"`

	// screenshot / clipboard
	SavePath string `json:"save_path,omitempty" jsonschema:"Save image to this path instead of returning base64. For screenshot/clipboard"`
}

// WintoolOutput is the MCP output type.
type WintoolOutput struct {
	Result string `json:"result"`
}

var validOps = map[string]bool{
	"list": true, "tree": true, "find": true, "inspect": true,
	"screenshot": true, "clipboard": true, "gettext": true, "settext": true,
	"click": true, "type": true, "send": true,
	"show": true, "move": true, "close": true, "focus": true,
}

// Handle is the MCP tool handler entry point.
func Handle(ctx context.Context, req *mcp.CallToolRequest, input WintoolInput) (*mcp.CallToolResult, WintoolOutput, error) {
	op := strings.ToLower(strings.TrimSpace(input.Operation))
	if !validOps[op] {
		return errorResult("invalid operation %q (use: list, tree, find, inspect, screenshot, clipboard, gettext, settext, click, type, send, show, move, close, focus)", op)
	}

	if input.PID < 0 {
		return errorResult("pid must be a positive integer")
	}

	if input.MaxResults <= 0 {
		input.MaxResults = 100
	}
	if input.MaxResults > 1000 {
		input.MaxResults = 1000
	}

	switch op {
	case "list":
		return opList(input)
	case "tree":
		return opTree(input)
	case "find":
		return opFind(input)
	case "inspect":
		return opInspect(input)
	case "screenshot":
		return opScreenshot(input)
	case "clipboard":
		return opClipboard(input)
	case "gettext":
		return opGettext(input)
	case "settext":
		return opSettext(input)
	case "click":
		return opClick(input)
	case "type":
		return opType(input)
	case "send":
		return opSend(input)
	case "show":
		return opShow(input)
	case "move":
		return opMove(input)
	case "close":
		return opClose(input)
	case "focus":
		return opFocus(input)
	default:
		return errorResult("unhandled operation: %s", op)
	}
}

// Register adds the wintool to the MCP server.
func Register(server *mcp.Server) {
	common.SafeAddTool(server, &mcp.Tool{
		Name: "wintool",
		Description: `Windows GUI automation tool for finding, inspecting, and controlling windows.
Find windows by title/class/PID, enumerate child controls, capture screenshots (base64 PNG),
read clipboard images, read/set text, click, type, send raw messages, show/hide/minimize/maximize, move/resize, close, focus.
Windows only. macOS and Linux are not supported.
Operations: list, tree, find, inspect, screenshot, clipboard, gettext, settext, click, type, send, show, move, close, focus.
clipboard: reads image from system clipboard and saves as PNG temp file. Use after Win+Shift+S or Copy.
type: sends keyboard input. Auto-detects console windows (ConsoleWindowClass) and uses WriteConsoleInput.
Tip: type + send(msg=WM_KEYDOWN, wparam=VK_RETURN) can inject commands into other terminal/IDE sessions. Works with Electron (VSCode) too.`,
	}, Handle)
}

// parseHWND parses a hex HWND string like "0x1A2B" or "1A2B" to uintptr.
func parseHWND(s string) (uintptr, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("hwnd is required for this operation")
	}
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	v, err := strconv.ParseUint(s, 16, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid hwnd %q: %w", s, err)
	}
	if v == 0 {
		return 0, fmt.Errorf("hwnd cannot be zero")
	}
	return uintptr(v), nil
}

// requireHWND is a helper that parses HWND from input or returns an error result.
func requireHWND(input WintoolInput) (uintptr, *mcp.CallToolResult, WintoolOutput) {
	hwnd, err := parseHWND(input.HWND)
	if err != nil {
		r, o, _ := errorResult("%v", err)
		return 0, r, o
	}
	return hwnd, nil, WintoolOutput{}
}

// CallResult is an alias used across platform files to avoid importing mcp directly.
type CallResult = mcp.CallToolResult

func successResult(msg string) (*mcp.CallToolResult, WintoolOutput, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
	}, WintoolOutput{Result: msg}, nil
}

func errorResult(format string, args ...any) (*mcp.CallToolResult, WintoolOutput, error) {
	msg := fmt.Sprintf(format, args...)
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		IsError: true,
	}, WintoolOutput{Result: msg}, nil
}

// resolveSavePath validates and resolves save_path for screenshot/clipboard.
// Returns the resolved absolute path to write to.
// "temp" creates a temp file with the given prefix; absolute paths are validated
// against dangerous/reserved paths (same checks as delete/rename/mkdir).
func resolveSavePath(savePath, tempPrefix string) (string, error) {
	if strings.EqualFold(savePath, "temp") {
		tmpFile, err := os.CreateTemp("", tempPrefix)
		if err != nil {
			return "", fmt.Errorf("failed to create temp file: %w", err)
		}
		tmpFile.Close()
		return tmpFile.Name(), nil
	}
	cleaned := filepath.Clean(savePath)
	if !filepath.IsAbs(cleaned) {
		return "", fmt.Errorf("save_path must be an absolute path or \"temp\"")
	}
	if err := common.CheckDangerousPath(cleaned); err != nil {
		return "", err
	}
	if err := common.CheckWindowsReserved(cleaned); err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(cleaned), 0755); err != nil {
		return "", fmt.Errorf("failed to create directory: %w", err)
	}
	return cleaned, nil
}
