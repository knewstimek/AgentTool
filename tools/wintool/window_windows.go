//go:build windows

package wintool

import (
	"fmt"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modUser32 = windows.NewLazySystemDLL("user32.dll")

	procEnumWindows              = modUser32.NewProc("EnumWindows")
	procEnumChildWindows         = modUser32.NewProc("EnumChildWindows")
	procGetWindowTextW           = modUser32.NewProc("GetWindowTextW")
	procGetWindowTextLengthW     = modUser32.NewProc("GetWindowTextLengthW")
	procGetClassNameW            = modUser32.NewProc("GetClassNameW")
	procGetWindowRect            = modUser32.NewProc("GetWindowRect")
	procGetClientRect            = modUser32.NewProc("GetClientRect")
	procGetWindowThreadProcessId = modUser32.NewProc("GetWindowThreadProcessId")
	procIsWindowVisible          = modUser32.NewProc("IsWindowVisible")
	procIsWindowEnabled          = modUser32.NewProc("IsWindowEnabled")
	procGetWindowLongPtrW        = modUser32.NewProc("GetWindowLongPtrW")
	procGetDlgCtrlID             = modUser32.NewProc("GetDlgCtrlID")
	procGetParent                = modUser32.NewProc("GetParent")
	procIsWindow                 = modUser32.NewProc("IsWindow")
)

// GWL_STYLE and GWL_EXSTYLE are negative indices; store as uintptr
// via two's complement to avoid constant overflow on Call().
var (
	gwlStyle   = ^uintptr(16 - 1) // -16 as uintptr
	gwlExStyle = ^uintptr(20 - 1) // -20 as uintptr
)

// RECT matches Win32 RECT structure.
type rect struct {
	Left, Top, Right, Bottom int32
}

// windowInfo holds information about a single window.
type windowInfo struct {
	HWND      uintptr
	PID       uint32
	Title     string
	ClassName string
	Rect      rect
	Visible   bool
	Enabled   bool
}

func isWindow(hwnd uintptr) bool {
	ret, _, _ := procIsWindow.Call(hwnd)
	return ret != 0
}

func getWindowText(hwnd uintptr) string {
	length, _, _ := procGetWindowTextLengthW.Call(hwnd)
	if length == 0 {
		return ""
	}
	buf := make([]uint16, length+1)
	procGetWindowTextW.Call(hwnd, uintptr(unsafe.Pointer(&buf[0])), length+1)
	return syscall.UTF16ToString(buf)
}

func getClassName(hwnd uintptr) string {
	buf := make([]uint16, 256)
	n, _, _ := procGetClassNameW.Call(hwnd, uintptr(unsafe.Pointer(&buf[0])), 256)
	if n == 0 {
		return ""
	}
	return syscall.UTF16ToString(buf[:n])
}

func getWindowRect(hwnd uintptr) rect {
	var r rect
	procGetWindowRect.Call(hwnd, uintptr(unsafe.Pointer(&r)))
	return r
}

func getClientRect(hwnd uintptr) rect {
	var r rect
	procGetClientRect.Call(hwnd, uintptr(unsafe.Pointer(&r)))
	return r
}

func getWindowPID(hwnd uintptr) uint32 {
	var pid uint32
	procGetWindowThreadProcessId.Call(hwnd, uintptr(unsafe.Pointer(&pid)))
	return pid
}

func isWindowVisible(hwnd uintptr) bool {
	ret, _, _ := procIsWindowVisible.Call(hwnd)
	return ret != 0
}

func isWindowEnabled(hwnd uintptr) bool {
	ret, _, _ := procIsWindowEnabled.Call(hwnd)
	return ret != 0
}

func getWindowStyle(hwnd uintptr) uint64 {
	ret, _, _ := procGetWindowLongPtrW.Call(hwnd, gwlStyle)
	return uint64(ret)
}

func getWindowExStyle(hwnd uintptr) uint64 {
	ret, _, _ := procGetWindowLongPtrW.Call(hwnd, gwlExStyle)
	return uint64(ret)
}

func getDlgCtrlID(hwnd uintptr) int {
	ret, _, _ := procGetDlgCtrlID.Call(hwnd)
	return int(ret)
}

func getParent(hwnd uintptr) uintptr {
	ret, _, _ := procGetParent.Call(hwnd)
	return ret
}

func getWindowInfo(hwnd uintptr) windowInfo {
	return windowInfo{
		HWND:      hwnd,
		PID:       getWindowPID(hwnd),
		Title:     getWindowText(hwnd),
		ClassName: getClassName(hwnd),
		Rect:      getWindowRect(hwnd),
		Visible:   isWindowVisible(hwnd),
		Enabled:   isWindowEnabled(hwnd),
	}
}

// enumWindows enumerates all top-level windows.
func enumWindows() []uintptr {
	var hwnds []uintptr
	cb := syscall.NewCallback(func(hwnd uintptr, lParam uintptr) uintptr {
		hwnds = append(hwnds, hwnd)
		return 1 // continue
	})
	procEnumWindows.Call(cb, 0)
	return hwnds
}

// enumChildWindows enumerates direct and indirect child windows.
// Limited to maxEnumChildren to prevent excessive memory allocation
// in complex UIs (browsers, etc.).
const maxEnumChildren = 10000

func enumChildWindows(parent uintptr) []uintptr {
	var children []uintptr
	cb := syscall.NewCallback(func(hwnd uintptr, lParam uintptr) uintptr {
		children = append(children, hwnd)
		if len(children) >= maxEnumChildren {
			return 0 // stop enumeration
		}
		return 1
	})
	procEnumChildWindows.Call(parent, cb, 0)
	return children
}

// opList lists all top-level windows.
func opList(input WintoolInput) (*CallResult, WintoolOutput, error) {
	hwnds := enumWindows()

	var sb strings.Builder
	count := 0
	for _, hwnd := range hwnds {
		info := getWindowInfo(hwnd)

		// Apply filters
		if input.PID != 0 && info.PID != uint32(input.PID) {
			continue
		}
		if input.Title != "" && !strings.Contains(strings.ToLower(info.Title), strings.ToLower(input.Title)) {
			continue
		}
		if input.Class != "" && !strings.Contains(strings.ToLower(info.ClassName), strings.ToLower(input.Class)) {
			continue
		}

		formatWindowLine(&sb, info)
		count++
		if count >= input.MaxResults {
			sb.WriteString(fmt.Sprintf("\n... truncated at %d results (use max_results to increase)\n", input.MaxResults))
			break
		}
	}

	if count == 0 {
		return successResult("No windows found matching the criteria.")
	}

	sb.WriteString(fmt.Sprintf("\nTotal: %d windows\n", count))
	return successResult(sb.String())
}

// opTree shows child/control tree for a window.
func opTree(input WintoolInput) (*CallResult, WintoolOutput, error) {
	hwnd, errResult, errOutput := requireHWND(input)
	if errResult != nil {
		return errResult, errOutput, nil
	}
	if !isWindow(hwnd) {
		return errorResult("hwnd 0x%X is not a valid window", hwnd)
	}

	var sb strings.Builder
	root := getWindowInfo(hwnd)
	sb.WriteString(fmt.Sprintf("Window 0x%X: %q [%s]\n", root.HWND, root.Title, root.ClassName))

	children := enumChildWindows(hwnd)
	count := 0
	for _, child := range children {
		if count >= input.MaxResults {
			sb.WriteString(fmt.Sprintf("... truncated at %d children\n", input.MaxResults))
			break
		}
		info := getWindowInfo(child)
		// Determine depth by walking parents
		depth := 0
		p := getParent(child)
		for p != 0 && p != hwnd {
			depth++
			p = getParent(p)
			if depth > 50 {
				break // safety: prevent infinite loop from circular parent chain
			}
		}
		indent := strings.Repeat("  ", depth+1)
		ctrlID := getDlgCtrlID(child)
		vis := ""
		if !info.Visible {
			vis = " [hidden]"
		}
		sb.WriteString(fmt.Sprintf("%s├─ 0x%X [%s] %q (id:%d, %dx%d)%s\n",
			indent, child, info.ClassName, info.Title,
			ctrlID,
			info.Rect.Right-info.Rect.Left, info.Rect.Bottom-info.Rect.Top,
			vis))
		count++
	}

	if len(children) == 0 {
		sb.WriteString("  (no child windows)\n")
	}
	return successResult(sb.String())
}

// opFind searches for windows by title/class/PID.
func opFind(input WintoolInput) (*CallResult, WintoolOutput, error) {
	if input.Title == "" && input.Class == "" && input.PID == 0 {
		return errorResult("find requires at least one of: title, class, pid")
	}

	hwnds := enumWindows()
	var sb strings.Builder
	count := 0
	for _, hwnd := range hwnds {
		info := getWindowInfo(hwnd)

		if input.PID != 0 && info.PID != uint32(input.PID) {
			continue
		}
		if input.Title != "" && !strings.Contains(strings.ToLower(info.Title), strings.ToLower(input.Title)) {
			continue
		}
		if input.Class != "" && !strings.Contains(strings.ToLower(info.ClassName), strings.ToLower(input.Class)) {
			continue
		}

		formatWindowLine(&sb, info)
		count++
		if count >= input.MaxResults {
			break
		}
	}

	if count == 0 {
		return successResult("No windows found matching the criteria.")
	}
	sb.WriteString(fmt.Sprintf("\nFound: %d windows\n", count))
	return successResult(sb.String())
}

// opInspect returns detailed info about a single window.
func opInspect(input WintoolInput) (*CallResult, WintoolOutput, error) {
	hwnd, errResult, errOutput := requireHWND(input)
	if errResult != nil {
		return errResult, errOutput, nil
	}
	if !isWindow(hwnd) {
		return errorResult("hwnd 0x%X is not a valid window", hwnd)
	}

	info := getWindowInfo(hwnd)
	r := info.Rect
	cr := getClientRect(hwnd)
	style := getWindowStyle(hwnd)
	exStyle := getWindowExStyle(hwnd)
	ctrlID := getDlgCtrlID(hwnd)
	parent := getParent(hwnd)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("HWND:      0x%X\n", hwnd))
	sb.WriteString(fmt.Sprintf("Title:     %q\n", info.Title))
	sb.WriteString(fmt.Sprintf("Class:     %s\n", info.ClassName))
	sb.WriteString(fmt.Sprintf("PID:       %d\n", info.PID))
	sb.WriteString(fmt.Sprintf("Visible:   %v\n", info.Visible))
	sb.WriteString(fmt.Sprintf("Enabled:   %v\n", info.Enabled))
	sb.WriteString(fmt.Sprintf("Rect:      (%d,%d)-(%d,%d) [%dx%d]\n",
		r.Left, r.Top, r.Right, r.Bottom, r.Right-r.Left, r.Bottom-r.Top))
	sb.WriteString(fmt.Sprintf("Client:    %dx%d\n", cr.Right, cr.Bottom))
	sb.WriteString(fmt.Sprintf("Style:     0x%08X\n", style))
	sb.WriteString(fmt.Sprintf("ExStyle:   0x%08X\n", exStyle))
	sb.WriteString(fmt.Sprintf("CtrlID:    %d\n", ctrlID))
	if parent != 0 {
		sb.WriteString(fmt.Sprintf("Parent:    0x%X\n", parent))
	}

	// Decode common styles
	sb.WriteString("\nStyles: ")
	decodeStyles(&sb, style, exStyle)

	children := enumChildWindows(hwnd)
	sb.WriteString(fmt.Sprintf("\nChildren:  %d\n", len(children)))

	return successResult(sb.String())
}

// formatWindowLine writes a single window's info to the builder.
func formatWindowLine(sb *strings.Builder, info windowInfo) {
	vis := "visible"
	if !info.Visible {
		vis = "hidden"
	}
	w := info.Rect.Right - info.Rect.Left
	h := info.Rect.Bottom - info.Rect.Top
	sb.WriteString(fmt.Sprintf("0x%X  pid:%-6d [%s] %dx%d %s  %q\n",
		info.HWND, info.PID, info.ClassName, w, h, vis, info.Title))
}

// decodeStyles writes human-readable style names.
func decodeStyles(sb *strings.Builder, style, exStyle uint64) {
	var styles []string

	// WS_ styles
	if style&0x10000000 != 0 {
		styles = append(styles, "WS_VISIBLE")
	}
	if style&0x20000000 != 0 {
		styles = append(styles, "WS_MINIMIZE")
	}
	if style&0x00800000 != 0 {
		styles = append(styles, "WS_BORDER")
	}
	if style&0x00C00000 != 0 {
		styles = append(styles, "WS_CAPTION")
	}
	if style&0x40000000 != 0 {
		styles = append(styles, "WS_CHILD")
	}
	if style&0x00080000 != 0 {
		styles = append(styles, "WS_SYSMENU")
	}
	if style&0x00040000 != 0 {
		styles = append(styles, "WS_THICKFRAME")
	}
	if style&0x01000000 != 0 {
		styles = append(styles, "WS_MAXIMIZE")
	}
	if style&0x00010000 != 0 {
		styles = append(styles, "WS_TABSTOP")
	}

	// WS_EX_ styles
	if exStyle&0x00000008 != 0 {
		styles = append(styles, "WS_EX_TOPMOST")
	}
	if exStyle&0x00000020 != 0 {
		styles = append(styles, "WS_EX_TRANSPARENT")
	}
	if exStyle&0x00040000 != 0 {
		styles = append(styles, "WS_EX_APPWINDOW")
	}
	if exStyle&0x00080000 != 0 {
		styles = append(styles, "WS_EX_LAYERED")
	}

	if len(styles) == 0 {
		sb.WriteString("(none decoded)")
	} else {
		sb.WriteString(strings.Join(styles, " | "))
	}
	sb.WriteString("\n")
}

