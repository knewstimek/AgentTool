//go:build windows

package wintool

import (
	"fmt"
	"strings"
	"sync"
	"syscall"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	procSendMessageW        = modUser32.NewProc("SendMessageW")
	procPostMessageW        = modUser32.NewProc("PostMessageW")
	procSetForegroundWindow = modUser32.NewProc("SetForegroundWindow")
	procShowWindow          = modUser32.NewProc("ShowWindow")
	procMoveWindow          = modUser32.NewProc("MoveWindow")

	procGetWindowThreadProcessId2 = modUser32.NewProc("GetWindowThreadProcessId")
	procAttachConsole             = modKernel32.NewProc("AttachConsole")
	procFreeConsole               = modKernel32.NewProc("FreeConsole")
	procWriteConsoleInputW        = modKernel32.NewProc("WriteConsoleInputW")
	procGetConsoleWindow          = modKernel32.NewProc("GetConsoleWindow")
)

// consoleMu protects AttachConsole/FreeConsole which are process-global.
// Only one goroutine can attach to a console at a time.
var consoleMu sync.Mutex

// Common window message constants.
const (
	wmClose        = 0x0010
	wmGettext      = 0x000D
	wmGettextLength = 0x000E
	wmSettext      = 0x000C
	wmChar         = 0x0102
	wmLButtonDown  = 0x0201
	wmLButtonUp    = 0x0202
	wmRButtonDown  = 0x0204
	wmRButtonUp    = 0x0205
	wmMButtonDown  = 0x0207
	wmMButtonUp    = 0x0208

	wmQuit     = 0x0012
	wmCopyData = 0x004A
	wmEndSession = 0x0016

	mkLButton = 0x0001
	mkRButton = 0x0002
	mkMButton = 0x0010

	swHide     = 0
	swShow     = 5
	swMinimize = 6
	swMaximize = 3
	swRestore  = 9
)

// blockedMessages contains message IDs that could crash the target process
// or cause system instability when sent with arbitrary parameters.
var blockedMessages = map[uint32]string{
	wmQuit:       "WM_QUIT",
	wmCopyData:   "WM_COPYDATA",   // requires valid pointer in lParam
	wmEndSession: "WM_ENDSESSION", // can force-terminate target
}

func sendMessage(hwnd uintptr, msg uint32, wParam uintptr, lParam uintptr) uintptr {
	ret, _, _ := procSendMessageW.Call(hwnd, uintptr(msg), wParam, lParam)
	return ret
}

func postMessage(hwnd uintptr, msg uint32, wParam uintptr, lParam uintptr) error {
	ret, _, err := procPostMessageW.Call(hwnd, uintptr(msg), wParam, lParam)
	if ret == 0 {
		return fmt.Errorf("PostMessage failed: %v", err)
	}
	return nil
}

func makeLParam(x, y int) uintptr {
	// MAKELPARAM: low word = x, high word = y (both as uint16)
	return uintptr(uint32(uint16(y))<<16 | uint32(uint16(x)))
}

// opGettext reads text from a window/control via WM_GETTEXT.
func opGettext(input WintoolInput) (*CallResult, WintoolOutput, error) {
	hwnd, errResult, errOutput := requireHWND(input)
	if errResult != nil {
		return errResult, errOutput, nil
	}
	if !isWindow(hwnd) {
		return errorResult("hwnd 0x%X is not a valid window", hwnd)
	}

	// Standard WM_GETTEXTLENGTH / WM_GETTEXT pattern.
	// WM_GETTEXT respects the buffer size in wParam, so truncation
	// may occur if text changes between calls, but no overflow.
	length := sendMessage(hwnd, wmGettextLength, 0, 0)
	if length == 0 {
		return successResult("(empty)")
	}

	// Cap at 64KB to prevent excessive allocation
	if length > 65536 {
		length = 65536
	}

	buf := make([]uint16, length+1)
	sendMessage(hwnd, wmGettext, length+1, uintptr(unsafe.Pointer(&buf[0])))
	text := syscall.UTF16ToString(buf)

	return successResult(text)
}

// opSettext sets text on a window/control via WM_SETTEXT.
func opSettext(input WintoolInput) (*CallResult, WintoolOutput, error) {
	hwnd, errResult, errOutput := requireHWND(input)
	if errResult != nil {
		return errResult, errOutput, nil
	}
	if !isWindow(hwnd) {
		return errorResult("hwnd 0x%X is not a valid window", hwnd)
	}

	textPtr, err := windows.UTF16PtrFromString(input.Text)
	if err != nil {
		return errorResult("invalid text: %v", err)
	}

	sendMessage(hwnd, wmSettext, 0, uintptr(unsafe.Pointer(textPtr)))
	return successResult(fmt.Sprintf("Text set on 0x%X", hwnd))
}

// opClick sends a mouse click at client-relative coordinates.
func opClick(input WintoolInput) (*CallResult, WintoolOutput, error) {
	hwnd, errResult, errOutput := requireHWND(input)
	if errResult != nil {
		return errResult, errOutput, nil
	}
	if !isWindow(hwnd) {
		return errorResult("hwnd 0x%X is not a valid window", hwnd)
	}

	if input.X < 0 || input.Y < 0 {
		return errorResult("click coordinates must be non-negative (got %d,%d)", input.X, input.Y)
	}

	lParam := makeLParam(input.X, input.Y)

	button := strings.ToLower(strings.TrimSpace(input.Button))
	if button == "" {
		button = "left"
	}

	var downMsg, upMsg uint32
	var wParam uintptr
	switch button {
	case "left":
		downMsg, upMsg, wParam = wmLButtonDown, wmLButtonUp, mkLButton
	case "right":
		downMsg, upMsg, wParam = wmRButtonDown, wmRButtonUp, mkRButton
	case "middle":
		downMsg, upMsg, wParam = wmMButtonDown, wmMButtonUp, mkMButton
	default:
		return errorResult("invalid button %q (use: left, right, middle)", button)
	}

	sendMessage(hwnd, downMsg, wParam, lParam)
	sendMessage(hwnd, upMsg, 0, lParam)

	return successResult(fmt.Sprintf("Clicked %s at (%d,%d) on 0x%X", button, input.X, input.Y, hwnd))
}

// opType sends keyboard characters via WM_CHAR, or WriteConsoleInput for console windows.
func opType(input WintoolInput) (*CallResult, WintoolOutput, error) {
	hwnd, errResult, errOutput := requireHWND(input)
	if errResult != nil {
		return errResult, errOutput, nil
	}
	if !isWindow(hwnd) {
		return errorResult("hwnd 0x%X is not a valid window", hwnd)
	}
	if input.Text == "" {
		return errorResult("text is required for type operation")
	}

	// Console windows (cmd.exe, PowerShell) need WriteConsoleInput
	// because they read from the console input buffer, not WM_CHAR.
	className := getClassName(hwnd)
	if className == "ConsoleWindowClass" {
		return typeConsole(hwnd, input.Text)
	}

	// Regular GUI windows: WM_CHAR with UTF-16 encoding.
	// BMP-outside characters (emoji, etc.) sent as surrogate pairs.
	utf16Chars := utf16.Encode([]rune(input.Text))
	for _, ch := range utf16Chars {
		sendMessage(hwnd, wmChar, uintptr(ch), 0)
	}

	return successResult(fmt.Sprintf("Typed %d characters on 0x%X", len(utf16Chars), hwnd))
}

// KEY_EVENT_RECORD for WriteConsoleInput.
// https://learn.microsoft.com/en-us/windows/console/key-event-record-str
type keyEventRecord struct {
	EventType uint16
	_         uint16 // padding
	KeyDown   int32
	RepeatCnt uint16
	VKeyCode  uint16
	VScanCode uint16
	UChar     uint16 // wchar
	CtrlState uint32
}

const (
	keyEvent = 0x0001
)

// typeConsole types text into a console window via WriteConsoleInput.
// Attaches to the console of the target process, writes key events, then detaches.
// Uses mutex because AttachConsole/FreeConsole are process-global (one console at a time).
func typeConsole(hwnd uintptr, text string) (*CallResult, WintoolOutput, error) {
	consoleMu.Lock()
	defer consoleMu.Unlock()

	// Get the PID of the console window's process
	var pid uint32
	procGetWindowThreadProcessId2.Call(hwnd, uintptr(unsafe.Pointer(&pid)))
	if pid == 0 {
		return errorResult("failed to get PID for console window 0x%X", hwnd)
	}

	// Remember if we had our own console, so we can restore it after.
	// MCP servers typically run without a console (pipe-based stdio),
	// but when run from a terminal (debugging), we need to restore it.
	hadConsole, _, _ := procGetConsoleWindow.Call()

	// Detach from our own console (if any), attach to target's console
	procFreeConsole.Call()
	ret, _, err := procAttachConsole.Call(uintptr(pid))
	if ret == 0 {
		// Restore our own console on failure
		if hadConsole != 0 {
			const attachParentProcess = ^uintptr(1 - 1) // (DWORD)-1
			procAttachConsole.Call(attachParentProcess)
		}
		return errorResult("AttachConsole(%d) failed: %v", pid, err)
	}
	defer func() {
		procFreeConsole.Call()
		// Restore our own console
		if hadConsole != 0 {
			const attachParentProcess = ^uintptr(1 - 1) // (DWORD)-1
			procAttachConsole.Call(attachParentProcess)
		}
	}()

	// Open the console input buffer directly via CONIN$.
	// GetStdHandle won't work here because MCP servers use pipe-based stdio,
	// and AttachConsole doesn't change the existing standard handles.
	conin, _ := syscall.UTF16PtrFromString("CONIN$")
	hInput, err2 := syscall.CreateFile(
		conin,
		syscall.GENERIC_READ|syscall.GENERIC_WRITE,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE,
		nil, syscall.OPEN_EXISTING, 0, 0,
	)
	if err2 != nil {
		return errorResult("CreateFile(CONIN$) failed for PID %d: %v", pid, err2)
	}
	defer syscall.CloseHandle(hInput)

	// Build KEY_EVENT_RECORD pairs (key down + key up) for each character
	utf16Chars := utf16.Encode([]rune(text))
	events := make([]keyEventRecord, 0, len(utf16Chars)*2)
	for _, ch := range utf16Chars {
		events = append(events, keyEventRecord{
			EventType: keyEvent,
			KeyDown:   1,
			RepeatCnt: 1,
			UChar:     ch,
		})
		events = append(events, keyEventRecord{
			EventType: keyEvent,
			KeyDown:   0,
			RepeatCnt: 1,
			UChar:     ch,
		})
	}

	var written uint32
	ret, _, err = procWriteConsoleInputW.Call(
		uintptr(hInput),
		uintptr(unsafe.Pointer(&events[0])),
		uintptr(len(events)),
		uintptr(unsafe.Pointer(&written)),
	)
	if ret == 0 {
		return errorResult("WriteConsoleInput failed: %v", err)
	}

	return successResult(fmt.Sprintf("Typed %d characters to console (PID %d, 0x%X) via WriteConsoleInput", len(utf16Chars), pid, hwnd))
}

// opSend sends a raw SendMessage/PostMessage.
func opSend(input WintoolInput) (*CallResult, WintoolOutput, error) {
	hwnd, errResult, errOutput := requireHWND(input)
	if errResult != nil {
		return errResult, errOutput, nil
	}
	if !isWindow(hwnd) {
		return errorResult("hwnd 0x%X is not a valid window", hwnd)
	}
	if input.Msg == 0 {
		return errorResult("msg is required for send operation (e.g. 16 for WM_CLOSE)")
	}

	// Block messages that can crash target processes or cause system instability
	if name, blocked := blockedMessages[input.Msg]; blocked {
		return errorResult("%s (0x%X) is blocked for safety", name, input.Msg)
	}

	if input.Post {
		err := postMessage(hwnd, input.Msg, uintptr(input.WParam), uintptr(input.LParam))
		if err != nil {
			return errorResult("PostMessage(0x%X, 0x%X): %v", hwnd, input.Msg, err)
		}
		return successResult(fmt.Sprintf("PostMessage(0x%X, msg=0x%X, wParam=0x%X, lParam=0x%X) sent",
			hwnd, input.Msg, input.WParam, input.LParam))
	}

	ret := sendMessage(hwnd, input.Msg, uintptr(input.WParam), uintptr(input.LParam))
	return successResult(fmt.Sprintf("SendMessage(0x%X, msg=0x%X, wParam=0x%X, lParam=0x%X) returned 0x%X",
		hwnd, input.Msg, input.WParam, input.LParam, ret))
}

// opShow changes window show state (minimize/maximize/restore/hide/show).
func opShow(input WintoolInput) (*CallResult, WintoolOutput, error) {
	hwnd, errResult, errOutput := requireHWND(input)
	if errResult != nil {
		return errResult, errOutput, nil
	}
	if !isWindow(hwnd) {
		return errorResult("hwnd 0x%X is not a valid window", hwnd)
	}

	cmd := strings.ToLower(strings.TrimSpace(input.ShowCmd))
	if cmd == "" {
		cmd = "show"
	}

	var sw int
	switch cmd {
	case "show":
		sw = swShow
	case "hide":
		sw = swHide
	case "minimize", "min":
		sw = swMinimize
	case "maximize", "max":
		sw = swMaximize
	case "restore":
		sw = swRestore
	default:
		return errorResult("invalid show_cmd %q (use: show, hide, minimize, maximize, restore)", cmd)
	}

	procShowWindow.Call(hwnd, uintptr(sw))
	return successResult(fmt.Sprintf("ShowWindow(0x%X, %s)", hwnd, cmd))
}

// opMove moves and/or resizes a window.
func opMove(input WintoolInput) (*CallResult, WintoolOutput, error) {
	hwnd, errResult, errOutput := requireHWND(input)
	if errResult != nil {
		return errResult, errOutput, nil
	}
	if !isWindow(hwnd) {
		return errorResult("hwnd 0x%X is not a valid window", hwnd)
	}

	// If width/height are 0, keep current size
	w := input.Width
	h := input.Height
	if w == 0 || h == 0 {
		r := getWindowRect(hwnd)
		if w == 0 {
			w = int(r.Right - r.Left)
		}
		if h == 0 {
			h = int(r.Bottom - r.Top)
		}
	}

	if w <= 0 || h <= 0 {
		return errorResult("width and height must be positive (got %dx%d)", w, h)
	}

	ret, _, err := procMoveWindow.Call(hwnd,
		uintptr(input.MoveX), uintptr(input.MoveY),
		uintptr(w), uintptr(h),
		1) // bRepaint = TRUE
	if ret == 0 {
		return errorResult("MoveWindow failed: %v", err)
	}

	return successResult(fmt.Sprintf("Moved 0x%X to (%d,%d) size %dx%d", hwnd, input.MoveX, input.MoveY, w, h))
}

// opClose sends WM_CLOSE to the window.
func opClose(input WintoolInput) (*CallResult, WintoolOutput, error) {
	hwnd, errResult, errOutput := requireHWND(input)
	if errResult != nil {
		return errResult, errOutput, nil
	}
	if !isWindow(hwnd) {
		return errorResult("hwnd 0x%X is not a valid window", hwnd)
	}

	sendMessage(hwnd, wmClose, 0, 0)
	return successResult(fmt.Sprintf("WM_CLOSE sent to 0x%X", hwnd))
}

// opFocus brings a window to the foreground.
func opFocus(input WintoolInput) (*CallResult, WintoolOutput, error) {
	hwnd, errResult, errOutput := requireHWND(input)
	if errResult != nil {
		return errResult, errOutput, nil
	}
	if !isWindow(hwnd) {
		return errorResult("hwnd 0x%X is not a valid window", hwnd)
	}

	ret, _, _ := procSetForegroundWindow.Call(hwnd)
	if ret == 0 {
		// SetForegroundWindow can fail if calling process is not foreground.
		// Show the window as a fallback.
		procShowWindow.Call(hwnd, uintptr(swRestore))
		ret, _, _ = procSetForegroundWindow.Call(hwnd)
		if ret == 0 {
			return successResult(fmt.Sprintf("SetForegroundWindow(0x%X) may not have succeeded (caller is not foreground process)", hwnd))
		}
	}

	return successResult(fmt.Sprintf("Focused 0x%X", hwnd))
}
