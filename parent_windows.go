package main

import (
	"os"
	"time"

	"golang.org/x/sys/windows"
)

// monitorParent waits for the parent process to exit and then terminates this
// process. On Windows we try to acquire a SYNCHRONIZE handle upfront so that
// WaitForSingleObject can detect the exit instantly without polling.
//
// Why not just poll OpenProcess?  OpenProcess succeeds for an *exited* process
// as long as any other process (e.g. the parent's parent shell) still holds a
// handle to its process object.  That keeps isProcessAlive returning true
// indefinitely while the terminal session is open, so this server would never
// self-terminate.
func monitorParent() {
	ppid := os.Getppid()
	if ppid <= 0 {
		return
	}

	// Acquire a SYNCHRONIZE handle tied to the specific process object.
	// This is immune to PID recycling: even if the PID is reused later,
	// our handle still refers to the original parent process object.
	h, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(ppid))
	if err != nil {
		// No SYNCHRONIZE permission — fall back to polling with exit-code check.
		monitorParentPoll(ppid)
		return
	}
	defer windows.CloseHandle(h)

	// Block until the parent process terminates. Zero polling overhead.
	windows.WaitForSingleObject(h, windows.INFINITE)
	os.Exit(0)
}

// monitorParentPoll is a fallback for environments where SYNCHRONIZE is
// unavailable. Polls every 5 seconds and uses GetExitCodeProcess to
// distinguish a truly running process from an exited one whose object still
// exists in the kernel (e.g. parent shell holds a handle).
func monitorParentPoll(ppid int) {
	for {
		time.Sleep(5 * time.Second)
		if !isProcessAlive(ppid) {
			os.Exit(0)
		}
	}
}

// isProcessAlive returns true only if the process is still running.
// OpenProcess alone is not sufficient: it succeeds for exited processes whose
// objects are kept alive by other handle holders. GetExitCodeProcess with
// STILL_ACTIVE (259) is the authoritative check.
func isProcessAlive(pid int) bool {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)
	var exitCode uint32
	if err := windows.GetExitCodeProcess(h, &exitCode); err != nil {
		return false
	}
	return exitCode == 259 // STILL_ACTIVE
}
