package main

import "golang.org/x/sys/windows"

// isProcessAlive checks if a process with the given PID is still running.
// Uses OpenProcess with PROCESS_QUERY_LIMITED_INFORMATION -- if the handle
// can't be opened, the process is dead.
func isProcessAlive(pid int) bool {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return false
	}
	windows.CloseHandle(h)
	return true
}
