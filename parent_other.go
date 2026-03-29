//go:build !windows

package main

import "syscall"

// isProcessAlive checks if a process with the given PID is still running.
// On Unix, Signal(0) returns nil if the process exists.
func isProcessAlive(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil
}
