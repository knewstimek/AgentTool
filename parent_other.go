//go:build !windows

package main

import (
	"os"
	"syscall"
	"time"
)

// monitorParent polls every 5 seconds and exits if the parent is gone.
// On Unix, ppid == 1 means the process was reparented to init (already an
// orphan), so there is nothing useful to monitor.
func monitorParent() {
	ppid := os.Getppid()
	if ppid <= 1 {
		return
	}
	for {
		time.Sleep(5 * time.Second)
		if !isProcessAlive(ppid) {
			os.Exit(0)
		}
	}
}

// isProcessAlive uses Signal(0) to check liveness without sending a signal.
func isProcessAlive(pid int) bool {
	return syscall.Kill(pid, 0) == nil
}
