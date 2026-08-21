package common

import (
	"runtime/debug"
	"sync/atomic"
	"time"
)

// IdleReleaseAfter is how long the server must go without a tool call before it
// hands its heap pages back to the OS.
const IdleReleaseAfter = 30 * time.Minute

var (
	lastActivity   atomic.Int64 // unix nanos of the most recent tool call
	pendingRelease atomic.Bool  // work has happened since the last release
)

// MarkActivity records that a tool call ran. Called from the single place every
// tool invocation passes through.
func MarkActivity() {
	lastActivity.Store(time.Now().UnixNano())
	pendingRelease.Store(true)
}

// StartIdleMemoryRelease returns heap pages to the OS once the server has been
// idle for `after`.
//
// A stdio MCP server cannot tell an abandoned client from a quiet one. The
// process that spawned it may be alive, finished with it forever, and still
// holding the pipe open -- no EOF ever arrives, so exiting on a guess would
// kill a session that merely paused. Handing the memory back is the safe half
// of that trade: nothing the client can observe changes, open shell and ssh
// sessions survive, and a server that once read a large file stops holding
// ~150MB for the rest of the machine's uptime.
//
// Go will not do this on its own. A full GC leaves the resident size where it
// was -- the spans are free but still mapped -- and only debug.FreeOSMemory
// decommits them. It stops the world, which is why it runs only after the
// server has gone quiet: there is nobody waiting on the pause, and the next
// request arrives to a small heap.
func StartIdleMemoryRelease(after time.Duration) {
	startIdleRelease(after, debug.FreeOSMemory)
}

// startIdleRelease is StartIdleMemoryRelease with the release action injected,
// so the timing rules can be tested without measuring resident memory.
func startIdleRelease(after time.Duration, release func()) {
	if after <= 0 {
		return
	}
	MarkActivity()

	go func() {
		// A fraction of the threshold, so the release lands near the moment the
		// server actually went quiet rather than a whole period later. The floor
		// only guards against a microscopic threshold; it must stay well under
		// any real one, or the release arrives a whole floor-period late.
		interval := after / 4
		if interval < 50*time.Millisecond {
			interval = 50 * time.Millisecond
		}
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for range ticker.C {
			if !pendingRelease.Load() {
				continue // nothing new to give back since the last release
			}
			if time.Since(time.Unix(0, lastActivity.Load())) < after {
				continue
			}
			// Cleared first: a call landing during the release marks it again,
			// so its allocations are not mistaken for already-released ones.
			pendingRelease.Store(false)
			release()
		}
	}()
}
