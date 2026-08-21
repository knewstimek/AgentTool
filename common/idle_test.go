package common

import (
	"sync/atomic"
	"testing"
	"time"
)

// The release must hold off while calls keep arriving, fire once the server
// goes quiet, and not fire again until there is something new to give back.
func TestIdleReleaseFollowsActivity(t *testing.T) {
	var releases atomic.Int32
	const idle = 200 * time.Millisecond

	startIdleRelease(idle, func() { releases.Add(1) })

	// Busy: activity every half-threshold must keep it from firing.
	for i := 0; i < 6; i++ {
		time.Sleep(idle / 2)
		MarkActivity()
	}
	if got := releases.Load(); got != 0 {
		t.Fatalf("released %d time(s) while the server was busy", got)
	}

	// Quiet: it fires once.
	time.Sleep(idle * 3)
	if got := releases.Load(); got != 1 {
		t.Fatalf("after going idle, released %d time(s), want 1", got)
	}

	// Still quiet: no repeat, because nothing new was allocated.
	time.Sleep(idle * 3)
	if got := releases.Load(); got != 1 {
		t.Fatalf("released again with no activity in between: %d", got)
	}

	// New work, then quiet again: fires a second time.
	MarkActivity()
	time.Sleep(idle * 3)
	if got := releases.Load(); got != 2 {
		t.Fatalf("after new activity and idling, released %d time(s), want 2", got)
	}
}

func TestIdleReleaseDisabled(t *testing.T) {
	var releases atomic.Int32
	startIdleRelease(0, func() { releases.Add(1) })
	time.Sleep(150 * time.Millisecond)
	if got := releases.Load(); got != 0 {
		t.Fatalf("a non-positive threshold must disable the watcher, got %d release(s)", got)
	}
}
