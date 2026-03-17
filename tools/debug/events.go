package debug

import (
	"encoding/json"
	"sync"
	"time"

	"github.com/google/go-dap"
)

const maxEventBufferSize = 100

// dapEvent represents a buffered DAP event for polling by the AI agent.
type dapEvent struct {
	Type      string    `json:"type"`
	Body      string    `json:"body"` // JSON-encoded event body
	Timestamp time.Time `json:"timestamp"`
}

// eventBuffer is a ring buffer that stores recent DAP events.
type eventBuffer struct {
	mu     sync.Mutex
	events []dapEvent
	cursor int // next read position for polling
}

func newEventBuffer() *eventBuffer {
	return &eventBuffer{
		events: make([]dapEvent, 0, maxEventBufferSize),
	}
}

// push adds an event to the buffer, evicting the oldest if full.
func (b *eventBuffer) push(evt dapEvent) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if len(b.events) >= maxEventBufferSize {
		// Shift: remove oldest, append new
		copy(b.events, b.events[1:])
		b.events[len(b.events)-1] = evt
		// Adjust cursor so drain() doesn't skip the newly pushed event
		if b.cursor > 0 {
			b.cursor--
		}
	} else {
		b.events = append(b.events, evt)
	}
}

// drain returns all events since the last drain call and advances the cursor.
func (b *eventBuffer) drain() []dapEvent {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.cursor >= len(b.events) {
		return nil
	}

	result := make([]dapEvent, len(b.events)-b.cursor)
	copy(result, b.events[b.cursor:])
	b.cursor = len(b.events)
	return result
}

// all returns all buffered events without advancing the cursor.
func (b *eventBuffer) all() []dapEvent {
	b.mu.Lock()
	defer b.mu.Unlock()

	result := make([]dapEvent, len(b.events))
	copy(result, b.events)
	return result
}

// eventLoop reads DAP messages from the adapter and dispatches them:
// - Response messages are delivered to the pending request channel via dapClient
// - Event messages are stored in the event buffer and, for specific events
//   (stopped, terminated, exited), signaled via dedicated channels.
//
// This goroutine runs for the lifetime of the debug session and exits when
// the connection is closed or the session's done channel is closed.
func (s *debugSession) eventLoop() {
	defer func() {
		s.mu.Lock()
		s.state = "terminated"
		s.mu.Unlock()
		// Signal anyone waiting on stopped
		s.signalStopped(nil)
	}()

	for {
		msg, err := s.client.readMessage()
		if err != nil {
			// Connection closed or broken — exit loop.
			// The done channel close in session.close() triggers the reader
			// error by closing the underlying pipe/conn, so no separate
			// done check is needed. This avoids a busy-spin if the reader
			// ever returns (0, nil) on a broken connection.
			return
		}

		// Check if it's a response (has request_seq)
		reqSeq := getResponseRequestSeq(msg)
		if reqSeq >= 0 {
			s.client.deliverResponse(msg, reqSeq)
			continue
		}

		// Check if it's a standard reverse request (adapter → client).
		// DAP defines runInTerminal and startDebugging as reverse requests.
		// go-dap parses these as normal Request types, but the adapter
		// expects a response. Without one, the adapter hangs forever.
		if handled := s.client.handleStandardReverseRequest(msg); handled {
			continue
		}

		// It's an event — buffer it
		evt := classifyEvent(msg)
		s.events.push(evt)

		// Update session state for specific events
		switch msg.(type) {
		case *dap.InitializedEvent:
			// Signal that adapter is ready for configuration requests.
			// close() is idempotent-safe: only the first close matters;
			// subsequent InitializedEvents (shouldn't happen per spec) are ignored.
			select {
			case <-s.initializedCh:
				// already closed
			default:
				close(s.initializedCh)
			}

		case *dap.StoppedEvent:
			s.mu.Lock()
			s.state = "stopped"
			if se, ok := msg.(*dap.StoppedEvent); ok {
				s.lastStoppedTID = se.Body.ThreadId
			}
			s.mu.Unlock()
			s.signalStopped(msg)

		case *dap.ContinuedEvent:
			s.mu.Lock()
			s.state = "running"
			s.mu.Unlock()

		case *dap.TerminatedEvent:
			s.mu.Lock()
			s.state = "terminated"
			s.mu.Unlock()
			return

		case *dap.ExitedEvent:
			s.mu.Lock()
			s.state = "exited"
			s.mu.Unlock()
		}
	}
}

// signalStopped sends a signal to anyone waiting for a stopped event
// (e.g., continue/next/step operations that block until breakpoint hit).
func (s *debugSession) signalStopped(msg dap.Message) {
	select {
	case s.stoppedCh <- msg:
	default:
		// No one waiting — that's fine
	}
}

// classifyEvent converts a DAP event message into a dapEvent for buffering.
func classifyEvent(msg dap.Message) dapEvent {
	var eventType string
	switch msg.(type) {
	case *dap.StoppedEvent:
		eventType = "stopped"
	case *dap.ContinuedEvent:
		eventType = "continued"
	case *dap.OutputEvent:
		eventType = "output"
	case *dap.TerminatedEvent:
		eventType = "terminated"
	case *dap.ExitedEvent:
		eventType = "exited"
	case *dap.ThreadEvent:
		eventType = "thread"
	case *dap.BreakpointEvent:
		eventType = "breakpoint"
	case *dap.ModuleEvent:
		eventType = "module"
	case *dap.LoadedSourceEvent:
		eventType = "loadedSource"
	case *dap.ProcessEvent:
		eventType = "process"
	case *dap.CapabilitiesEvent:
		eventType = "capabilities"
	case *dap.InitializedEvent:
		eventType = "initialized"
	default:
		eventType = "unknown"
	}

	body, _ := json.Marshal(msg)

	return dapEvent{
		Type:      eventType,
		Body:      string(body),
		Timestamp: time.Now(),
	}
}
