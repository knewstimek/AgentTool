package debug

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/go-dap"
)

const defaultTimeout = 30 * time.Second
const maxTimeout = 120 * time.Second
const handshakeTimeout = 5 * time.Second // fast-fail for initialize/launch/attach

// buildInitializeArgs creates DAP initialize arguments that match VS Code's
// capability set. Some adapters (vsdbg) fingerprint these fields to verify
// the client is a genuine VS Code instance and reject connections with
// minimal capabilities.
func buildInitializeArgs(clientID, clientName, adapterID string) dap.InitializeRequestArguments {
	return dap.InitializeRequestArguments{
		ClientID:                      clientID,
		ClientName:                    clientName,
		AdapterID:                     adapterID,
		PathFormat:                    "path",
		Locale:                        "en",
		LinesStartAt1:                 true,
		ColumnsStartAt1:               true,
		SupportsVariableType:          true,
		SupportsRunInTerminalRequest:  true,
		SupportsProgressReporting:     true,
		SupportsInvalidatedEvent:      true,
		SupportsMemoryReferences:      true,
		SupportsMemoryEvent:           true,
		SupportsStartDebuggingRequest: true,
	}
}

// resolveTimeout clamps the user-provided timeout to [default, max] range.
func resolveTimeout(timeoutSec int) time.Duration {
	if timeoutSec <= 0 {
		return defaultTimeout
	}
	d := time.Duration(timeoutSec) * time.Second
	if d > maxTimeout {
		d = maxTimeout
	}
	return d
}

// opLaunch starts a debug adapter and performs the initialize → launch handshake.
// Two modes:
//   - Spawn mode (adapter_command): starts adapter as child process, scans stdout for TCP port
//   - TCP mode (address): connects to an already-running adapter (e.g. debugpy.adapter)
func opLaunch(input DebugInput) (string, error) {
	if input.AdapterCommand == "" && input.Address == "" {
		return "", fmt.Errorf("adapter_command or address is required for launch")
	}

	id := input.SessionID
	if id == "" {
		id = fmt.Sprintf("debug-%d", time.Now().UnixNano())
	}

	// Check if session already exists
	if _, ok := pool.get(id); ok {
		return "", fmt.Errorf("session %q already exists", id)
	}

	var session *debugSession
	var err error

	if input.Address != "" {
		// TCP mode: connect to an already-running adapter (e.g. debugpy.adapter --port 5679)
		session, err = createTCPSession(id, input.Address)
	} else {
		// Spawn mode: start adapter process and detect TCP port from stdout
		var adapterCwd string
		if input.LaunchArgs != "" {
			var peekArgs map[string]interface{}
			if json.Unmarshal([]byte(input.LaunchArgs), &peekArgs) == nil {
				if cwd, ok := peekArgs["cwd"].(string); ok {
					adapterCwd = cwd
				}
			}
		}
		session, err = createStdioSession(id, input.AdapterCommand, input.AdapterArgs, adapterCwd)
	}
	if err != nil {
		return "", err
	}

	session.launchMode = true

	// Register session in pool
	if err := pool.add(session); err != nil {
		session.close()
		return "", err
	}

	// initialize uses a short timeout (adapter should respond instantly).
	// launch/configurationDone use user timeout since launch may trigger a build.
	timeout := resolveTimeout(input.TimeoutSec)

	// Step 1: initialize
	initReq := &dap.InitializeRequest{}
	initReq.Seq = session.client.nextSeq()
	// Resolve DAP initialize parameters with priority chain:
	//   dedicated param (input.ClientID) → __ meta field → default
	// "type" in launch_args → AdapterID (some adapters like vsdbg require exact ID e.g. "cppvsdbg").
	// clientID matters for licensing (vsdbg checks it to enforce VS Code-only).
	adapterID := strings.TrimSuffix(filepath.Base(input.AdapterCommand), filepath.Ext(input.AdapterCommand))
	clientID := "agent-tool"
	clientName := "agent-tool MCP debug client"
	if input.LaunchArgs != "" {
		var peek map[string]interface{}
		if json.Unmarshal([]byte(input.LaunchArgs), &peek) == nil {
			if t, ok := peek["type"].(string); ok && t != "" {
				adapterID = t
			}
			if c, ok := peek["__clientID"].(string); ok && c != "" {
				clientID = c
			}
			if c, ok := peek["__clientName"].(string); ok && c != "" {
				clientName = c
			}
		}
	}
	// Dedicated params take highest priority (override __ meta fields)
	if input.ClientID != "" {
		clientID = input.ClientID
	}
	if input.ClientName != "" {
		clientName = input.ClientName
	}
	initReq.Arguments = buildInitializeArgs(clientID, clientName, adapterID)

	resp, err := session.client.sendRequest(initReq, handshakeTimeout)
	if err != nil {
		pool.remove(id)
		return "", fmt.Errorf("initialize failed: %w", err)
	}

	if ok, msg := isResponseSuccess(resp); !ok {
		pool.remove(id)
		return "", fmt.Errorf("initialize rejected by adapter: %s (hint: set \"type\" in launch_args to the adapter's expected ID, e.g. \"type\":\"cppvsdbg\" for vsdbg)", msg)
	}
	if initResp, ok := resp.(*dap.InitializeResponse); ok {
		session.capabilities = initResp.Body
	}

	// Note: initialized event may arrive before or after launch response
	// (DAP spec allows both). We wait for it in sendConfigurationDoneIfNeeded
	// which runs before the first continue/step.

	// Step 2: launch
	launchArgs := make(map[string]interface{})
	if input.LaunchArgs != "" {
		if err := json.Unmarshal([]byte(input.LaunchArgs), &launchArgs); err != nil {
			pool.remove(id)
			return "", fmt.Errorf("invalid launch_args JSON: %w", err)
		}
	}

	// Strip meta fields (__ prefix) consumed by the tool, not the adapter.
	for k := range launchArgs {
		if strings.HasPrefix(k, "__") {
			delete(launchArgs, k)
		}
	}

	launchArgsJSON, _ := json.Marshal(launchArgs)
	launchReq := &dap.LaunchRequest{}
	launchReq.Seq = session.client.nextSeq()
	launchReq.Arguments = launchArgsJSON

	// Send launch request asynchronously. Some adapters (dlv) respond immediately,
	// while others (debugpy) defer the response until after configurationDone.
	// We wait for either: (1) an error response, (2) the initialized event, or (3) timeout.
	respCh, cleanup, err := session.client.sendRequestAsync(launchReq)
	if err != nil {
		pool.remove(id)
		return "", fmt.Errorf("launch failed: %w", err)
	}
	defer cleanup()

	select {
	case resp := <-respCh:
		// Got a response — check if it's an error
		if ok, msg := isResponseSuccess(resp); !ok {
			pool.remove(id)
			return "", fmt.Errorf("launch failed: %s", msg)
		}
		// Success response — adapter didn't defer. Continue.
	case <-session.initializedCh:
		// Adapter sent initialized event before launch response (debugpy behavior).
		// Launch is proceeding; response will arrive after configurationDone.
	case <-time.After(timeout):
		pool.remove(id)
		return "", fmt.Errorf("launch timed out: no response or initialized event within %v", timeout)
	}

	// Do NOT send configurationDone yet — the caller must set breakpoints first,
	// then call continue which will send configurationDone automatically.
	session.mu.Lock()
	session.state = "stopped"
	session.mu.Unlock()

	adapterInfo := input.AdapterCommand
	if adapterInfo == "" {
		adapterInfo = input.Address
	}
	return fmt.Sprintf("Session started.\nSession ID: %s\nAdapter: %s\nState: stopped (awaiting configuration)\n\nUse operation=set_breakpoints to set breakpoints, then operation=continue to start execution.", id, adapterInfo), nil
}

// opAttach connects to a running debug adapter over TCP and performs
// the initialize → attach → configurationDone handshake.
func opAttach(input DebugInput) (string, error) {
	if input.Address == "" {
		return "", fmt.Errorf("address (host:port) is required for attach")
	}

	id := input.SessionID
	if id == "" {
		id = fmt.Sprintf("debug-%d", time.Now().UnixNano())
	}

	if _, ok := pool.get(id); ok {
		return "", fmt.Errorf("session %q already exists", id)
	}

	session, err := createTCPSession(id, input.Address)
	if err != nil {
		return "", err
	}

	if err := pool.add(session); err != nil {
		session.close()
		return "", err
	}

	timeout := resolveTimeout(input.TimeoutSec)

	// Step 1: initialize (same priority chain as opLaunch)
	adapterID := "tcp"
	clientID := "agent-tool"
	clientName := "agent-tool MCP debug client"
	if input.LaunchArgs != "" {
		var peek map[string]interface{}
		if json.Unmarshal([]byte(input.LaunchArgs), &peek) == nil {
			if t, ok := peek["type"].(string); ok && t != "" {
				adapterID = t
			}
			if c, ok := peek["__clientID"].(string); ok && c != "" {
				clientID = c
			}
			if c, ok := peek["__clientName"].(string); ok && c != "" {
				clientName = c
			}
		}
	}
	// Dedicated params take highest priority
	if input.ClientID != "" {
		clientID = input.ClientID
	}
	if input.ClientName != "" {
		clientName = input.ClientName
	}

	initReq := &dap.InitializeRequest{}
	initReq.Seq = session.client.nextSeq()
	initReq.Arguments = buildInitializeArgs(clientID, clientName, adapterID)

	resp, err := session.client.sendRequest(initReq, handshakeTimeout)
	if err != nil {
		pool.remove(id)
		return "", fmt.Errorf("initialize failed: %w", err)
	}

	if ok, msg := isResponseSuccess(resp); !ok {
		pool.remove(id)
		return "", fmt.Errorf("initialize rejected by adapter: %s", msg)
	}
	if initResp, ok := resp.(*dap.InitializeResponse); ok {
		session.capabilities = initResp.Body
	}

	// Step 2: attach
	attachArgs := make(map[string]interface{})
	if input.LaunchArgs != "" {
		if err := json.Unmarshal([]byte(input.LaunchArgs), &attachArgs); err != nil {
			pool.remove(id)
			return "", fmt.Errorf("invalid launch_args JSON: %w", err)
		}
	}

	// Strip meta fields (__ prefix) consumed by the tool, not the adapter.
	for k := range attachArgs {
		if strings.HasPrefix(k, "__") {
			delete(attachArgs, k)
		}
	}

	attachArgsJSON, _ := json.Marshal(attachArgs)
	attachReq := &dap.AttachRequest{}
	attachReq.Seq = session.client.nextSeq()
	attachReq.Arguments = attachArgsJSON

	// Same async pattern as launch — adapter may defer response until configurationDone.
	respCh, cleanup, err := session.client.sendRequestAsync(attachReq)
	if err != nil {
		pool.remove(id)
		return "", fmt.Errorf("attach failed: %w", err)
	}
	defer cleanup()

	select {
	case resp := <-respCh:
		if ok, msg := isResponseSuccess(resp); !ok {
			pool.remove(id)
			return "", fmt.Errorf("attach failed: %s", msg)
		}
	case <-session.initializedCh:
		// Adapter ready for configuration before attach response — that's fine.
	case <-time.After(timeout):
		pool.remove(id)
		return "", fmt.Errorf("attach timed out: no response or initialized event within %v", timeout)
	}

	session.mu.Lock()
	session.state = "stopped"
	session.mu.Unlock()

	return fmt.Sprintf("Attached to debug adapter.\nSession ID: %s\nAddress: %s\nState: stopped (awaiting configuration)\n\nUse operation=set_breakpoints to set breakpoints, then operation=continue to start execution.", id, input.Address), nil
}

// opSetBreakpoints sets breakpoints for a source file.
func opSetBreakpoints(session *debugSession, input DebugInput) (string, error) {
	if input.SourcePath == "" {
		return "", fmt.Errorf("source_path is required for set_breakpoints")
	}

	timeout := resolveTimeout(input.TimeoutSec)

	// Parse breakpoints JSON
	var bps []breakpointSpec
	if input.Breakpoints != "" {
		if err := json.Unmarshal(normalizeBPJSON([]byte(input.Breakpoints)), &bps); err != nil {
			return "", fmt.Errorf("invalid breakpoints JSON: %w", err)
		}
	}

	// Build DAP breakpoint request
	req := &dap.SetBreakpointsRequest{}
	req.Seq = session.client.nextSeq()
	req.Arguments = dap.SetBreakpointsArguments{
		Source: dap.Source{
			Path: input.SourcePath,
		},
	}

	dapBPs := make([]dap.SourceBreakpoint, len(bps))
	for i, bp := range bps {
		dapBPs[i] = dap.SourceBreakpoint{
			Line:      bp.Line,
			Condition: bp.Condition,
			HitCondition: bp.HitCondition,
			LogMessage:   bp.LogMessage,
		}
	}
	req.Arguments.Breakpoints = dapBPs

	resp, err := session.client.sendRequest(req, timeout)
	if err != nil {
		return "", fmt.Errorf("setBreakpoints failed: %w", err)
	}

	if ok, msg := isResponseSuccess(resp); !ok {
		return "", fmt.Errorf("setBreakpoints failed: %s", msg)
	}

	// Format result
	bpResp, ok := resp.(*dap.SetBreakpointsResponse)
	if !ok {
		return "Breakpoints set (no detailed response)", nil
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Breakpoints set for %s:\n", input.SourcePath))
	for i, bp := range bpResp.Body.Breakpoints {
		verified := "unverified"
		if bp.Verified {
			verified = "verified"
		}
		// DAP spec: Line is optional in response. Fall back to requested line.
		line := bp.Line
		if line == 0 && i < len(bps) {
			line = bps[i].Line
		}
		sb.WriteString(fmt.Sprintf("  Line %d: %s", line, verified))
		if bp.Message != "" {
			sb.WriteString(fmt.Sprintf(" (%s)", bp.Message))
		}
		sb.WriteString("\n")
	}
	return sb.String(), nil
}

// sendConfigurationDoneIfNeeded sends configurationDone the first time it's called.
// DAP requires breakpoints to be set between initialized and configurationDone,
// so we defer configurationDone until the first continue/step call.
// Also sends setExceptionBreakpoints (required by DAP spec during configuration phase).
func sendConfigurationDoneIfNeeded(session *debugSession, timeout time.Duration) error {
	// Mark configDone atomically to prevent double-send when two goroutines
	// call continue/step concurrently (TOCTOU fix).
	session.mu.Lock()
	if session.configDone {
		session.mu.Unlock()
		return nil
	}
	session.configDone = true
	session.mu.Unlock()

	// DAP spec: configuration requests are only valid after the initialized event.
	// Some adapters send it right after initialize response (dlv), others after
	// launch/attach response (debugpy). Wait here to handle both.
	select {
	case <-session.initializedCh:
	case <-time.After(handshakeTimeout):
		// Rollback on failure so caller can retry
		session.mu.Lock()
		session.configDone = false
		session.mu.Unlock()
		return fmt.Errorf("adapter did not send initialized event within %v", handshakeTimeout)
	}

	// DAP spec: setExceptionBreakpoints must be sent during configuration,
	// even if empty. Some adapters (e.g. debugpy) require this.
	exBpReq := &dap.SetExceptionBreakpointsRequest{}
	exBpReq.Seq = session.client.nextSeq()
	exBpReq.Arguments = dap.SetExceptionBreakpointsArguments{
		Filters: []string{},
	}
	if _, err := session.client.sendRequest(exBpReq, timeout); err != nil {
		session.mu.Lock()
		session.configDone = false
		session.mu.Unlock()
		return fmt.Errorf("setExceptionBreakpoints failed: %w", err)
	}

	cfgReq := &dap.ConfigurationDoneRequest{}
	cfgReq.Seq = session.client.nextSeq()

	_, err := session.client.sendRequest(cfgReq, timeout)
	if err != nil {
		session.mu.Lock()
		session.configDone = false
		session.mu.Unlock()
		return fmt.Errorf("configurationDone failed: %w", err)
	}

	return nil
}

// opContinue resumes execution and waits for a stopped event.
func opContinue(session *debugSession, input DebugInput) (string, error) {
	if err := checkSessionAlive(session); err != nil {
		return "", err
	}

	timeout := resolveTimeout(input.TimeoutSec)
	threadID := resolveThreadID(session, input.ThreadID)

	// Drain stale stopped event to avoid receiving a previous stop
	select {
	case <-session.stoppedCh:
	default:
	}

	session.mu.Lock()
	needsConfigDone := !session.configDone
	session.mu.Unlock()

	// Send configurationDone on first continue (starts program execution).
	// After configurationDone the program is already running — do NOT send
	// a ContinueRequest, just wait for the first breakpoint hit.
	if needsConfigDone {
		if err := sendConfigurationDoneIfNeeded(session, timeout); err != nil {
			return "", err
		}

		session.mu.Lock()
		session.state = "running"
		session.mu.Unlock()

		return waitForStopped(session, timeout)
	}

	// Normal continue: program is stopped, resume it
	session.mu.Lock()
	session.state = "running"
	session.mu.Unlock()

	req := &dap.ContinueRequest{}
	req.Seq = session.client.nextSeq()
	req.Arguments = dap.ContinueArguments{
		ThreadId: threadID,
	}

	_, err := session.client.sendRequest(req, timeout)
	if err != nil {
		return "", err
	}

	return waitForStopped(session, timeout)
}

// opNext performs a single step (line-level).
func opNext(session *debugSession, input DebugInput) (string, error) {
	return stepOperation(session, input, "next")
}

// opStepIn steps into a function call.
func opStepIn(session *debugSession, input DebugInput) (string, error) {
	return stepOperation(session, input, "stepIn")
}

// opStepOut steps out of the current function.
func opStepOut(session *debugSession, input DebugInput) (string, error) {
	return stepOperation(session, input, "stepOut")
}

// stepOperation handles next/stepIn/stepOut which all follow the same pattern.
func stepOperation(session *debugSession, input DebugInput, kind string) (string, error) {
	if err := checkSessionAlive(session); err != nil {
		return "", err
	}

	timeout := resolveTimeout(input.TimeoutSec)
	threadID := resolveThreadID(session, input.ThreadID)

	// Drain stale stopped event to avoid receiving a previous stop
	select {
	case <-session.stoppedCh:
	default:
	}

	session.mu.Lock()
	needsConfigDone := !session.configDone
	session.mu.Unlock()

	if needsConfigDone {
		if err := sendConfigurationDoneIfNeeded(session, timeout); err != nil {
			return "", err
		}
		session.mu.Lock()
		session.state = "running"
		session.mu.Unlock()
		return waitForStopped(session, timeout)
	}

	session.mu.Lock()
	session.state = "running"
	session.mu.Unlock()

	var req dap.Message
	switch kind {
	case "next":
		r := &dap.NextRequest{}
		r.Seq = session.client.nextSeq()
		r.Arguments = dap.NextArguments{ThreadId: threadID}
		req = r
	case "stepIn":
		r := &dap.StepInRequest{}
		r.Seq = session.client.nextSeq()
		r.Arguments = dap.StepInArguments{ThreadId: threadID}
		req = r
	case "stepOut":
		r := &dap.StepOutRequest{}
		r.Seq = session.client.nextSeq()
		r.Arguments = dap.StepOutArguments{ThreadId: threadID}
		req = r
	}

	_, err := session.client.sendRequest(req, timeout)
	if err != nil {
		return "", err
	}

	return waitForStopped(session, timeout)
}

// waitForStopped blocks until a stopped event arrives or timeout.
func waitForStopped(session *debugSession, timeout time.Duration) (string, error) {
	select {
	case msg := <-session.stoppedCh:
		if msg == nil {
			return "Session terminated while waiting for stopped event", nil
		}
		if evt, ok := msg.(*dap.StoppedEvent); ok {
			return formatStoppedEvent(evt), nil
		}
		return "Stopped (details unavailable)", nil
	case <-session.done:
		// Session was closed (adapter crash, disconnect, etc.)
		return "Session terminated while waiting for stopped event. Use operation=status for details.", nil
	case <-time.After(timeout):
		return "Program is still running (no breakpoint hit within timeout). Use operation=status to check later.", nil
	}
}

// opPause pauses execution.
func opPause(session *debugSession, input DebugInput) (string, error) {
	if err := checkSessionAlive(session); err != nil {
		return "", err
	}
	timeout := resolveTimeout(input.TimeoutSec)
	threadID := resolveThreadID(session, input.ThreadID)

	// Drain stale stopped event
	select {
	case <-session.stoppedCh:
	default:
	}

	req := &dap.PauseRequest{}
	req.Seq = session.client.nextSeq()
	req.Arguments = dap.PauseArguments{ThreadId: threadID}

	_, err := session.client.sendRequest(req, timeout)
	if err != nil {
		return "", fmt.Errorf("pause failed: %w", err)
	}

	return waitForStopped(session, timeout)
}

// opThreads lists all threads.
func opThreads(session *debugSession, input DebugInput) (string, error) {
	timeout := resolveTimeout(input.TimeoutSec)

	req := &dap.ThreadsRequest{}
	req.Seq = session.client.nextSeq()

	resp, err := session.client.sendRequest(req, timeout)
	if err != nil {
		return "", fmt.Errorf("threads failed: %w", err)
	}

	threadsResp, ok := resp.(*dap.ThreadsResponse)
	if !ok {
		return "Threads response unavailable", nil
	}

	var sb strings.Builder
	sb.WriteString("Threads:\n")
	for _, t := range threadsResp.Body.Threads {
		sb.WriteString(fmt.Sprintf("  [%d] %s\n", t.Id, t.Name))
	}
	return sb.String(), nil
}

// opStackTrace returns the call stack for a thread.
func opStackTrace(session *debugSession, input DebugInput) (string, error) {
	timeout := resolveTimeout(input.TimeoutSec)
	threadID := resolveThreadID(session, input.ThreadID)

	req := &dap.StackTraceRequest{}
	req.Seq = session.client.nextSeq()
	req.Arguments = dap.StackTraceArguments{
		ThreadId: threadID,
		Levels:   50, // reasonable max
	}

	resp, err := session.client.sendRequest(req, timeout)
	if err != nil {
		return "", fmt.Errorf("stackTrace failed: %w", err)
	}

	stResp, ok := resp.(*dap.StackTraceResponse)
	if !ok {
		return "StackTrace response unavailable", nil
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Stack Trace (thread %d, %d frames):\n", threadID, stResp.Body.TotalFrames))
	for i, frame := range stResp.Body.StackFrames {
		source := "(unknown)"
		if frame.Source != nil {
			source = frame.Source.Path
			if source == "" {
				source = frame.Source.Name
			}
		}
		line := fmt.Sprintf("  #%d [ID:%d] %s at %s:%d", i, frame.Id, frame.Name, source, frame.Line)
		if frame.InstructionPointerReference != "" {
			line += fmt.Sprintf(" (pc:%s)", frame.InstructionPointerReference)
		}
		sb.WriteString(line + "\n")
	}
	return sb.String(), nil
}

// opScopes returns the scopes for a stack frame.
func opScopes(session *debugSession, input DebugInput) (string, error) {
	timeout := resolveTimeout(input.TimeoutSec)

	// FrameID 0 is valid in DAP (first frame), so no zero-check here.
	// The caller should obtain frame IDs from stack_trace results.
	req := &dap.ScopesRequest{}
	req.Seq = session.client.nextSeq()
	req.Arguments = dap.ScopesArguments{
		FrameId: input.FrameID,
	}

	resp, err := session.client.sendRequest(req, timeout)
	if err != nil {
		return "", fmt.Errorf("scopes failed: %w", err)
	}

	scopesResp, ok := resp.(*dap.ScopesResponse)
	if !ok {
		return "Scopes response unavailable", nil
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Scopes (frame %d):\n", input.FrameID))
	for _, scope := range scopesResp.Body.Scopes {
		expensive := ""
		if scope.Expensive {
			expensive = " [expensive]"
		}
		sb.WriteString(fmt.Sprintf("  %s (ref:%d, vars:%d)%s\n", scope.Name, scope.VariablesReference, scope.NamedVariables, expensive))
	}
	return sb.String(), nil
}

// opVariables returns variables for a given reference.
func opVariables(session *debugSession, input DebugInput) (string, error) {
	timeout := resolveTimeout(input.TimeoutSec)

	if input.VariablesReference == 0 {
		return "", fmt.Errorf("variables_reference is required for variables")
	}

	req := &dap.VariablesRequest{}
	req.Seq = session.client.nextSeq()
	req.Arguments = dap.VariablesArguments{
		VariablesReference: input.VariablesReference,
	}

	resp, err := session.client.sendRequest(req, timeout)
	if err != nil {
		return "", fmt.Errorf("variables failed: %w", err)
	}

	varsResp, ok := resp.(*dap.VariablesResponse)
	if !ok {
		return "Variables response unavailable", nil
	}

	var sb strings.Builder
	sb.WriteString("Variables:\n")
	for _, v := range varsResp.Body.Variables {
		ref := ""
		if v.VariablesReference > 0 {
			ref = fmt.Sprintf(" (ref:%d, expandable)", v.VariablesReference)
		}
		typ := ""
		if v.Type != "" {
			typ = fmt.Sprintf(" [%s]", v.Type)
		}
		sb.WriteString(fmt.Sprintf("  %s%s = %s%s\n", v.Name, typ, v.Value, ref))
	}
	return sb.String(), nil
}

// opEvaluate evaluates an expression in the current context.
func opEvaluate(session *debugSession, input DebugInput) (string, error) {
	timeout := resolveTimeout(input.TimeoutSec)

	if input.Expression == "" {
		return "", fmt.Errorf("expression is required for evaluate")
	}

	evalContext := input.Context
	if evalContext == "" {
		evalContext = "repl"
	}

	req := &dap.EvaluateRequest{}
	req.Seq = session.client.nextSeq()
	req.Arguments = dap.EvaluateArguments{
		Expression: input.Expression,
		FrameId:    input.FrameID,
		Context:    evalContext,
	}

	resp, err := session.client.sendRequest(req, timeout)
	if err != nil {
		return "", fmt.Errorf("evaluate failed: %w", err)
	}

	if ok, msg := isResponseSuccess(resp); !ok {
		return "", fmt.Errorf("evaluate failed: %s", msg)
	}

	evalResp, ok := resp.(*dap.EvaluateResponse)
	if !ok {
		return "Evaluate response unavailable", nil
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Expression: %s\n", input.Expression))
	sb.WriteString(fmt.Sprintf("Result: %s\n", evalResp.Body.Result))
	if evalResp.Body.Type != "" {
		sb.WriteString(fmt.Sprintf("Type: %s\n", evalResp.Body.Type))
	}
	if evalResp.Body.VariablesReference > 0 {
		sb.WriteString(fmt.Sprintf("Expandable: ref:%d\n", evalResp.Body.VariablesReference))
	}
	return sb.String(), nil
}

// opDisconnect terminates the debug session.
func opDisconnect(session *debugSession, input DebugInput) (string, error) {
	timeout := resolveTimeout(input.TimeoutSec)

	req := &dap.DisconnectRequest{}
	req.Seq = session.client.nextSeq()
	// DAP spec: terminate the debuggee only if we launched it.
	// For attach sessions, the debuggee was already running and should be left alive.
	req.Arguments = &dap.DisconnectArguments{
		TerminateDebuggee: session.launchMode,
	}

	// Best-effort: adapter might already be gone
	session.client.sendRequest(req, timeout)

	// Remove from pool (this also calls session.close())
	pool.remove(session.id)

	return fmt.Sprintf("Session %s disconnected and cleaned up.", session.id), nil
}

// opStatus returns current session state and recent events.
func opStatus(session *debugSession, input DebugInput) (string, error) {
	state := session.getState()
	events := session.events.drain()

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Session: %s\n", session.id))
	sb.WriteString(fmt.Sprintf("State: %s\n", state))
	sb.WriteString(fmt.Sprintf("Mode: %s\n", session.mode))

	// Show adapter capabilities so agents know what's supported.
	// go-dap's Capabilities is a flat struct with bool fields — no reflect-based
	// enumeration, so we check each field manually.
	caps := session.capabilities
	var supported []string
	if caps.SupportsStepBack {
		supported = append(supported, "stepBack")
	}
	if caps.SupportTerminateDebuggee {
		supported = append(supported, "terminateDebuggee")
	}
	if caps.SupportsRestartFrame {
		supported = append(supported, "restartFrame")
	}
	if caps.SupportsGotoTargetsRequest {
		supported = append(supported, "gotoTargets")
	}
	if caps.SupportsStepInTargetsRequest {
		supported = append(supported, "stepInTargets")
	}
	if caps.SupportsCompletionsRequest {
		supported = append(supported, "completions")
	}
	if caps.SupportsModulesRequest {
		supported = append(supported, "modules")
	}
	if caps.SupportsExceptionInfoRequest {
		supported = append(supported, "exceptionInfo")
	}
	if caps.SupportsLoadedSourcesRequest {
		supported = append(supported, "loadedSources")
	}
	if caps.SupportsDataBreakpoints {
		supported = append(supported, "dataBreakpoints")
	}
	if caps.SupportsDisassembleRequest {
		supported = append(supported, "disassemble")
	}
	if caps.SupportsReadMemoryRequest {
		supported = append(supported, "readMemory")
	}
	if caps.SupportsWriteMemoryRequest {
		supported = append(supported, "writeMemory")
	}
	if caps.SupportsSetVariable {
		supported = append(supported, "setVariable")
	}
	if caps.SupportsSetExpression {
		supported = append(supported, "setExpression")
	}
	if caps.SupportsFunctionBreakpoints {
		supported = append(supported, "functionBreakpoints")
	}
	if caps.SupportsInstructionBreakpoints {
		supported = append(supported, "instructionBreakpoints")
	}
	if caps.SupportsTerminateRequest {
		supported = append(supported, "terminate")
	}
	if caps.SupportsRestartRequest {
		supported = append(supported, "restart")
	}
	if caps.SupportsCancelRequest {
		supported = append(supported, "cancel")
	}
	if caps.SupportsBreakpointLocationsRequest {
		supported = append(supported, "breakpointLocations")
	}
	if caps.SupportsTerminateThreadsRequest {
		supported = append(supported, "terminateThreads")
	}
	if len(supported) > 0 {
		sb.WriteString(fmt.Sprintf("Capabilities: %s\n", strings.Join(supported, ", ")))
	} else {
		sb.WriteString("Capabilities: (basic only — adapter reported no extended capabilities)\n")
	}

	if len(events) > 0 {
		sb.WriteString(fmt.Sprintf("\nRecent events (%d):\n", len(events)))
		for _, evt := range events {
			sb.WriteString(fmt.Sprintf("  [%s] %s\n", evt.Timestamp.Format("15:04:05"), evt.Type))
			// Show output event body inline for convenience
			if evt.Type == "output" {
				var outputEvt struct {
					Body struct {
						Output   string `json:"output"`
						Category string `json:"category"`
					} `json:"body"`
				}
				if json.Unmarshal([]byte(evt.Body), &outputEvt) == nil {
					cat := outputEvt.Body.Category
					if cat == "" {
						cat = "console"
					}
					sb.WriteString(fmt.Sprintf("    [%s] %s", cat, outputEvt.Body.Output))
				}
			}
		}
	} else {
		sb.WriteString("\nNo new events since last check.\n")
	}

	return sb.String(), nil
}

// checkSessionAlive returns an error if the session's program has terminated.
// Call this before sending execution commands (continue/step/pause) to avoid
// sending requests to a dead adapter that will never respond.
func checkSessionAlive(session *debugSession) error {
	state := session.getState()
	switch state {
	case "terminated", "exited":
		return fmt.Errorf("program has %s — use disconnect to clean up the session", state)
	}
	return nil
}

// --- Helper types and functions ---

// breakpointSpec is the JSON schema for user-provided breakpoint entries.
// JSON tags use camelCase (DAP standard). snake_case is also accepted
// via normalizeBPJSON preprocessing.
type breakpointSpec struct {
	Line         int    `json:"line"`
	Condition    string `json:"condition,omitempty"`
	HitCondition string `json:"hitCondition,omitempty"`
	LogMessage   string `json:"logMessage,omitempty"`
}

// snakeToCamelBP maps snake_case breakpoint JSON keys to their DAP camelCase
// equivalents. Both conventions are accepted for user convenience.
var snakeToCamelBP = map[string]string{
	"hit_condition":         "hitCondition",
	"log_message":           "logMessage",
	"instruction_reference": "instructionReference",
	"data_id":               "dataId",
	"access_type":           "accessType",
}

// normalizeBPJSON converts snake_case keys in a breakpoint JSON array to
// camelCase so both conventions are accepted. Returns original data on error.
func normalizeBPJSON(data []byte) []byte {
	var items []map[string]json.RawMessage
	if err := json.Unmarshal(data, &items); err != nil {
		return data
	}
	changed := false
	for i, item := range items {
		for snake, camel := range snakeToCamelBP {
			if v, ok := item[snake]; ok {
				if _, exists := item[camel]; !exists {
					item[camel] = v
				}
				delete(item, snake)
				changed = true
			}
		}
		items[i] = item
	}
	if !changed {
		return data
	}
	result, err := json.Marshal(items)
	if err != nil {
		return data
	}
	return result
}

// resolveThreadID returns the thread ID to use for continue/step/pause.
// Uses the explicitly provided ID if non-zero, falls back to the last
// StoppedEvent's thread ID, and finally defaults to 1.
func resolveThreadID(session *debugSession, inputTID int) int {
	if inputTID != 0 {
		return inputTID
	}
	session.mu.Lock()
	tid := session.lastStoppedTID
	session.mu.Unlock()
	if tid != 0 {
		return tid
	}
	return 1
}

// formatStoppedEvent renders a stopped event into a human-readable summary.
func formatStoppedEvent(evt *dap.StoppedEvent) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Stopped: %s\n", evt.Body.Reason))
	if evt.Body.Description != "" {
		sb.WriteString(fmt.Sprintf("Description: %s\n", evt.Body.Description))
	}
	sb.WriteString(fmt.Sprintf("Thread: %d\n", evt.Body.ThreadId))
	if evt.Body.Text != "" {
		sb.WriteString(fmt.Sprintf("Text: %s\n", evt.Body.Text))
	}
	sb.WriteString("\nUse operation=stack_trace to see the call stack, or operation=threads to list threads.")
	return sb.String()
}
