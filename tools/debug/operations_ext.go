package debug

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/go-dap"
)

// --- Breakpoint location query ---

// opBreakpointLocations returns all possible breakpoint locations in a source range.
func opBreakpointLocations(session *debugSession, input DebugInput) (string, error) {
	timeout := resolveTimeout(input.TimeoutSec)

	if input.SourcePath == "" {
		return "", fmt.Errorf("source_path is required for breakpoint_locations")
	}
	if input.Line == 0 {
		return "", fmt.Errorf("line is required for breakpoint_locations")
	}

	req := &dap.BreakpointLocationsRequest{}
	req.Seq = session.client.nextSeq()
	req.Arguments = &dap.BreakpointLocationsArguments{
		Source: dap.Source{Path: input.SourcePath},
		Line:   input.Line,
		Column: input.Column,
	}

	resp, err := session.client.sendRequest(req, timeout)
	if err != nil {
		return "", fmt.Errorf("breakpointLocations failed: %w", err)
	}
	if ok, msg := isResponseSuccess(resp); !ok {
		return "", fmt.Errorf("breakpointLocations failed: %s", msg)
	}

	blResp, ok := resp.(*dap.BreakpointLocationsResponse)
	if !ok {
		return "BreakpointLocations response unavailable", nil
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Breakpoint locations at %s:%d (%d found):\n", input.SourcePath, input.Line, len(blResp.Body.Breakpoints)))
	for _, loc := range blResp.Body.Breakpoints {
		sb.WriteString(fmt.Sprintf("  Line %d", loc.Line))
		if loc.Column > 0 {
			sb.WriteString(fmt.Sprintf(", col %d", loc.Column))
		}
		if loc.EndLine > 0 {
			sb.WriteString(fmt.Sprintf(" → line %d", loc.EndLine))
		}
		sb.WriteString("\n")
	}
	return sb.String(), nil
}

// --- Breakpoint operations ---

// opSetFunctionBreakpoints sets breakpoints on function names.
func opSetFunctionBreakpoints(session *debugSession, input DebugInput) (string, error) {
	timeout := resolveTimeout(input.TimeoutSec)

	var bps []struct {
		Name         string `json:"name"`
		Condition    string `json:"condition,omitempty"`
		HitCondition string `json:"hitCondition,omitempty"`
	}
	if input.Breakpoints != "" {
		if err := json.Unmarshal(normalizeBPJSON([]byte(input.Breakpoints)), &bps); err != nil {
			return "", fmt.Errorf("invalid breakpoints JSON: %w", err)
		}
	}

	dapBPs := make([]dap.FunctionBreakpoint, len(bps))
	for i, bp := range bps {
		dapBPs[i] = dap.FunctionBreakpoint{
			Name:         bp.Name,
			Condition:    bp.Condition,
			HitCondition: bp.HitCondition,
		}
	}

	req := &dap.SetFunctionBreakpointsRequest{}
	req.Seq = session.client.nextSeq()
	req.Arguments = dap.SetFunctionBreakpointsArguments{
		Breakpoints: dapBPs,
	}

	resp, err := session.client.sendRequest(req, timeout)
	if err != nil {
		return "", fmt.Errorf("setFunctionBreakpoints failed: %w", err)
	}
	if ok, msg := isResponseSuccess(resp); !ok {
		return "", fmt.Errorf("setFunctionBreakpoints failed: %s", msg)
	}

	bpResp, ok := resp.(*dap.SetFunctionBreakpointsResponse)
	if !ok {
		return "Function breakpoints set (no detailed response)", nil
	}

	return formatBreakpointsResponse("Function breakpoints", bpResp.Body.Breakpoints), nil
}

// opSetExceptionBreakpointsExplicit allows explicit exception breakpoint configuration.
// Different from the implicit one sent during configurationDone.
func opSetExceptionBreakpointsExplicit(session *debugSession, input DebugInput) (string, error) {
	timeout := resolveTimeout(input.TimeoutSec)

	var filters []string
	if input.Filters != "" {
		if err := json.Unmarshal([]byte(input.Filters), &filters); err != nil {
			return "", fmt.Errorf("invalid filters JSON: %w", err)
		}
	}

	req := &dap.SetExceptionBreakpointsRequest{}
	req.Seq = session.client.nextSeq()
	req.Arguments = dap.SetExceptionBreakpointsArguments{
		Filters: filters,
	}

	resp, err := session.client.sendRequest(req, timeout)
	if err != nil {
		return "", fmt.Errorf("setExceptionBreakpoints failed: %w", err)
	}
	if ok, msg := isResponseSuccess(resp); !ok {
		return "", fmt.Errorf("setExceptionBreakpoints failed: %s", msg)
	}

	return fmt.Sprintf("Exception breakpoints set with filters: %v", filters), nil
}

// opSetDataBreakpoints sets data (watchpoint) breakpoints.
func opSetDataBreakpoints(session *debugSession, input DebugInput) (string, error) {
	timeout := resolveTimeout(input.TimeoutSec)

	var bps []struct {
		DataID       string `json:"dataId"`
		AccessType   string `json:"accessType,omitempty"`
		Condition    string `json:"condition,omitempty"`
		HitCondition string `json:"hitCondition,omitempty"`
	}
	if input.Breakpoints != "" {
		if err := json.Unmarshal(normalizeBPJSON([]byte(input.Breakpoints)), &bps); err != nil {
			return "", fmt.Errorf("invalid breakpoints JSON: %w", err)
		}
	}

	dapBPs := make([]dap.DataBreakpoint, len(bps))
	for i, bp := range bps {
		dapBPs[i] = dap.DataBreakpoint{
			DataId:       bp.DataID,
			AccessType:   dap.DataBreakpointAccessType(bp.AccessType),
			Condition:    bp.Condition,
			HitCondition: bp.HitCondition,
		}
	}

	req := &dap.SetDataBreakpointsRequest{}
	req.Seq = session.client.nextSeq()
	req.Arguments = dap.SetDataBreakpointsArguments{
		Breakpoints: dapBPs,
	}

	resp, err := session.client.sendRequest(req, timeout)
	if err != nil {
		return "", fmt.Errorf("setDataBreakpoints failed: %w", err)
	}
	if ok, msg := isResponseSuccess(resp); !ok {
		return "", fmt.Errorf("setDataBreakpoints failed: %s", msg)
	}

	bpResp, ok := resp.(*dap.SetDataBreakpointsResponse)
	if !ok {
		return "Data breakpoints set (no detailed response)", nil
	}

	return formatBreakpointsResponse("Data breakpoints", bpResp.Body.Breakpoints), nil
}

// opDataBreakpointInfo queries whether a data breakpoint can be set on a variable.
func opDataBreakpointInfo(session *debugSession, input DebugInput) (string, error) {
	timeout := resolveTimeout(input.TimeoutSec)

	if input.Name == "" {
		return "", fmt.Errorf("name is required for data_breakpoint_info")
	}

	req := &dap.DataBreakpointInfoRequest{}
	req.Seq = session.client.nextSeq()
	req.Arguments = dap.DataBreakpointInfoArguments{
		VariablesReference: input.VariablesReference,
		Name:               input.Name,
		FrameId:            input.FrameID,
	}

	resp, err := session.client.sendRequest(req, timeout)
	if err != nil {
		return "", fmt.Errorf("dataBreakpointInfo failed: %w", err)
	}
	if ok, msg := isResponseSuccess(resp); !ok {
		return "", fmt.Errorf("dataBreakpointInfo failed: %s", msg)
	}

	infoResp, ok := resp.(*dap.DataBreakpointInfoResponse)
	if !ok {
		return "DataBreakpointInfo response unavailable", nil
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Variable: %s\n", input.Name))
	sb.WriteString(fmt.Sprintf("DataId: %v\n", infoResp.Body.DataId))
	if infoResp.Body.Description != "" {
		sb.WriteString(fmt.Sprintf("Description: %s\n", infoResp.Body.Description))
	}
	if len(infoResp.Body.AccessTypes) > 0 {
		types := make([]string, len(infoResp.Body.AccessTypes))
		for i, t := range infoResp.Body.AccessTypes {
			types[i] = string(t)
		}
		sb.WriteString(fmt.Sprintf("Access types: %s\n", strings.Join(types, ", ")))
	}
	sb.WriteString(fmt.Sprintf("Can persist: %v\n", infoResp.Body.CanPersist))
	return sb.String(), nil
}

// opSetInstructionBreakpoints sets breakpoints at specific instruction addresses.
func opSetInstructionBreakpoints(session *debugSession, input DebugInput) (string, error) {
	timeout := resolveTimeout(input.TimeoutSec)

	var bps []struct {
		InstructionReference string `json:"instructionReference"`
		Offset               int    `json:"offset,omitempty"`
		Condition            string `json:"condition,omitempty"`
		HitCondition         string `json:"hitCondition,omitempty"`
	}
	if input.Breakpoints != "" {
		if err := json.Unmarshal(normalizeBPJSON([]byte(input.Breakpoints)), &bps); err != nil {
			return "", fmt.Errorf("invalid breakpoints JSON: %w", err)
		}
	}

	dapBPs := make([]dap.InstructionBreakpoint, len(bps))
	for i, bp := range bps {
		dapBPs[i] = dap.InstructionBreakpoint{
			InstructionReference: bp.InstructionReference,
			Offset:               bp.Offset,
			Condition:            bp.Condition,
			HitCondition:         bp.HitCondition,
		}
	}

	req := &dap.SetInstructionBreakpointsRequest{}
	req.Seq = session.client.nextSeq()
	req.Arguments = dap.SetInstructionBreakpointsArguments{
		Breakpoints: dapBPs,
	}

	resp, err := session.client.sendRequest(req, timeout)
	if err != nil {
		return "", fmt.Errorf("setInstructionBreakpoints failed: %w", err)
	}
	if ok, msg := isResponseSuccess(resp); !ok {
		return "", fmt.Errorf("setInstructionBreakpoints failed: %s", msg)
	}

	bpResp, ok := resp.(*dap.SetInstructionBreakpointsResponse)
	if !ok {
		return "Instruction breakpoints set (no detailed response)", nil
	}

	return formatBreakpointsResponse("Instruction breakpoints", bpResp.Body.Breakpoints), nil
}

// --- Execution control extensions ---

// opStepBack performs a reverse single step.
func opStepBack(session *debugSession, input DebugInput) (string, error) {
	if err := checkSessionAlive(session); err != nil {
		return "", err
	}
	timeout := resolveTimeout(input.TimeoutSec)
	threadID := resolveThreadID(session, input.ThreadID)

	select {
	case <-session.stoppedCh:
	default:
	}

	session.mu.Lock()
	session.state = "running"
	session.mu.Unlock()

	req := &dap.StepBackRequest{}
	req.Seq = session.client.nextSeq()
	req.Arguments = dap.StepBackArguments{ThreadId: threadID}

	_, err := session.client.sendRequest(req, timeout)
	if err != nil {
		return "", fmt.Errorf("stepBack failed: %w", err)
	}

	return waitForStopped(session, timeout)
}

// opReverseContinue resumes backward execution.
func opReverseContinue(session *debugSession, input DebugInput) (string, error) {
	if err := checkSessionAlive(session); err != nil {
		return "", err
	}
	timeout := resolveTimeout(input.TimeoutSec)
	threadID := resolveThreadID(session, input.ThreadID)

	select {
	case <-session.stoppedCh:
	default:
	}

	session.mu.Lock()
	session.state = "running"
	session.mu.Unlock()

	req := &dap.ReverseContinueRequest{}
	req.Seq = session.client.nextSeq()
	req.Arguments = dap.ReverseContinueArguments{ThreadId: threadID}

	_, err := session.client.sendRequest(req, timeout)
	if err != nil {
		return "", fmt.Errorf("reverseContinue failed: %w", err)
	}

	return waitForStopped(session, timeout)
}

// opRestartFrame restarts execution from a specific stack frame.
func opRestartFrame(session *debugSession, input DebugInput) (string, error) {
	if err := checkSessionAlive(session); err != nil {
		return "", err
	}
	timeout := resolveTimeout(input.TimeoutSec)

	select {
	case <-session.stoppedCh:
	default:
	}

	session.mu.Lock()
	session.state = "running"
	session.mu.Unlock()

	req := &dap.RestartFrameRequest{}
	req.Seq = session.client.nextSeq()
	req.Arguments = dap.RestartFrameArguments{FrameId: input.FrameID}

	_, err := session.client.sendRequest(req, timeout)
	if err != nil {
		return "", fmt.Errorf("restartFrame failed: %w", err)
	}

	return waitForStopped(session, timeout)
}

// opGoto jumps to a specific goto target.
func opGoto(session *debugSession, input DebugInput) (string, error) {
	if err := checkSessionAlive(session); err != nil {
		return "", err
	}
	timeout := resolveTimeout(input.TimeoutSec)
	threadID := resolveThreadID(session, input.ThreadID)
	if input.TargetID == 0 {
		return "", fmt.Errorf("target_id is required for goto (use goto_targets to get available targets)")
	}

	select {
	case <-session.stoppedCh:
	default:
	}

	session.mu.Lock()
	session.state = "running"
	session.mu.Unlock()

	req := &dap.GotoRequest{}
	req.Seq = session.client.nextSeq()
	req.Arguments = dap.GotoArguments{
		ThreadId: threadID,
		TargetId: input.TargetID,
	}

	_, err := session.client.sendRequest(req, timeout)
	if err != nil {
		return "", fmt.Errorf("goto failed: %w", err)
	}

	return waitForStopped(session, timeout)
}

// opGotoTargets returns possible goto targets for a source location.
func opGotoTargets(session *debugSession, input DebugInput) (string, error) {
	timeout := resolveTimeout(input.TimeoutSec)

	if input.SourcePath == "" {
		return "", fmt.Errorf("source_path is required for goto_targets")
	}
	if input.Line == 0 {
		return "", fmt.Errorf("line is required for goto_targets")
	}

	req := &dap.GotoTargetsRequest{}
	req.Seq = session.client.nextSeq()
	req.Arguments = dap.GotoTargetsArguments{
		Source: dap.Source{Path: input.SourcePath},
		Line:   input.Line,
		Column: input.Column,
	}

	resp, err := session.client.sendRequest(req, timeout)
	if err != nil {
		return "", fmt.Errorf("gotoTargets failed: %w", err)
	}
	if ok, msg := isResponseSuccess(resp); !ok {
		return "", fmt.Errorf("gotoTargets failed: %s", msg)
	}

	gtResp, ok := resp.(*dap.GotoTargetsResponse)
	if !ok {
		return "GotoTargets response unavailable", nil
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Goto targets at %s:%d:\n", input.SourcePath, input.Line))
	for _, t := range gtResp.Body.Targets {
		sb.WriteString(fmt.Sprintf("  [ID:%d] %s (line %d", t.Id, t.Label, t.Line))
		if t.Column > 0 {
			sb.WriteString(fmt.Sprintf(", col %d", t.Column))
		}
		sb.WriteString(")\n")
	}
	return sb.String(), nil
}

// opStepInTargets returns possible step-in targets for a stack frame.
func opStepInTargets(session *debugSession, input DebugInput) (string, error) {
	timeout := resolveTimeout(input.TimeoutSec)

	req := &dap.StepInTargetsRequest{}
	req.Seq = session.client.nextSeq()
	req.Arguments = dap.StepInTargetsArguments{
		FrameId: input.FrameID,
	}

	resp, err := session.client.sendRequest(req, timeout)
	if err != nil {
		return "", fmt.Errorf("stepInTargets failed: %w", err)
	}
	if ok, msg := isResponseSuccess(resp); !ok {
		return "", fmt.Errorf("stepInTargets failed: %s", msg)
	}

	siResp, ok := resp.(*dap.StepInTargetsResponse)
	if !ok {
		return "StepInTargets response unavailable", nil
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Step-in targets (frame %d):\n", input.FrameID))
	for _, t := range siResp.Body.Targets {
		sb.WriteString(fmt.Sprintf("  [ID:%d] %s", t.Id, t.Label))
		if t.Line > 0 {
			sb.WriteString(fmt.Sprintf(" (line %d)", t.Line))
		}
		sb.WriteString("\n")
	}
	return sb.String(), nil
}

// --- Variable modification ---

// opSetVariable sets the value of a variable.
func opSetVariable(session *debugSession, input DebugInput) (string, error) {
	timeout := resolveTimeout(input.TimeoutSec)

	if input.VariablesReference == 0 {
		return "", fmt.Errorf("variables_reference is required for set_variable")
	}
	if input.Name == "" {
		return "", fmt.Errorf("name is required for set_variable")
	}
	if input.Value == "" {
		return "", fmt.Errorf("value is required for set_variable")
	}

	req := &dap.SetVariableRequest{}
	req.Seq = session.client.nextSeq()
	req.Arguments = dap.SetVariableArguments{
		VariablesReference: input.VariablesReference,
		Name:               input.Name,
		Value:              input.Value,
	}

	resp, err := session.client.sendRequest(req, timeout)
	if err != nil {
		return "", fmt.Errorf("setVariable failed: %w", err)
	}
	if ok, msg := isResponseSuccess(resp); !ok {
		return "", fmt.Errorf("setVariable failed: %s", msg)
	}

	svResp, ok := resp.(*dap.SetVariableResponse)
	if !ok {
		return "Variable set (no detailed response)", nil
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Variable %s set to: %s\n", input.Name, svResp.Body.Value))
	if svResp.Body.Type != "" {
		sb.WriteString(fmt.Sprintf("Type: %s\n", svResp.Body.Type))
	}
	if svResp.Body.VariablesReference > 0 {
		sb.WriteString(fmt.Sprintf("Expandable: ref:%d\n", svResp.Body.VariablesReference))
	}
	return sb.String(), nil
}

// opSetExpression sets the value of an expression.
func opSetExpression(session *debugSession, input DebugInput) (string, error) {
	timeout := resolveTimeout(input.TimeoutSec)

	if input.Expression == "" {
		return "", fmt.Errorf("expression is required for set_expression")
	}
	if input.Value == "" {
		return "", fmt.Errorf("value is required for set_expression")
	}

	req := &dap.SetExpressionRequest{}
	req.Seq = session.client.nextSeq()
	req.Arguments = dap.SetExpressionArguments{
		Expression: input.Expression,
		Value:      input.Value,
		FrameId:    input.FrameID,
	}

	resp, err := session.client.sendRequest(req, timeout)
	if err != nil {
		return "", fmt.Errorf("setExpression failed: %w", err)
	}
	if ok, msg := isResponseSuccess(resp); !ok {
		return "", fmt.Errorf("setExpression failed: %s", msg)
	}

	seResp, ok := resp.(*dap.SetExpressionResponse)
	if !ok {
		return "Expression set (no detailed response)", nil
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Expression %s set to: %s\n", input.Expression, seResp.Body.Value))
	if seResp.Body.Type != "" {
		sb.WriteString(fmt.Sprintf("Type: %s\n", seResp.Body.Type))
	}
	return sb.String(), nil
}

// --- Completions ---

// opCompletions returns completion suggestions for the given text.
func opCompletions(session *debugSession, input DebugInput) (string, error) {
	timeout := resolveTimeout(input.TimeoutSec)

	if input.Text == "" {
		return "", fmt.Errorf("text is required for completions")
	}
	col := input.Column
	if col == 0 {
		col = len(input.Text) + 1 // cursor at end
	}

	req := &dap.CompletionsRequest{}
	req.Seq = session.client.nextSeq()
	req.Arguments = dap.CompletionsArguments{
		FrameId: input.FrameID,
		Text:    input.Text,
		Column:  col,
		Line:    input.Line,
	}

	resp, err := session.client.sendRequest(req, timeout)
	if err != nil {
		return "", fmt.Errorf("completions failed: %w", err)
	}
	if ok, msg := isResponseSuccess(resp); !ok {
		return "", fmt.Errorf("completions failed: %s", msg)
	}

	cResp, ok := resp.(*dap.CompletionsResponse)
	if !ok {
		return "Completions response unavailable", nil
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Completions for %q:\n", input.Text))
	for _, item := range cResp.Body.Targets {
		sb.WriteString(fmt.Sprintf("  %s", item.Label))
		if item.Detail != "" {
			sb.WriteString(fmt.Sprintf(" — %s", item.Detail))
		}
		if item.Type != "" {
			sb.WriteString(fmt.Sprintf(" [%s]", item.Type))
		}
		sb.WriteString("\n")
	}
	return sb.String(), nil
}

// --- Exception info ---

// opExceptionInfo retrieves details about the current exception.
func opExceptionInfo(session *debugSession, input DebugInput) (string, error) {
	timeout := resolveTimeout(input.TimeoutSec)
	threadID := resolveThreadID(session, input.ThreadID)

	req := &dap.ExceptionInfoRequest{}
	req.Seq = session.client.nextSeq()
	req.Arguments = dap.ExceptionInfoArguments{
		ThreadId: threadID,
	}

	resp, err := session.client.sendRequest(req, timeout)
	if err != nil {
		return "", fmt.Errorf("exceptionInfo failed: %w", err)
	}
	if ok, msg := isResponseSuccess(resp); !ok {
		return "", fmt.Errorf("exceptionInfo failed: %s", msg)
	}

	eiResp, ok := resp.(*dap.ExceptionInfoResponse)
	if !ok {
		return "ExceptionInfo response unavailable", nil
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Exception: %s\n", eiResp.Body.ExceptionId))
	if eiResp.Body.Description != "" {
		sb.WriteString(fmt.Sprintf("Description: %s\n", eiResp.Body.Description))
	}
	sb.WriteString(fmt.Sprintf("Break mode: %s\n", eiResp.Body.BreakMode))
	if eiResp.Body.Details != nil {
		if eiResp.Body.Details.Message != "" {
			sb.WriteString(fmt.Sprintf("Message: %s\n", eiResp.Body.Details.Message))
		}
		if eiResp.Body.Details.TypeName != "" {
			sb.WriteString(fmt.Sprintf("Type: %s\n", eiResp.Body.Details.TypeName))
		}
		if eiResp.Body.Details.StackTrace != "" {
			sb.WriteString(fmt.Sprintf("Stack trace:\n%s\n", eiResp.Body.Details.StackTrace))
		}
	}
	return sb.String(), nil
}

// --- Source / modules ---

// opSource retrieves source code for a given source reference.
func opSource(session *debugSession, input DebugInput) (string, error) {
	timeout := resolveTimeout(input.TimeoutSec)

	if input.SourceReference == 0 && input.SourcePath == "" {
		return "", fmt.Errorf("source_reference or source_path is required for source")
	}

	req := &dap.SourceRequest{}
	req.Seq = session.client.nextSeq()
	req.Arguments = dap.SourceArguments{
		SourceReference: input.SourceReference,
	}
	if input.SourcePath != "" {
		req.Arguments.Source = &dap.Source{Path: input.SourcePath}
	}

	resp, err := session.client.sendRequest(req, timeout)
	if err != nil {
		return "", fmt.Errorf("source failed: %w", err)
	}
	if ok, msg := isResponseSuccess(resp); !ok {
		return "", fmt.Errorf("source failed: %s", msg)
	}

	srcResp, ok := resp.(*dap.SourceResponse)
	if !ok {
		return "Source response unavailable", nil
	}

	var sb strings.Builder
	if srcResp.Body.MimeType != "" {
		sb.WriteString(fmt.Sprintf("MIME: %s\n---\n", srcResp.Body.MimeType))
	}
	content := srcResp.Body.Content
	// Cap output to 100KB to avoid blowing up agent context window
	const maxSourceBytes = 102400
	if len(content) > maxSourceBytes {
		content = content[:maxSourceBytes] + "\n... (truncated, original size: " + fmt.Sprintf("%d", len(srcResp.Body.Content)) + " bytes)"
	}
	sb.WriteString(content)
	return sb.String(), nil
}

// opModules returns loaded modules/libraries.
func opModules(session *debugSession, input DebugInput) (string, error) {
	timeout := resolveTimeout(input.TimeoutSec)

	req := &dap.ModulesRequest{}
	req.Seq = session.client.nextSeq()
	req.Arguments = dap.ModulesArguments{
		StartModule: input.StartModule,
		ModuleCount: input.ModuleCount,
	}

	resp, err := session.client.sendRequest(req, timeout)
	if err != nil {
		return "", fmt.Errorf("modules failed: %w", err)
	}
	if ok, msg := isResponseSuccess(resp); !ok {
		return "", fmt.Errorf("modules failed: %s", msg)
	}

	modResp, ok := resp.(*dap.ModulesResponse)
	if !ok {
		return "Modules response unavailable", nil
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Modules (total: %d):\n", modResp.Body.TotalModules))
	for _, m := range modResp.Body.Modules {
		sb.WriteString(fmt.Sprintf("  [%v] %s", m.Id, m.Name))
		if m.Path != "" {
			sb.WriteString(fmt.Sprintf(" (%s)", m.Path))
		}
		if m.SymbolStatus != "" {
			sb.WriteString(fmt.Sprintf(" symbols:%s", m.SymbolStatus))
		}
		sb.WriteString("\n")
	}
	return sb.String(), nil
}

// opLoadedSources returns all loaded source files.
func opLoadedSources(session *debugSession, input DebugInput) (string, error) {
	timeout := resolveTimeout(input.TimeoutSec)

	req := &dap.LoadedSourcesRequest{}
	req.Seq = session.client.nextSeq()

	resp, err := session.client.sendRequest(req, timeout)
	if err != nil {
		return "", fmt.Errorf("loadedSources failed: %w", err)
	}
	if ok, msg := isResponseSuccess(resp); !ok {
		return "", fmt.Errorf("loadedSources failed: %s", msg)
	}

	lsResp, ok := resp.(*dap.LoadedSourcesResponse)
	if !ok {
		return "LoadedSources response unavailable", nil
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Loaded sources (%d):\n", len(lsResp.Body.Sources)))
	for _, src := range lsResp.Body.Sources {
		path := src.Path
		if path == "" {
			path = src.Name
		}
		sb.WriteString(fmt.Sprintf("  %s\n", path))
	}
	return sb.String(), nil
}

// --- Memory / disassembly ---

// opDisassemble returns disassembled instructions.
func opDisassemble(session *debugSession, input DebugInput) (string, error) {
	timeout := resolveTimeout(input.TimeoutSec)

	if input.MemoryReference == "" {
		return "", fmt.Errorf("memory_reference is required for disassemble")
	}
	count := input.Count
	if count == 0 {
		count = 50 // reasonable default
	}
	// Cap to prevent excessive output in agent context window
	const maxDisassembleCount = 1000
	if count > maxDisassembleCount {
		count = maxDisassembleCount
	}

	req := &dap.DisassembleRequest{}
	req.Seq = session.client.nextSeq()
	req.Arguments = dap.DisassembleArguments{
		MemoryReference:   input.MemoryReference,
		InstructionOffset: input.InstructionOffset,
		InstructionCount:  count,
		ResolveSymbols:    input.ResolveSymbols,
	}

	resp, err := session.client.sendRequest(req, timeout)
	if err != nil {
		return "", fmt.Errorf("disassemble failed: %w", err)
	}
	if ok, msg := isResponseSuccess(resp); !ok {
		return "", fmt.Errorf("disassemble failed: %s", msg)
	}

	daResp, ok := resp.(*dap.DisassembleResponse)
	if !ok {
		return "Disassemble response unavailable", nil
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Disassembly from %s (%d instructions):\n", input.MemoryReference, len(daResp.Body.Instructions)))
	for _, inst := range daResp.Body.Instructions {
		sb.WriteString(fmt.Sprintf("  %s", inst.Address))
		if inst.InstructionBytes != "" {
			sb.WriteString(fmt.Sprintf("  %-20s", inst.InstructionBytes))
		}
		sb.WriteString(fmt.Sprintf("  %s", inst.Instruction))
		if inst.Symbol != "" {
			sb.WriteString(fmt.Sprintf("  <%s>", inst.Symbol))
		}
		if inst.Location != nil && inst.Line > 0 {
			path := inst.Location.Path
			if path == "" {
				path = inst.Location.Name
			}
			sb.WriteString(fmt.Sprintf("  ; %s:%d", path, inst.Line))
		}
		sb.WriteString("\n")
	}
	return sb.String(), nil
}

// opReadMemory reads bytes from a memory location.
func opReadMemory(session *debugSession, input DebugInput) (string, error) {
	timeout := resolveTimeout(input.TimeoutSec)

	if input.MemoryReference == "" {
		return "", fmt.Errorf("memory_reference is required for read_memory")
	}
	count := input.Count
	if count == 0 {
		count = 256 // reasonable default
	}
	// Cap at 64KB to avoid excessive output
	if count > 65536 {
		count = 65536
	}

	req := &dap.ReadMemoryRequest{}
	req.Seq = session.client.nextSeq()
	req.Arguments = dap.ReadMemoryArguments{
		MemoryReference: input.MemoryReference,
		Count:           count,
	}

	resp, err := session.client.sendRequest(req, timeout)
	if err != nil {
		return "", fmt.Errorf("readMemory failed: %w", err)
	}
	if ok, msg := isResponseSuccess(resp); !ok {
		return "", fmt.Errorf("readMemory failed: %s", msg)
	}

	rmResp, ok := resp.(*dap.ReadMemoryResponse)
	if !ok {
		return "ReadMemory response unavailable", nil
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Memory at %s:\n", rmResp.Body.Address))
	if rmResp.Body.UnreadableBytes > 0 {
		sb.WriteString(fmt.Sprintf("Unreadable bytes: %d\n", rmResp.Body.UnreadableBytes))
	}
	if rmResp.Body.Data != "" {
		sb.WriteString(fmt.Sprintf("Data (base64): %s\n", rmResp.Body.Data))
	}
	return sb.String(), nil
}

// opWriteMemory writes bytes to a memory location.
func opWriteMemory(session *debugSession, input DebugInput) (string, error) {
	timeout := resolveTimeout(input.TimeoutSec)

	if input.MemoryReference == "" {
		return "", fmt.Errorf("memory_reference is required for write_memory")
	}
	if input.Data == "" {
		return "", fmt.Errorf("data (base64-encoded) is required for write_memory")
	}

	// Pre-validate base64 to give a clear error before sending to adapter
	decoded, b64Err := base64.StdEncoding.DecodeString(input.Data)
	if b64Err != nil {
		return "", fmt.Errorf("invalid base64 data: %w", b64Err)
	}
	// Cap at 64KB to match read_memory limit
	const maxWriteBytes = 65536
	if len(decoded) > maxWriteBytes {
		return "", fmt.Errorf("write_memory data too large: %d bytes (max %d)", len(decoded), maxWriteBytes)
	}

	req := &dap.WriteMemoryRequest{}
	req.Seq = session.client.nextSeq()
	req.Arguments = dap.WriteMemoryArguments{
		MemoryReference: input.MemoryReference,
		Data:            input.Data,
	}

	resp, err := session.client.sendRequest(req, timeout)
	if err != nil {
		return "", fmt.Errorf("writeMemory failed: %w", err)
	}
	if ok, msg := isResponseSuccess(resp); !ok {
		return "", fmt.Errorf("writeMemory failed: %s", msg)
	}

	wmResp, ok := resp.(*dap.WriteMemoryResponse)
	if !ok {
		return "Memory written (no detailed response)", nil
	}

	return fmt.Sprintf("Memory written at %s: %d bytes (offset: %d)", input.MemoryReference, wmResp.Body.BytesWritten, wmResp.Body.Offset), nil
}

// --- Session lifecycle ---

// opTerminate requests graceful termination of the debuggee.
// Some adapters (debugpy) kill the process before sending the response,
// which drops the connection and causes a timeout. We treat connection
// closure as successful termination rather than an error.
func opTerminate(session *debugSession, input DebugInput) (string, error) {
	timeout := resolveTimeout(input.TimeoutSec)

	req := &dap.TerminateRequest{}
	req.Seq = session.client.nextSeq()
	req.Arguments = &dap.TerminateArguments{}

	respCh, cleanup, err := session.client.sendRequestAsync(req)
	if err != nil {
		return "", fmt.Errorf("terminate failed: %w", err)
	}
	defer cleanup()

	select {
	case <-respCh:
		// Got a response — adapter acknowledged termination
	case <-session.done:
		// Connection closed — adapter terminated the process (debugpy behavior)
	case <-time.After(timeout):
		// Timeout — still treat as sent (terminate is best-effort)
	}

	return "Terminate request sent. The debuggee may handle it gracefully. Use disconnect to force cleanup.", nil
}

// opRestart restarts the debug session.
func opRestart(session *debugSession, input DebugInput) (string, error) {
	timeout := resolveTimeout(input.TimeoutSec)

	req := &dap.RestartRequest{}
	req.Seq = session.client.nextSeq()
	// RestartRequest.Arguments is json.RawMessage — pass launch_args if provided.
	if input.LaunchArgs != "" {
		req.Arguments = json.RawMessage(input.LaunchArgs)
	} else {
		req.Arguments = json.RawMessage("{}")
	}

	_, err := session.client.sendRequest(req, timeout)
	if err != nil {
		return "", fmt.Errorf("restart failed: %w", err)
	}

	// Reset session state for fresh configuration cycle.
	// initializedCh must be recreated — reusing a closed channel would skip
	// the initialized event wait (or panic on double close).
	session.mu.Lock()
	session.configDone = false
	session.state = "stopped"
	session.initializedCh = make(chan struct{})
	session.mu.Unlock()

	// Drain stale stopped event from previous run
	select {
	case <-session.stoppedCh:
	default:
	}

	return "Session restarted. Set breakpoints and continue.", nil
}

// opCancel cancels a pending request.
func opCancel(session *debugSession, input DebugInput) (string, error) {
	timeout := resolveTimeout(input.TimeoutSec)

	req := &dap.CancelRequest{}
	req.Seq = session.client.nextSeq()
	req.Arguments = &dap.CancelArguments{
		RequestId: input.RequestID,
	}

	_, err := session.client.sendRequest(req, timeout)
	if err != nil {
		return "", fmt.Errorf("cancel failed: %w", err)
	}

	return fmt.Sprintf("Cancel request sent for request ID %d.", input.RequestID), nil
}

// opTerminateThreads terminates specific threads.
func opTerminateThreads(session *debugSession, input DebugInput) (string, error) {
	timeout := resolveTimeout(input.TimeoutSec)

	var threadIDs []int
	if input.ThreadIDs != "" {
		if err := json.Unmarshal([]byte(input.ThreadIDs), &threadIDs); err != nil {
			return "", fmt.Errorf("invalid thread_ids JSON: %w", err)
		}
	}

	req := &dap.TerminateThreadsRequest{}
	req.Seq = session.client.nextSeq()
	req.Arguments = dap.TerminateThreadsArguments{
		ThreadIds: threadIDs,
	}

	_, err := session.client.sendRequest(req, timeout)
	if err != nil {
		return "", fmt.Errorf("terminateThreads failed: %w", err)
	}

	return fmt.Sprintf("Terminate request sent for threads: %v", threadIDs), nil
}

// --- Shared helpers ---

// formatBreakpointsResponse formats a list of breakpoints into a readable string.
func formatBreakpointsResponse(label string, bps []dap.Breakpoint) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%s:\n", label))
	for _, bp := range bps {
		verified := "unverified"
		if bp.Verified {
			verified = "verified"
		}
		// DAP spec: Line is optional. Show ID or index-based label when line is 0.
		if bp.Line > 0 {
			sb.WriteString(fmt.Sprintf("  Line %d: %s", bp.Line, verified))
		} else if bp.Id > 0 {
			sb.WriteString(fmt.Sprintf("  BP #%d: %s", bp.Id, verified))
		} else {
			sb.WriteString(fmt.Sprintf("  BP: %s", verified))
		}
		if bp.Message != "" {
			sb.WriteString(fmt.Sprintf(" (%s)", bp.Message))
		}
		sb.WriteString("\n")
	}
	return sb.String()
}

// opResolveAddress maps an address to its containing module + offset.
// Fetches all modules via DAP, parses each module's AddressRange, and finds
// which module contains the given address.
func opResolveAddress(session *debugSession, input DebugInput) (string, error) {
	if input.MemoryReference == "" {
		return "", fmt.Errorf("memory_reference is required (hex address to resolve, e.g. '0x7ffe5488')")
	}

	addr, err := strconv.ParseUint(strings.TrimPrefix(input.MemoryReference, "0x"), 16, 64)
	if err != nil {
		return "", fmt.Errorf("invalid address %q: %w", input.MemoryReference, err)
	}

	timeout := resolveTimeout(input.TimeoutSec)

	// Fetch all modules (moduleCount=0 means all)
	req := &dap.ModulesRequest{}
	req.Seq = session.client.nextSeq()
	req.Arguments = dap.ModulesArguments{
		StartModule: 0,
		ModuleCount: 0,
	}

	resp, err := session.client.sendRequest(req, timeout)
	if err != nil {
		return "", fmt.Errorf("modules request failed: %w", err)
	}
	if ok, msg := isResponseSuccess(resp); !ok {
		return "", fmt.Errorf("modules request failed: %s", msg)
	}

	modResp, ok := resp.(*dap.ModulesResponse)
	if !ok {
		return "", fmt.Errorf("unexpected response type for modules")
	}

	// Try to find the module containing the address
	for _, m := range modResp.Body.Modules {
		base, size, ok := parseAddressRange(m.AddressRange)
		if !ok {
			continue
		}
		if addr >= base && addr < base+size {
			offset := addr - base
			return fmt.Sprintf("0x%X → %s+0x%X (base: 0x%X, size: 0x%X, path: %s)",
				addr, m.Name, offset, base, size, m.Path), nil
		}
	}

	// Not found — still return module list for context
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("0x%X → no matching module found\n\nLoaded modules (%d):\n", addr, len(modResp.Body.Modules)))
	for _, m := range modResp.Body.Modules {
		sb.WriteString(fmt.Sprintf("  %s", m.Name))
		if m.AddressRange != "" {
			sb.WriteString(fmt.Sprintf("  range: %s", m.AddressRange))
		}
		if m.Path != "" {
			sb.WriteString(fmt.Sprintf("  (%s)", m.Path))
		}
		sb.WriteString("\n")
	}
	return sb.String(), nil
}

// parseAddressRange parses a module's AddressRange string into base and size.
// Supports common formats from DAP adapters:
//   - "0x7ffe0000-0x7fff0000"       (base-end range, codelldb/lldb-dap)
//   - "0x7ffe0000[0x10000]"         (base[size])
//   - "7ffe0000-7fff0000"           (without 0x prefix)
//   - "0x7FFE0000 - 0x7FFF0000"     (with spaces)
func parseAddressRange(s string) (base, size uint64, ok bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, 0, false
	}

	// Format: "base[size]"
	if idx := strings.Index(s, "["); idx >= 0 {
		endIdx := strings.Index(s, "]")
		if endIdx <= idx {
			return 0, 0, false
		}
		baseStr := strings.TrimSpace(s[:idx])
		sizeStr := strings.TrimSpace(s[idx+1 : endIdx])
		base, err1 := parseHexAddr(baseStr)
		sz, err2 := parseHexAddr(sizeStr)
		if err1 != nil || err2 != nil {
			return 0, 0, false
		}
		return base, sz, true
	}

	// Format: "base-end" or "base - end"
	if idx := strings.Index(s, "-"); idx >= 0 {
		// Handle "0x7ffe0000-0x7fff0000" — need to find '-' that isn't inside "0x"
		// Split on last '-' to avoid issues with addresses containing '-'
		baseStr := strings.TrimSpace(s[:idx])
		endStr := strings.TrimSpace(s[idx+1:])
		base, err1 := parseHexAddr(baseStr)
		end, err2 := parseHexAddr(endStr)
		if err1 != nil || err2 != nil || end <= base {
			return 0, 0, false
		}
		return base, end - base, true
	}

	return 0, 0, false
}

func parseHexAddr(s string) (uint64, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	return strconv.ParseUint(s, 16, 64)
}
