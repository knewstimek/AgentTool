package debug

import (
	"context"
	"fmt"
	"strings"

	"agent-tool/common"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// DebugInput defines the parameters for all debug operations.
type DebugInput struct {
	// Session identification
	SessionID string `json:"session_id,omitempty" jsonschema:"Debug session ID. Auto-generated if empty on launch"`

	// Operation
	Operation string `json:"operation" jsonschema:"Debug operation: launch, attach, set_breakpoints, continue, next, step_in, step_out, pause, threads, stack_trace, scopes, variables, evaluate, disconnect, status, set_function_breakpoints, set_exception_breakpoints, set_data_breakpoints, data_breakpoint_info, set_instruction_breakpoints, disassemble, read_memory, write_memory, set_variable, set_expression, goto, goto_targets, step_back, reverse_continue, restart_frame, modules, loaded_sources, exception_info, completions, source, terminate, restart, cancel, step_in_targets, terminate_threads, resolve_address,required"`

	// launch/attach: adapter configuration
	AdapterCommand string   `json:"adapter_command,omitempty" jsonschema:"Debug adapter executable path or command (e.g. dlv, debugpy, codelldb)"`
	AdapterArgs    []string `json:"adapter_args,omitempty" jsonschema:"Debug adapter command arguments (e.g. [dap] for dlv)"`
	Address        string   `json:"address,omitempty" jsonschema:"Debug adapter TCP address host:port (for TCP mode, Phase 2)"`
	LaunchArgs     string   `json:"launch_args,omitempty" jsonschema:"JSON object with launch configuration passed to the adapter (program path, args, env, cwd, etc.). Keys starting with __ are meta fields consumed by this tool and not forwarded to the adapter. Use help(topic=debug) for adapter-specific recipes."`

	// DAP initialize overrides (optional, most adapters work with defaults)
	ClientID   string `json:"client_id,omitempty" jsonschema:"DAP client identifier sent in initialize. Default: agent-tool. Set to vscode for vsdbg compatibility."`
	ClientName string `json:"client_name,omitempty" jsonschema:"DAP client display name sent in initialize. Default: agent-tool MCP debug client"`

	// set_breakpoints: breakpoint configuration
	SourcePath  string `json:"source_path,omitempty" jsonschema:"Absolute source file path for breakpoints"`
	Breakpoints string `json:"breakpoints,omitempty" jsonschema:"JSON array of breakpoints: [{line: N, condition: '...', hitCondition: '...', logMessage: '...'}]"`

	// set_exception_breakpoints
	Filters string `json:"filters,omitempty" jsonschema:"JSON array of exception filter IDs for set_exception_breakpoints (e.g. [\"raised\",\"uncaught\"])"`

	// stack_trace / scopes / variables / evaluate context
	ThreadID           int `json:"thread_id,omitempty" jsonschema:"Thread ID (for stack_trace, continue, next, step_in, step_out, pause, goto, step_back, reverse_continue, exception_info). Default: 1"`
	FrameID            int `json:"frame_id,omitempty" jsonschema:"Stack frame ID (for scopes, evaluate, set_expression, restart_frame, step_in_targets, completions)"`
	VariablesReference int `json:"variables_reference,omitempty" jsonschema:"Variables reference ID from scopes response (for variables, set_variable, data_breakpoint_info)"`

	// evaluate / set_expression
	Expression string `json:"expression,omitempty" jsonschema:"Expression to evaluate in the debug context"`
	Context    string `json:"context,omitempty" jsonschema:"Evaluation context: watch, repl, hover. Default: repl"`

	// set_variable / set_expression / data_breakpoint_info
	Name  string `json:"name,omitempty" jsonschema:"Variable name (for set_variable, data_breakpoint_info)"`
	Value string `json:"value,omitempty" jsonschema:"New value (for set_variable, set_expression)"`

	// goto / goto_targets / completions
	TargetID int `json:"target_id,omitempty" jsonschema:"Target ID for goto (from goto_targets response)"`
	Line     int `json:"line,omitempty" jsonschema:"Line number (for goto_targets, completions)"`
	Column   int `json:"column,omitempty" jsonschema:"Column number (for goto_targets, completions)"`

	// completions
	Text string `json:"text,omitempty" jsonschema:"Text for completions request"`

	// disassemble / read_memory / write_memory
	MemoryReference   string `json:"memory_reference,omitempty" jsonschema:"Memory reference address (for disassemble, read_memory, write_memory)"`
	Count             int    `json:"count,omitempty" jsonschema:"Byte count (read_memory) or instruction count (disassemble)"`
	InstructionOffset int    `json:"instruction_offset,omitempty" jsonschema:"Instruction offset relative to memory_reference (disassemble)"`
	ResolveSymbols    interface{} `json:"resolve_symbols,omitempty" jsonschema:"Resolve symbols in disassembly output: true or false. Default: false"`
	Data              string `json:"data,omitempty" jsonschema:"Base64-encoded data (write_memory)"`

	// source
	SourceReference int `json:"source_reference,omitempty" jsonschema:"Source reference ID (for source request, from stack frame)"`

	// modules paging
	StartModule int `json:"start_module,omitempty" jsonschema:"Start index for modules paging"`
	ModuleCount int `json:"module_count,omitempty" jsonschema:"Number of modules to return (0 = all)"`

	// terminate_threads
	ThreadIDs string `json:"thread_ids,omitempty" jsonschema:"JSON array of thread IDs to terminate (for terminate_threads)"`

	// cancel
	RequestID int `json:"request_id,omitempty" jsonschema:"Pending request ID to cancel"`

	// Timeout
	TimeoutSec int `json:"timeout_sec,omitempty" jsonschema:"Operation timeout in seconds. Default: 30, Max: 120"`
}

// DebugOutput is the output structure for the debug tool.
type DebugOutput struct {
	Result string `json:"result"`
}

var validOperations = map[string]bool{
	"launch": true, "attach": true,
	"set_breakpoints": true, "breakpoint_locations": true, "set_function_breakpoints": true,
	"set_exception_breakpoints": true, "set_data_breakpoints": true,
	"data_breakpoint_info": true, "set_instruction_breakpoints": true,
	"continue": true, "next": true, "step_in": true, "step_out": true,
	"step_back": true, "reverse_continue": true, "restart_frame": true,
	"goto": true, "goto_targets": true, "step_in_targets": true,
	"pause": true,
	"threads": true, "stack_trace": true, "scopes": true, "variables": true,
	"set_variable": true, "set_expression": true,
	"evaluate": true, "completions": true,
	"source": true, "modules": true, "loaded_sources": true,
	"exception_info": true,
	"disassemble": true, "read_memory": true, "write_memory": true,
	"terminate": true, "restart": true, "cancel": true,
	"terminate_threads": true,
	"resolve_address":   true,
	"disconnect": true, "status": true,
}

// Handle processes a debug tool invocation.
func Handle(ctx context.Context, req *mcp.CallToolRequest, input DebugInput) (*mcp.CallToolResult, DebugOutput, error) {
	op := strings.ToLower(strings.TrimSpace(input.Operation))
	if !validOperations[op] {
		return errorResult("invalid operation: use help(topic=debug) to see available operations")
	}
	input.Operation = op

	// launch/attach create new sessions — don't require an existing one
	if op == "launch" {
		result, err := opLaunch(input)
		if err != nil {
			return errorResult(fmt.Sprintf("launch failed: %v", err))
		}
		return successResult(result)
	}
	if op == "attach" {
		result, err := opAttach(input)
		if err != nil {
			return errorResult(fmt.Sprintf("attach failed: %v", err))
		}
		return successResult(result)
	}

	// All other operations require an existing session
	if input.SessionID == "" {
		return errorResult("session_id is required (use operation=launch first to create a session)")
	}

	session, ok := pool.get(input.SessionID)
	if !ok {
		return errorResult(fmt.Sprintf("session %q not found. Use operation=launch to create a new session.", input.SessionID))
	}

	var result string
	var err error

	switch op {
	// Breakpoints
	case "set_breakpoints":
		result, err = opSetBreakpoints(session, input)
	case "breakpoint_locations":
		result, err = opBreakpointLocations(session, input)
	case "set_function_breakpoints":
		result, err = opSetFunctionBreakpoints(session, input)
	case "set_exception_breakpoints":
		result, err = opSetExceptionBreakpointsExplicit(session, input)
	case "set_data_breakpoints":
		result, err = opSetDataBreakpoints(session, input)
	case "data_breakpoint_info":
		result, err = opDataBreakpointInfo(session, input)
	case "set_instruction_breakpoints":
		result, err = opSetInstructionBreakpoints(session, input)
	// Execution control
	case "continue":
		result, err = opContinue(session, input)
	case "next":
		result, err = opNext(session, input)
	case "step_in":
		result, err = opStepIn(session, input)
	case "step_out":
		result, err = opStepOut(session, input)
	case "step_back":
		result, err = opStepBack(session, input)
	case "reverse_continue":
		result, err = opReverseContinue(session, input)
	case "restart_frame":
		result, err = opRestartFrame(session, input)
	case "goto":
		result, err = opGoto(session, input)
	case "goto_targets":
		result, err = opGotoTargets(session, input)
	case "step_in_targets":
		result, err = opStepInTargets(session, input)
	case "pause":
		result, err = opPause(session, input)
	// Inspection
	case "threads":
		result, err = opThreads(session, input)
	case "stack_trace":
		result, err = opStackTrace(session, input)
	case "scopes":
		result, err = opScopes(session, input)
	case "variables":
		result, err = opVariables(session, input)
	case "set_variable":
		result, err = opSetVariable(session, input)
	case "set_expression":
		result, err = opSetExpression(session, input)
	case "evaluate":
		result, err = opEvaluate(session, input)
	case "completions":
		result, err = opCompletions(session, input)
	case "exception_info":
		result, err = opExceptionInfo(session, input)
	// Source / modules
	case "source":
		result, err = opSource(session, input)
	case "modules":
		result, err = opModules(session, input)
	case "loaded_sources":
		result, err = opLoadedSources(session, input)
	// Memory / disassembly
	case "disassemble":
		result, err = opDisassemble(session, input)
	case "read_memory":
		result, err = opReadMemory(session, input)
	case "write_memory":
		result, err = opWriteMemory(session, input)
	case "resolve_address":
		result, err = opResolveAddress(session, input)
	// Session lifecycle
	case "terminate":
		result, err = opTerminate(session, input)
	case "restart":
		result, err = opRestart(session, input)
	case "cancel":
		result, err = opCancel(session, input)
	case "terminate_threads":
		result, err = opTerminateThreads(session, input)
	case "disconnect":
		result, err = opDisconnect(session, input)
	case "status":
		result, err = opStatus(session, input)
	}

	if err != nil {
		return errorResult(fmt.Sprintf("%s failed: %v", op, err))
	}

	return successResult(result)
}

// Register registers the debug tool with the MCP server.
func Register(server *mcp.Server) {
	common.SafeAddTool(server, &mcp.Tool{
		Name: "debug",
		Description: `Interactive debugger using Debug Adapter Protocol (DAP).
Launch and control debug sessions for any language with a DAP-compatible adapter.
Supports breakpoints, stepping, variable inspection, expression evaluation, stack traces.
Adapters: dlv (Go), debugpy (Python), codelldb/lldb-dap (C/C++/Rust), and more.
Operations: launch, attach, set_breakpoints, continue, next, step_in, step_out, pause, threads, stack_trace, scopes, variables, evaluate, disconnect, status.
Extended: breakpoint_locations, set_function_breakpoints, set_exception_breakpoints, set_data_breakpoints, data_breakpoint_info, set_instruction_breakpoints, disassemble, read_memory, write_memory, set_variable, set_expression, goto, goto_targets, step_back, reverse_continue, restart_frame, modules, loaded_sources, exception_info, completions, source, terminate, restart, cancel, step_in_targets, terminate_threads, resolve_address.
Requires a DAP adapter executable installed on the system (e.g. 'dlv dap' for Go, 'python -m debugpy' for Python).`,
	}, Handle)
}

func successResult(msg string) (*mcp.CallToolResult, DebugOutput, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
	}, DebugOutput{Result: msg}, nil
}

func errorResult(msg string) (*mcp.CallToolResult, DebugOutput, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		IsError: true,
	}, DebugOutput{Result: msg}, nil
}
