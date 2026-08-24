package toolbox

import (
	"context"
	"strings"
	"testing"

	"agent-tool/common"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestProfilesStayCompactAndComposable(t *testing.T) {
	if groups, ok := profileGroups("core"); !ok || len(groups) != 1 || groups[0] != "core" {
		t.Fatalf("core profile = %v, %v", groups, ok)
	}
	if groups, ok := profileGroups("remote"); !ok || len(groups) != 2 {
		t.Fatalf("remote profile = %v, %v", groups, ok)
	}
	if _, ok := profileGroups("everything-ish"); ok {
		t.Fatal("unknown profile was accepted")
	}
}

func TestManagerEnablesOnlyRequestedGroup(t *testing.T) {
	server := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "test"}, nil)
	registered := map[string]int{}
	m := NewManager(server, []Spec{
		{Name: "read", Group: "core", Register: func() { registered["read"]++ }},
		{Name: "ssh", Group: "remote", Register: func() { registered["ssh"]++ }},
	})
	if err := m.EnableProfile("core"); err != nil {
		t.Fatal(err)
	}
	if registered["read"] != 1 || registered["ssh"] != 0 {
		t.Fatalf("registered = %#v", registered)
	}
	if err := m.EnableProfile("core"); err != nil || registered["read"] != 1 {
		t.Fatalf("duplicate enable = %#v, %v", registered, err)
	}
}

type gatewayEchoInput struct {
	Message string `json:"message" jsonschema:"Message to echo,required"`
}

type gatewayEchoOutput struct {
	Message string `json:"message"`
}

func TestGatewayDescribesAndCallsToolWithoutClientRefresh(t *testing.T) {
	server := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "test"}, nil)
	m := NewManager(server, []Spec{{
		Name: "echo", Group: "remote", Register: func() {
			common.SafeAddTool(server, &mcp.Tool{Name: "echo", Description: "Echo a message."},
				func(_ context.Context, _ *mcp.CallToolRequest, input gatewayEchoInput) (*mcp.CallToolResult, gatewayEchoOutput, error) {
					text := "echo: " + input.Message
					return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}, gatewayEchoOutput{Message: text}, nil
				})
		},
	}})

	describeResult, _, err := m.Handle(context.Background(), nil, Input{Operation: "describe", Tool: "echo"})
	if err != nil || describeResult.IsError {
		t.Fatalf("describe failed: result=%v err=%v", describeResult, err)
	}
	description := describeResult.Content[0].(*mcp.TextContent).Text
	if !strings.Contains(description, `"message"`) || !strings.Contains(description, "operation=call") {
		t.Fatalf("describe omitted schema or gateway guidance: %s", description)
	}

	req := &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Name: "toolbox"}}
	callResult, _, err := m.Handle(context.Background(), req, Input{
		Operation: "call", Tool: "echo", Arguments: map[string]any{"message": "hello"},
	})
	if err != nil || callResult.IsError {
		t.Fatalf("gateway call failed: result=%v err=%v", callResult, err)
	}
	if got := callResult.Content[0].(*mcp.TextContent).Text; got != "echo: hello" {
		t.Fatalf("gateway result = %q", got)
	}
}

func TestGatewayPreservesTargetValidationErrors(t *testing.T) {
	server := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "test"}, nil)
	m := NewManager(server, []Spec{{
		Name: "echo", Group: "remote", Register: func() {
			common.SafeAddTool(server, &mcp.Tool{Name: "echo"},
				func(_ context.Context, _ *mcp.CallToolRequest, input gatewayEchoInput) (*mcp.CallToolResult, gatewayEchoOutput, error) {
					return nil, gatewayEchoOutput{}, nil
				})
		},
	}})
	req := &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Name: "toolbox"}}
	result, _, err := m.Handle(context.Background(), req, Input{Operation: "call", Tool: "echo"})
	if err != nil || !result.IsError {
		t.Fatalf("expected target validation tool error: result=%v err=%v", result, err)
	}
	text := result.Content[0].(*mcp.TextContent).Text
	if !strings.Contains(text, "validation error") || !strings.Contains(text, "message") {
		t.Fatalf("unexpected validation result: %s", text)
	}
}

func TestToolboxOutputRetrievesPreservedRawCommandOutput(t *testing.T) {
	server := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "test"}, nil)
	m := NewManager(server, nil)
	id := common.PreserveRawOutput("bash", "warning: original\nwarning: original\n", false, 36)
	if id == "" {
		t.Fatal("failed to preserve test output")
	}
	result, _, err := m.Handle(context.Background(), nil, Input{Operation: "output", OutputID: id})
	if err != nil || result.IsError {
		t.Fatalf("output lookup failed: result=%v err=%v", result, err)
	}
	text := result.Content[0].(*mcp.TextContent).Text
	for _, want := range []string{"source: bash", "warning: original\nwarning: original\n"} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in %q", want, text)
		}
	}
	paged, _, err := m.Handle(context.Background(), nil, Input{
		Operation: "output", OutputID: id, OutputMaxChars: 10,
	})
	if err != nil || paged.IsError {
		t.Fatalf("paged output lookup failed: result=%v err=%v", paged, err)
	}
	pagedText := paged.Content[0].(*mcp.TextContent).Text
	if !strings.Contains(pagedText, "next_offset: 10") || !strings.HasSuffix(pagedText, "warning: o") {
		t.Fatalf("unexpected paged output: %q", pagedText)
	}
}
