package procexec

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"agent-tool/common"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestProcExecHelperProcess(t *testing.T) {
	if os.Getenv("AGENT_TOOL_PROCEXEC_HELPER") != "1" {
		return
	}
	for i := 0; i < 3; i++ {
		fmt.Fprintln(os.Stderr, "warning: duplicated diagnostic")
	}
	os.Exit(0)
}

func TestForegroundCompactsDiagnosticsAndPreservesRaw(t *testing.T) {
	result, out, err := execForeground(context.Background(), ProcExecInput{
		Command:        os.Args[0],
		Args:           []string{"-test.run=^TestProcExecHelperProcess$"},
		Env:            []string{"AGENT_TOOL_PROCEXEC_HELPER=1"},
		MaxOutputChars: common.DefaultOutputChars,
		OutputView:     "compact",
	}, 30)
	if err != nil || result.IsError {
		t.Fatalf("exec failed: result=%v out=%+v err=%v", result, out, err)
	}
	if !out.Compacted || out.OmittedLines != 2 || out.RawOutputID == "" {
		t.Fatalf("unexpected compaction metadata: %+v", out)
	}
	text := result.Content[0].(*mcp.TextContent).Text
	if !strings.Contains(text, "warning: duplicated diagnostic [x3]") || !strings.Contains(text, "raw_output_id=") {
		t.Fatalf("unexpected compact output: %q", text)
	}
	raw, ok := common.LoadRawOutput(out.RawOutputID)
	if !ok || strings.Count(raw.Content, "warning: duplicated diagnostic") != 3 {
		t.Fatalf("raw output was not preserved: ok=%v record=%+v", ok, raw)
	}
}

func TestForegroundRawViewDoesNotCompact(t *testing.T) {
	result, out, err := execForeground(context.Background(), ProcExecInput{
		Command:        os.Args[0],
		Args:           []string{"-test.run=^TestProcExecHelperProcess$"},
		Env:            []string{"AGENT_TOOL_PROCEXEC_HELPER=1"},
		MaxOutputChars: common.DefaultOutputChars,
		OutputView:     "raw",
	}, 30)
	if err != nil || result.IsError {
		t.Fatalf("exec failed: result=%v out=%+v err=%v", result, out, err)
	}
	if out.Compacted || out.RawOutputID != "" || strings.Count(out.Stderr, "warning: duplicated diagnostic") != 3 {
		t.Fatalf("raw view changed output: %+v", out)
	}
}
