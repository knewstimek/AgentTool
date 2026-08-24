package ssh

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"agent-tool/common"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestSSHJobStatusAndTailDoNotRequireConnectionFields(t *testing.T) {
	job := &sshJob{
		id: "test-job", createdAt: time.Now(), status: "completed", exitCode: 0,
		finishedAt: time.Now(), stdout: common.NewBoundedCapture(1024), stderr: common.NewBoundedCapture(1024),
	}
	_, _ = job.stdout.Write([]byte("one\ntwo\nthree\n"))
	sshJobs.Lock()
	sshJobs.items[job.id] = job
	sshJobs.Unlock()
	t.Cleanup(func() {
		sshJobs.Lock()
		delete(sshJobs.items, job.id)
		sshJobs.Unlock()
	})

	result, out, err := Handle(context.Background(), nil, SSHInput{Operation: "tail", JobID: job.id, TailLines: 2})
	if err != nil || result.IsError {
		t.Fatalf("Handle() error = %v, result = %#v", err, result)
	}
	if out.Status != "completed" || !strings.Contains(out.Result, "two\nthree") || strings.Contains(out.Result, "one\n") {
		t.Fatalf("unexpected tail result: %q", out.Result)
	}
}

func TestLastLines(t *testing.T) {
	if got := lastLines("a\nb\nc\n", 2); got != "b\nc" {
		t.Fatalf("lastLines() = %q", got)
	}
}

func TestRegisteredStatusDoesNotRequireConnectionFields(t *testing.T) {
	server := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "test"}, nil)
	Register(server)
	registration, ok := common.RegisteredSafeTool(server, "ssh")
	if !ok {
		t.Fatal("ssh SafeAddTool registration not found")
	}
	arguments, err := json.Marshal(map[string]any{
		"operation": "status",
		"job_id":    "missing-test-job",
	})
	if err != nil {
		t.Fatal(err)
	}
	req := &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Name: "ssh", Arguments: arguments}}
	result, err := registration.Handler(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	text := result.Content[0].(*mcp.TextContent).Text
	if !result.IsError || text != "SSH job not found or expired" {
		t.Fatalf("status was blocked before job lookup: isError=%v text=%q", result.IsError, text)
	}
}
