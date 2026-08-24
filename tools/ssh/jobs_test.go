package ssh

import (
	"context"
	"strings"
	"testing"
	"time"

	"agent-tool/common"
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
