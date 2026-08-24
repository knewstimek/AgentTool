package ssh

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"agent-tool/common"

	gossh "golang.org/x/crypto/ssh"
)

const sshJobRetention = time.Hour

type sshJob struct {
	mu         sync.Mutex
	id         string
	command    string
	createdAt  time.Time
	finishedAt time.Time
	status     string
	exitCode   int
	err        string
	stdout     *common.BoundedCapture
	stderr     *common.BoundedCapture
	session    *gossh.Session
}

type sshJobSnapshot struct {
	ID              string
	Status          string
	ExitCode        int
	Error           string
	CreatedAt       time.Time
	FinishedAt      time.Time
	Stdout          string
	Stderr          string
	StdoutBytes     int64
	StderrBytes     int64
	StdoutTruncated bool
	StderrTruncated bool
}

var sshJobs = struct {
	sync.Mutex
	items map[string]*sshJob
}{items: make(map[string]*sshJob)}

func startSSHJob(client *gossh.Client, command string, maxOutputBytes int, outputMode string) (*sshJob, error) {
	session, err := client.NewSession()
	if err != nil {
		return nil, err
	}
	idBytes := make([]byte, 12)
	if _, err := rand.Read(idBytes); err != nil {
		_ = session.Close()
		return nil, err
	}
	job := &sshJob{
		id:        hex.EncodeToString(idBytes),
		command:   command,
		createdAt: time.Now(),
		status:    "running",
		stdout:    common.NewBoundedCaptureMode((maxOutputBytes+1)/2, outputMode),
		stderr:    common.NewBoundedCaptureMode(maxOutputBytes/2, outputMode),
		session:   session,
	}
	session.Stdout = job.stdout
	session.Stderr = job.stderr

	sshJobs.Lock()
	pruneSSHJobsLocked(time.Now())
	sshJobs.items[job.id] = job
	sshJobs.Unlock()

	go func() {
		err := session.Run(command)
		job.mu.Lock()
		defer job.mu.Unlock()
		job.finishedAt = time.Now()
		job.session = nil
		job.exitCode = 0
		if job.status == "cancelled" {
			if exitErr, ok := err.(*gossh.ExitError); ok {
				job.exitCode = exitErr.ExitStatus()
			}
		} else if exitErr, ok := err.(*gossh.ExitError); ok {
			job.exitCode = exitErr.ExitStatus()
			job.status = "failed"
			job.err = exitErr.Error()
		} else if err != nil {
			job.status = "failed"
			job.err = err.Error()
		} else {
			job.status = "completed"
		}
		_ = session.Close()
	}()
	return job, nil
}

func getSSHJob(id string) (*sshJob, bool) {
	sshJobs.Lock()
	defer sshJobs.Unlock()
	pruneSSHJobsLocked(time.Now())
	job, ok := sshJobs.items[id]
	return job, ok
}

func pruneSSHJobsLocked(now time.Time) {
	for id, job := range sshJobs.items {
		job.mu.Lock()
		finished := job.finishedAt
		job.mu.Unlock()
		if !finished.IsZero() && now.Sub(finished) > sshJobRetention {
			delete(sshJobs.items, id)
		}
	}
}

func (j *sshJob) snapshot() sshJobSnapshot {
	j.mu.Lock()
	defer j.mu.Unlock()
	stdout, stdoutBytes, stdoutTruncated := j.stdout.Result()
	stderr, stderrBytes, stderrTruncated := j.stderr.Result()
	return sshJobSnapshot{
		ID: j.id, Status: j.status, ExitCode: j.exitCode, Error: j.err,
		CreatedAt: j.createdAt, FinishedAt: j.finishedAt,
		Stdout: stdout, Stderr: stderr, StdoutBytes: stdoutBytes,
		StderrBytes: stderrBytes, StdoutTruncated: stdoutTruncated,
		StderrTruncated: stderrTruncated,
	}
}

func (j *sshJob) cancel() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.status != "running" {
		return fmt.Errorf("job is already %s", j.status)
	}
	j.status = "cancelled"
	j.finishedAt = time.Now()
	if j.session != nil {
		_ = j.session.Signal(gossh.SIGKILL)
		return j.session.Close()
	}
	return nil
}

func lastLines(s string, count int) string {
	if count <= 0 {
		return ""
	}
	lines := strings.Split(strings.TrimRight(s, "\r\n"), "\n")
	if len(lines) > count {
		lines = lines[len(lines)-count:]
	}
	return strings.Join(lines, "\n")
}
