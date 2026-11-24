package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// P4 of the 2026-11-20 audit: what the run does about its own failures.
func TestRun_APreviousStatusThatIsNotOneIsStartedFresh(t *testing.T) {
	fixedNow(t, t0)
	for _, body := range []string{
		"{", // not JSON
		`{"lastSuccess":{"url":"stale"},"schemaVersion":"nine"}`, // decodes halfway
	} {
		prev := filepath.Join(t.TempDir(), "prev.json")
		if err := os.WriteFile(prev, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		s, stderr := runStatus(t, "-ref", "127.0.0.1:1/assay-db:v9", "-prev", prev, "-workflow", "db-publish", "-result", "failure")
		if s.LastSuccess != nil || s.LastRun == nil {
			t.Errorf("%s: lastSuccess %+v, lastRun %+v; want a fresh status", body, s.LastSuccess, s.LastRun)
		}
		if !strings.Contains(stderr, "starting fresh") {
			t.Errorf("%s: stderr %q", body, stderr)
		}
		if !s.GeneratedAt.Equal(t0) {
			t.Errorf("generatedAt = %v, want %v", s.GeneratedAt, t0)
		}
	}
}

func TestRun_FailuresOfTheRunItself(t *testing.T) {
	fixedNow(t, t0)
	dir := t.TempDir()
	out := filepath.Join(dir, "status.json")
	for _, tc := range []struct {
		name string
		args []string
		code int
		want string
	}{
		{"no workflow", []string{"-result", "success", "-out", out}, 2, "-workflow is required"},
		{"a previous status that cannot be read", []string{"-workflow", "db-publish", "-result", "failure", "-prev", dir, "-out", out}, 1, "read " + dir},
		{"an output that cannot be written", []string{"-workflow", "db-publish", "-result", "failure", "-out", dir}, 1, "write " + dir},
	} {
		var stdout, stderr bytes.Buffer
		if code := run(append(tc.args, "-ref", "127.0.0.1:1/assay-db:v9"), &stdout, &stderr); code != tc.code || !strings.Contains(stderr.String(), tc.want) {
			t.Errorf("%s: exit %d, stderr %q; want %d naming %q", tc.name, code, stderr.String(), tc.code, tc.want)
		}
		if stdout.Len() != 0 {
			t.Errorf("%s: stdout %q", tc.name, stdout.String())
		}
	}
	if _, err := os.Stat(out); err == nil {
		t.Error("a refused run wrote a status")
	}
	// The workflow log shows what was written.
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-ref", "127.0.0.1:1/assay-db:v9", "-workflow", "db-publish", "-result", "failure", "-out", out}, &stdout, &stderr); code != 0 {
		t.Fatal(stderr.String())
	}
	if b, err := os.ReadFile(out); err != nil || stdout.String() != string(b) {
		t.Errorf("stdout %q, file %q, %v", stdout.String(), b, err)
	}
}
