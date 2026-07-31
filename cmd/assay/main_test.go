package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRun_ExitCodes(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want int
	}{
		{"no arguments", nil, exitError},
		{"version", []string{"version"}, exitOK},
		{"help", []string{"help"}, exitOK},
		{"unknown command", []string{"bogus"}, exitError},
		{"scan without target", []string{"scan"}, exitError},
		// An image reference is not a path, and images are not read directly
		// until slice 2b. It must fail loudly rather than be interpreted as a
		// filename that happens not to exist — a scanner that returns 0 on a
		// target it never opened is worse than one that fails.
		{"scan of an image reference, which is not a path", []string{"scan", "alpine:3.19"}, exitError},
		{"db without subcommand", []string{"db"}, exitError},
		{"db unknown subcommand", []string{"db", "bogus"}, exitError},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if got := run(tc.args, &stdout, &stderr); got != tc.want {
				t.Errorf("run(%v) = %d, want %d (stderr: %s)",
					tc.args, got, tc.want, stderr.String())
			}
		})
	}
}

func TestRun_VersionGoesToStdout(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"version"}, &stdout, &stderr); code != exitOK {
		t.Fatalf("version returned %d, want %d", code, exitOK)
	}
	if !strings.HasPrefix(stdout.String(), "assay ") {
		t.Errorf("version output not on stdout or malformed: %q", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Errorf("version wrote to stderr: %q", stderr.String())
	}
}

// Errors belong on stderr so that `assay scan ... --output json | jq` stays clean.
func TestRun_ErrorsGoToStderr(t *testing.T) {
	var stdout, stderr bytes.Buffer
	run([]string{"bogus"}, &stdout, &stderr)
	if stdout.Len() != 0 {
		t.Errorf("error path polluted stdout: %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "unknown command") {
		t.Errorf("stderr missing diagnostic: %q", stderr.String())
	}
}
