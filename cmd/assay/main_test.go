package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/scancmd"
	"github.com/kun9497/assay/internal/severity"
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
		// An explicit image reference that cannot be read must fail loudly
		// rather than be interpreted as a clean, empty scan (D11). This uses a
		// docker-archive: prefix pointing at a file that does not exist, rather
		// than a bare registry reference like "alpine:3.19": the prefix makes
		// classification unambiguous and the load fails locally, so the test
		// never reaches an actual registry over the network.
		{"scan of an image target that cannot be read", []string{"scan", "docker-archive:/does/not/exist.tar"}, exitError},
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

// TestParseScanArgs covers the CLI syntax for the three --fail-on* flags:
// recognized in any position relative to the target (grype-style tools are
// invoked as `scan <target> --fail-on <band>`, target first), both the
// "--fail-on value" and "--fail-on=value" spellings, and the error cases a
// typo produces. Bad input must be an error, never a silently-ignored flag
// (task 5 brief) — a threshold the user thought they set but did not is worse
// than no threshold at all.
func TestParseScanArgs(t *testing.T) {
	high, critical := severity.High, severity.Critical

	t.Run("target only, no flags", func(t *testing.T) {
		target, opts, err := parseScanArgs([]string{"alpine:3.19"})
		if err != nil {
			t.Fatalf("err = %v, want nil", err)
		}
		if target != "alpine:3.19" {
			t.Errorf("target = %q, want %q", target, "alpine:3.19")
		}
		if opts != (scancmd.Options{}) {
			t.Errorf("opts = %+v, want the zero value", opts)
		}
	})

	t.Run("--fail-on after the target, space form", func(t *testing.T) {
		target, opts, err := parseScanArgs([]string{"alpine:3.19", "--fail-on", "high"})
		if err != nil {
			t.Fatalf("err = %v, want nil", err)
		}
		if target != "alpine:3.19" {
			t.Errorf("target = %q, want %q", target, "alpine:3.19")
		}
		if opts.FailOn == nil || *opts.FailOn != high {
			t.Errorf("opts.FailOn = %v, want %v", opts.FailOn, high)
		}
	})

	t.Run("--fail-on before the target", func(t *testing.T) {
		// The stdlib flag package stops parsing at the first non-flag
		// argument, which would treat the target itself as ending flag
		// parsing. This CLI's flags must work in either position.
		target, opts, err := parseScanArgs([]string{"--fail-on", "critical", "alpine:3.19"})
		if err != nil {
			t.Fatalf("err = %v, want nil", err)
		}
		if target != "alpine:3.19" {
			t.Errorf("target = %q, want %q", target, "alpine:3.19")
		}
		if opts.FailOn == nil || *opts.FailOn != critical {
			t.Errorf("opts.FailOn = %v, want %v", opts.FailOn, critical)
		}
	})

	t.Run("--fail-on=value form", func(t *testing.T) {
		target, opts, err := parseScanArgs([]string{"alpine:3.19", "--fail-on=high"})
		if err != nil {
			t.Fatalf("err = %v, want nil", err)
		}
		if target != "alpine:3.19" {
			t.Errorf("target = %q, want %q", target, "alpine:3.19")
		}
		if opts.FailOn == nil || *opts.FailOn != high {
			t.Errorf("opts.FailOn = %v, want %v", opts.FailOn, high)
		}
	})

	t.Run("--fail-on-unknown and --fail-on-incomplete together", func(t *testing.T) {
		target, opts, err := parseScanArgs(
			[]string{"alpine:3.19", "--fail-on-unknown", "--fail-on-incomplete"})
		if err != nil {
			t.Fatalf("err = %v, want nil", err)
		}
		if target != "alpine:3.19" {
			t.Errorf("target = %q, want %q", target, "alpine:3.19")
		}
		if !opts.FailOnUnknown {
			t.Error("opts.FailOnUnknown = false, want true")
		}
		if !opts.FailOnIncomplete {
			t.Error("opts.FailOnIncomplete = false, want true")
		}
	})

	t.Run("all three flags plus the target, mixed order", func(t *testing.T) {
		target, opts, err := parseScanArgs([]string{
			"--fail-on-incomplete", "alpine:3.19", "--fail-on", "medium", "--fail-on-unknown",
		})
		if err != nil {
			t.Fatalf("err = %v, want nil", err)
		}
		if target != "alpine:3.19" {
			t.Errorf("target = %q, want %q", target, "alpine:3.19")
		}
		if opts.FailOn == nil || *opts.FailOn != severity.Medium {
			t.Errorf("opts.FailOn = %v, want %v", opts.FailOn, severity.Medium)
		}
		if !opts.FailOnUnknown || !opts.FailOnIncomplete {
			t.Errorf("opts = %+v, want both bool gates true", opts)
		}
	})

	t.Run("no target at all", func(t *testing.T) {
		target, _, err := parseScanArgs([]string{"--fail-on", "high"})
		if err != nil {
			t.Fatalf("err = %v, want nil (the caller checks for an empty target)", err)
		}
		if target != "" {
			t.Errorf("target = %q, want empty", target)
		}
	})

	t.Run("--fail-on with no value is an error, not a silently-ignored flag", func(t *testing.T) {
		_, _, err := parseScanArgs([]string{"alpine:3.19", "--fail-on"})
		if err == nil {
			t.Fatal("err = nil, want an error naming the missing value")
		}
		if !strings.Contains(err.Error(), "--fail-on") {
			t.Errorf("err = %q, want it to name --fail-on", err)
		}
	})

	// D17/the brief: a threshold the user thought they set but did not is
	// worse than no threshold, so a typo must be an error, not "no gate".
	t.Run("an invalid --fail-on value is an error naming what is accepted", func(t *testing.T) {
		_, _, err := parseScanArgs([]string{"alpine:3.19", "--fail-on", "extreme"})
		if err == nil {
			t.Fatal("err = nil, want an error for an invalid band")
		}
		for _, want := range []string{"extreme", "none", "low", "medium", "high", "critical"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("err = %q, missing %q", err, want)
			}
		}
	})

	t.Run("an unrecognized flag is an error, not silently ignored", func(t *testing.T) {
		_, _, err := parseScanArgs([]string{"alpine:3.19", "--bogus"})
		if err == nil {
			t.Fatal("err = nil, want an error naming the unknown flag")
		}
		if !strings.Contains(err.Error(), "--bogus") {
			t.Errorf("err = %q, want it to name --bogus", err)
		}
	})

	t.Run("a second positional argument is an error", func(t *testing.T) {
		_, _, err := parseScanArgs([]string{"alpine:3.19", "alpine:3.20"})
		if err == nil {
			t.Fatal("err = nil, want an error: scan takes exactly one target")
		}
	})
}

// The CLI contract end to end: a bad --fail-on value reaches run() as exit 2
// with the accepted values on stderr, never a scan that silently ran with no
// gate at all.
func TestRun_ScanBadFailOnValueExits2(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"scan", "docker-archive:/does/not/exist.tar", "--fail-on", "extreme"},
		&stdout, &stderr)
	if code != exitError {
		t.Errorf("run() = %d, want exitError (%d)", code, exitError)
	}
	if stdout.Len() != 0 {
		t.Errorf("error path polluted stdout: %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "want one of") {
		t.Errorf("stderr = %q, want it to name the accepted bands", stderr.String())
	}
}

// scan with flags but no target must still be treated as "no target", the
// same exit code and messaging as today's no-flags case.
func TestRun_ScanFlagsWithNoTargetExits2(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"scan", "--fail-on", "high"}, &stdout, &stderr)
	if code != exitError {
		t.Errorf("run() = %d, want exitError (%d)", code, exitError)
	}
	if !strings.Contains(stderr.String(), "requires a target") {
		t.Errorf("stderr = %q, want it to say a target is required", stderr.String())
	}
}
