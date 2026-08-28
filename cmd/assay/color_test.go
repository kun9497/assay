package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// TestPolicyAllowsColor is D107's own instruction: "test the policy function
// directly, caller-first on the seam the CLI actually calls" — no TTY
// anywhere in this test, because the https://no-color.org convention is a
// pure function of one string.
func TestPolicyAllowsColor(t *testing.T) {
	for _, tc := range []struct {
		noColorEnv string
		want       bool
	}{
		{"", true},
		// The convention's own wording is presence, not truthiness -- "0"
		// disables color exactly like "1" does. This is deliberately NOT
		// envFlag's boolean parsing (used a few lines up in main.go for
		// KISA_ENABLE/NVD_ENABLE): NO_COLOR is not that kind of flag, and a
		// reader who sets NO_COLOR=0 expecting envFlag's "off" spelling to
		// mean "on" would be surprised in the wrong direction for a feature
		// whose whole point is staying out of a pipeline that cannot render
		// it.
		{"0", false},
		{"1", false},
		{"true", false},
		{"false", false},
		{"anything", false},
	} {
		t.Run("NO_COLOR="+tc.noColorEnv, func(t *testing.T) {
			if got := policyAllowsColor(tc.noColorEnv); got != tc.want {
				t.Errorf("policyAllowsColor(%q) = %v, want %v", tc.noColorEnv, got, tc.want)
			}
		})
	}
}

// TestWantColor pins the AND: both a colorable terminal AND policy
// permission are required, and either one alone is not enough.
func TestWantColor(t *testing.T) {
	for _, tc := range []struct {
		name       string
		isTerminal bool
		noColorEnv string
		want       bool
	}{
		{"terminal, no NO_COLOR: colors on", true, "", true},
		{"terminal, but NO_COLOR set: colors off", true, "1", false},
		{"not a terminal, no NO_COLOR: colors off", false, "", false},
		{"not a terminal, and NO_COLOR set: colors off", false, "1", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := wantColor(tc.isTerminal, tc.noColorEnv); got != tc.want {
				t.Errorf("wantColor(%v, %q) = %v, want %v", tc.isTerminal, tc.noColorEnv, got, tc.want)
			}
		})
	}
}

// TestStdoutIsTerminal_NonFileWriterIsNeverColorable pins the type-assertion
// half of stdoutIsTerminal without a real terminal: every writer a test can
// construct here (a bytes.Buffer, or a *os.File pointed at a plain file
// rather than a console) must read as not colorable, which is exactly what
// keeps every OTHER test in this package — none of which has a real TTY —
// from accidentally emitting ANSI codes.
func TestStdoutIsTerminal_NonFileWriterIsNeverColorable(t *testing.T) {
	var buf bytes.Buffer
	if stdoutIsTerminal(&buf) {
		t.Error("a bytes.Buffer must never read as a colorable terminal")
	}

	f, err := os.Create(filepath.Join(t.TempDir(), "not-a-console"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if stdoutIsTerminal(f) {
		t.Error("a plain regular file must never read as a colorable terminal")
	}
}

// TestRun_NoColorOverridesAPositiveTerminalCheck is the caller-first proof
// that NO_COLOR wins even when the terminal half of the decision says yes —
// the exact scenario D107 calls out: "NO_COLOR non-empty forces off even
// when the TTY check would say on". It drives run() itself, the real CLI
// seam (buildRunSeamFixture's own reasoning: a unit test of wantColor alone
// cannot catch main.go dropping the NO_COLOR read, or the terminal check, on
// the way into it), with stdoutIsTerminalFunc stubbed to claim "yes, a real
// terminal" — the one half no test process can honestly provide — so the
// second half, NO_COLOR, is what this test actually isolates.
func TestRun_NoColorOverridesAPositiveTerminalCheck(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("ASSAY_DB_DIR", dir)
	sbom := buildRunSeamFixture(t, dir)

	orig := stdoutIsTerminalFunc
	stdoutIsTerminalFunc = func(w io.Writer) bool { return true }
	defer func() { stdoutIsTerminalFunc = orig }()

	t.Run("NO_COLOR set: no ESC byte reaches stdout even though the terminal check says yes", func(t *testing.T) {
		t.Setenv("NO_COLOR", "1")
		var stdout, stderr bytes.Buffer
		if code := run([]string{"scan", sbom}, &stdout, &stderr); code != exitOK {
			t.Fatalf("run() = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitOK, stdout.String(), stderr.String())
		}
		if bytes.ContainsRune(stdout.Bytes(), '\x1b') {
			t.Errorf("NO_COLOR is set; stdout must carry no ESC byte:\n%q", stdout.String())
		}
	})

	t.Run("NO_COLOR unset: the stubbed positive terminal check reaches report.Table as color", func(t *testing.T) {
		t.Setenv("NO_COLOR", "")
		var stdout, stderr bytes.Buffer
		if code := run([]string{"scan", sbom}, &stdout, &stderr); code != exitOK {
			t.Fatalf("run() = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitOK, stdout.String(), stderr.String())
		}
		if !bytes.ContainsRune(stdout.Bytes(), '\x1b') {
			t.Errorf("terminal check stubbed true and NO_COLOR unset; stdout should carry ANSI codes:\n%q", stdout.String())
		}
	})
}
