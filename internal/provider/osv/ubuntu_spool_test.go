package osv

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestUbuntuTrackerSync_GitMissing is the git-missing error path: lookGit is
// the injectable seam (its own doc comment explains why this was chosen over
// manipulating PATH). The error must name UBUNTU_TRACKER_ENABLE=0 as the off
// switch -- D85's "never silently skip" rule -- rather than merely failing.
func TestUbuntuTrackerSync_GitMissing(t *testing.T) {
	orig := lookGit
	lookGit = func(string) (string, error) { return "", exec.ErrNotFound }
	defer func() { lookGit = orig }()

	_, err := ubuntuTrackerSync(context.Background(), t.TempDir(), "https://example.invalid/repo")
	if err == nil {
		t.Fatal("ubuntuTrackerSync with no git = nil error, want one naming the missing tool")
	}
	if !strings.Contains(err.Error(), "git") {
		t.Errorf("error %q does not name git as the missing tool", err)
	}
	if !strings.Contains(err.Error(), "UBUNTU_TRACKER_ENABLE=0") {
		t.Errorf("error %q does not name UBUNTU_TRACKER_ENABLE=0 as the off switch", err)
	}
	if !errors.Is(err, exec.ErrNotFound) {
		t.Errorf("error %v does not wrap the underlying lookGit error", err)
	}
}

// requireGit skips the calling test when no real git binary is on PATH --
// CI and this project's own Windows/Git Bash environment both have one, but
// a test exercising the real subprocess path should degrade rather than
// fail on a machine that genuinely lacks it.
func requireGit(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH; skipping real-git spool test")
	}
}

// initFixtureTrackerRepo creates a real, tiny git repository shaped like the
// tracker's own layout (one active/ file) and returns its path -- a local
// clone SOURCE for TestUbuntuTrackerSync_RealGitCloneThenFetchReset, entirely
// offline. -c user.name/user.email are passed on the command line so the
// commit does not depend on this machine's global git config existing.
func initFixtureTrackerRepo(t *testing.T) string {
	t.Helper()
	src := filepath.Join(t.TempDir(), "src")
	if err := os.MkdirAll(filepath.Join(src, "active"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "active", "CVE-2026-9100"),
		[]byte("Candidate: CVE-2026-9100\n\nPatches_x:\njammy_x: ignored\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = src
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
	}
	run("init", "--initial-branch=master")
	run("-c", "user.name=assay-test", "-c", "user.email=assay-test@example.invalid",
		"add", "-A")
	run("-c", "user.name=assay-test", "-c", "user.email=assay-test@example.invalid",
		"commit", "-m", "seed")
	return src
}

// TestUbuntuTrackerSync_RealGitCloneThenFetchReset exercises the actual git
// mechanics (this is "a first for this project", per the brief): a fresh
// destination clones, and a SECOND sync of the same destination takes the
// fetch+reset branch rather than re-cloning -- both must leave a readable
// HEAD timestamp behind, and the destination's .git directory proves which
// branch ran (a clone creates it from nothing; a fetch+reset never removes
// it).
func TestUbuntuTrackerSync_RealGitCloneThenFetchReset(t *testing.T) {
	requireGit(t)
	src := initFixtureTrackerRepo(t)
	dst := filepath.Join(t.TempDir(), "spool")

	asOf1, err := ubuntuTrackerSync(context.Background(), dst, src)
	if err != nil {
		t.Fatalf("ubuntuTrackerSync (clone): %v", err)
	}
	if asOf1.IsZero() || asOf1.After(time.Now().Add(time.Minute)) {
		t.Errorf("asOf = %v, want a real, recent HEAD timestamp", asOf1)
	}
	if _, err := os.Stat(filepath.Join(dst, ".git")); err != nil {
		t.Fatalf("clone did not leave a .git directory behind: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dst, "active", "CVE-2026-9100")); err != nil {
		t.Fatalf("clone did not check out the fixture file: %v", err)
	}

	// Second sync of the SAME destination: this is the fetch+reset branch,
	// not a second clone. It must succeed and report a timestamp again.
	asOf2, err := ubuntuTrackerSync(context.Background(), dst, src)
	if err != nil {
		t.Fatalf("ubuntuTrackerSync (fetch+reset): %v", err)
	}
	if asOf2.IsZero() {
		t.Error("second sync (fetch+reset) returned a zero timestamp")
	}
	if _, err := os.Stat(filepath.Join(dst, "active", "CVE-2026-9100")); err != nil {
		t.Fatalf("fetch+reset lost the fixture file: %v", err)
	}
}

// TestParseUbuntuTracker_RealClone runs the full sync+parse pair against the
// real-git fixture, proving the two halves compose: a cloned working tree
// parses into a tracker the same way a hand-built temp directory does in
// ubuntu_fixstate_test.go.
func TestParseUbuntuTracker_RealClone(t *testing.T) {
	requireGit(t)
	src := initFixtureTrackerRepo(t)
	dst := filepath.Join(t.TempDir(), "spool")
	if _, err := ubuntuTrackerSync(context.Background(), dst, src); err != nil {
		t.Fatalf("ubuntuTrackerSync: %v", err)
	}
	var st stats
	tracker, err := parseUbuntuTracker(dst, &st)
	if err != nil {
		t.Fatalf("parseUbuntuTracker: %v", err)
	}
	entry, found := tracker.lookup("CVE-2026-9100", "x", "22.04")
	if !found {
		t.Fatal("tracker.lookup found no entry for the cloned fixture's tuple")
	}
	if entry.state != "ignored" {
		t.Errorf("state = %q, want ignored", entry.state)
	}
	if st.UbuntuTuplesLoaded != 1 {
		t.Errorf("UbuntuTuplesLoaded = %d, want 1", st.UbuntuTuplesLoaded)
	}
}
