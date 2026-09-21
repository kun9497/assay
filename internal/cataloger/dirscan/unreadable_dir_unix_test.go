//go:build !windows

package dirscan

import (
	"os"
	"testing"
)

// makeUnreadable makes dir impossible to enumerate for the rest of the test by
// dropping every permission bit. See the Windows build of this file for why
// the two are separate and why the same few lines are duplicated in
// internal/scancmd rather than exported.
//
// Root ignores the mode entirely, so the precondition cannot be established
// there and the test skips rather than asserting a pass it did not earn. CI
// runs as a non-root user, so the real coverage is not lost.
func makeUnreadable(t *testing.T, dir string) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("running as root: mode 0o000 does not deny root, so an unreadable directory cannot be staged")
	}
	if err := os.Chmod(dir, 0o000); err != nil {
		t.Skipf("could not drop permissions on %q: %v", dir, err)
	}
	// Registered after t.TempDir()'s own cleanup so LIFO ordering restores the
	// mode before the temp tree is removed.
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
}
