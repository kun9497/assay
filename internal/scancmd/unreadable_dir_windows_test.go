//go:build windows

package scancmd

import (
	"syscall"
	"testing"
)

// makeUnreadable makes dir impossible to enumerate for the rest of the test.
//
// Windows has no mode bits to drop - 0o000 on a directory is not enforced - so
// the equivalent is an exclusive handle: CreateFile with a share mode of 0
// means every later open of that directory, including the FindFirstFile behind
// os.ReadDir, fails with ERROR_SHARING_VIOLATION. FILE_FLAG_BACKUP_SEMANTICS
// is what allows CreateFile to open a directory at all.
//
// These few lines are duplicated in the dirscan package's own test rather than
// exported from one: a test helper shared across packages would have to live in
// non-test code, which is a worse trade than two copies of a five-line
// syscall.
//
// The cleanup is registered here, AFTER t.TempDir() registered its own, so
// LIFO ordering closes the handle before the temp tree is removed - Windows
// refuses to delete a directory that is still held open, and that failure
// would surface as an unrelated cleanup error rather than as anything about
// this test.
func makeUnreadable(t *testing.T, dir string) {
	t.Helper()
	p, err := syscall.UTF16PtrFromString(dir)
	if err != nil {
		t.Skipf("cannot encode %q as a Windows path: %v", dir, err)
	}
	h, err := syscall.CreateFile(p, syscall.GENERIC_READ, 0 /* no sharing */, nil,
		syscall.OPEN_EXISTING, syscall.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		t.Skipf("could not take an exclusive handle on %q: %v", dir, err)
	}
	t.Cleanup(func() { _ = syscall.CloseHandle(h) })
}
