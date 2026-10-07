//go:build windows

package dbcmd

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

// tryLockExclusive takes LockFileEx's exclusive lock over the whole file
// without waiting (D116). x/sys/windows rather than a hand-rolled syscall:
// it is already a direct dependency (D107), so this links nothing new.
//
// The range is the largest one the call accepts, not the file's current
// size: the lock file stays empty, and a lock on bytes that do not exist is
// still a lock -- Windows tracks ranges, not contents. Locks are per handle,
// so a second open in the same process conflicts, as a second process would.
func tryLockExclusive(f *os.File) error {
	err := windows.LockFileEx(windows.Handle(f.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0, ^uint32(0), ^uint32(0), new(windows.Overlapped))
	if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
		return errLockHeld
	}
	return err
}

func unlockFile(f *os.File) error {
	return windows.UnlockFileEx(windows.Handle(f.Fd()), 0, ^uint32(0), ^uint32(0), new(windows.Overlapped))
}
