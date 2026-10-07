//go:build !windows

// Every non-Windows target the project releases (linux, darwin; .goreleaser.yaml)
// has flock(2). The tag says !windows rather than listing them so a new Unix
// target compiles here by default; solaris and aix, which lack syscall.Flock,
// are not release targets and are out of scope until one is.

package dbcmd

import (
	"errors"
	"os"
	"syscall"
)

// tryLockExclusive takes flock(2)'s exclusive lock without waiting (D116).
// flock rather than fcntl's POSIX record locks: a POSIX lock belongs to the
// process and is dropped when ANY descriptor the process holds on the file
// is closed, so an unrelated open-and-close of the lock path would silently
// release it. flock belongs to the open file description, which is also why
// a second open in the same process conflicts, as a second process would.
func tryLockExclusive(f *os.File) error {
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return nil
		}
		// A signal can interrupt even a non-blocking call; that is not an
		// answer about the lock, so ask again.
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return errLockHeld
		}
		return err
	}
}

func unlockFile(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
}
