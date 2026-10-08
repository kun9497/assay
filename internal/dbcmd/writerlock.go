package dbcmd

import (
	"errors"
	"fmt"
	"io"
	"os"
)

// writerBusyError is the refusal a second database writer gets (D116). Its
// own type, not a wrapped I/O error, because the two mean opposite things to
// the person reading them: busy is "someone else is doing this right now,
// rerun later", while a failure to open or lock the file at all is a broken
// directory or filesystem that rerunning will not fix.
type writerBusyError struct{ lockPath string }

func (e *writerBusyError) Error() string {
	return fmt.Sprintf("another assay process is writing this database (lock held: %s); "+
		"wait for it to finish or stop it, then rerun", e.lockPath)
}

// acquireWriterLock takes the exclusive writer lock on dbPath+".lock" for
// `db build` (Update) and `db update` (Pull), and returns the function that
// lets it go (D116). Callers take it after MkdirAll and before the first
// touch of dbPath+".tmp", and defer release so the lock spans the whole
// temp-write-and-rename, failed rename included.
//
// The lock is the operating system's own (flock / LockFileEx), not a file
// whose existence is the lock. An O_EXCL lock file is pure standard library
// and outlives a crashed holder, and every cure for that -- a pid inside
// checked for liveness, an age past which it is presumed dead -- is a second
// rule whose failure is two writers racing again because one decided the
// other's lock was stale. An OS lock has no such state: a writer that dies,
// however it dies, releases it by dying.
//
// It refuses rather than waits. A build runs half an hour or more, and a
// second writer quietly queued behind it would look hung for that long --
// indistinguishable from the Windows deadlock this replaces, where the
// second writer sat in bbolt's own lock on the shared temp file forever. A
// refusal naming the lock file is something a person or a CI step can act
// on at once; a --wait flag is a later, smaller decision than a default
// that blocks.
//
// The temp name stays dbPath+".tmp": under this lock nothing else can be
// writing it, and a leftover from a crashed writer is removed by the next
// one exactly as before.
//
// The lock FILE is never deleted, only unlocked. Unlinking it on release
// races the next writer's open: that writer locks the old, now-nameless
// inode while a third creates and locks a fresh one, and two writers each
// hold "the" lock. An empty file left beside the database costs nothing.
//
// Scope is one machine. Readers never look at it (a scan's read-only open
// must never wait on a build), and file locks over a network filesystem
// shared between machines are their own problem this does not claim to
// solve.
func acquireWriterLock(dbPath string) (release func(), err error) {
	lockPath := dbPath + ".lock"
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := tryLockExclusive(f); err != nil {
		f.Close()
		if errors.Is(err, errLockHeld) {
			return nil, &writerBusyError{lockPath: lockPath}
		}
		return nil, err
	}
	return func() {
		// Unlocked explicitly before the close rather than left to it:
		// Windows documents that a lock outstanding at close is released
		// only "when the system can", not at once, and the next build in
		// the same process (or a test) would be refused in that gap. No
		// test can hold this line: the close-time release has been
		// immediate everywhere it was tried, so dropping the unlock leaves
		// the suite green. It stays on the documentation's word.
		_ = unlockFile(f)
		_ = f.Close()
	}, nil
}

// errLockHeld is what each platform's tryLockExclusive returns when another
// holder has the lock, so acquireWriterLock can tell busy from broken
// without knowing which errno or Windows error code means busy.
var errLockHeld = errors.New("lock held by another writer")

// writerLockFailed renders a failed acquireWriterLock for a caller, which
// then returns 2: busy as itself (it is already a sentence a person can act
// on), anything else under a prefix naming what was being attempted.
func writerLockFailed(stderr io.Writer, err error) {
	var busy *writerBusyError
	if errors.As(err, &busy) {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return
	}
	fmt.Fprintf(stderr, "error: lock database for writing: %v\n", err)
}
