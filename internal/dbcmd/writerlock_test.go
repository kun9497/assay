package dbcmd

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// holdWriterLock takes dbPath's writer lock through the same primitive the
// commands use, standing in for a second assay process mid-build. Same
// primitive on purpose: a test that held the lock some other way (an
// O_EXCL file, a bare open) would prove only that the commands notice THAT,
// not that two real writers exclude each other.
//
// Registered with t.Cleanup AFTER the caller's t.TempDir, so it runs first:
// on Windows a directory holding an open handle cannot be removed.
func holdWriterLock(t *testing.T, dbPath string) {
	t.Helper()
	release, err := acquireWriterLock(dbPath)
	if err != nil {
		t.Fatalf("the test could not take the writer lock it means to hold: %v", err)
	}
	t.Cleanup(release)
}

// within runs a command and fails the test if it has not returned after d,
// rather than letting it hang the suite. D116's whole point is that a second
// writer refuses at once; a writer that waited on the lock instead would
// otherwise turn a red test into a stuck CI job, which is exactly the
// can't-tell-it-from-a-deadlock symptom the decision removes.
func within[T any](t *testing.T, d time.Duration, run func() T) T {
	t.Helper()
	done := make(chan T, 1)
	go func() { done <- run() }()
	select {
	case got := <-done:
		return got
	case <-time.After(d):
		t.Fatalf("still running after %v: a second writer waited on the lock instead of refusing (D116)", d)
		var zero T
		return zero
	}
}

// plantInFlightTemp writes a stand-in for the lock holder's half-written
// <dbPath>.tmp and returns its bytes. "No temp file exists afterwards"
// cannot tell a refused writer that never reached the temp path from one
// that removed it on the way in -- the Linux outcome D116 records, where the
// second writer's os.Remove unlinks the file the first is still filling. A
// planted file that must survive byte for byte tells the two apart.
func plantInFlightTemp(t *testing.T, dbPath string) []byte {
	t.Helper()
	body := []byte("the lock holder's half-written database")
	if err := os.WriteFile(dbPath+".tmp", body, 0o600); err != nil {
		t.Fatal(err)
	}
	return body
}

// assertUnchanged fails unless path still holds exactly want.
func assertUnchanged(t *testing.T, path string, want []byte, what string) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%s is gone after a refused writer: %v", what, err)
	}
	if string(got) != string(want) {
		t.Errorf("%s was modified by a writer that should have been refused", what)
	}
}

// The primitive itself, on whichever platform runs it: a second acquire on
// the same path is refused while the first is held, and succeeds once it is
// released. Same process on purpose -- flock is per open file description
// and LockFileEx per handle, so two opens in one process conflict exactly as
// two processes do, and the test needs no subprocess.
func TestAcquireWriterLock_ExcludesASecondWriterUntilReleased(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "vulnerability.db")

	first, err := acquireWriterLock(dbPath)
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	// Guarded: a lock that blocked instead of refusing would otherwise hang
	// here until go test's own ten-minute timeout.
	err = within(t, 10*time.Second, func() error {
		_, err := acquireWriterLock(dbPath)
		return err
	})
	if err == nil {
		t.Fatal("second acquire succeeded while the first was held")
	} else {
		var busy *writerBusyError
		if !errors.As(err, &busy) {
			t.Fatalf("second acquire failed with %T (%v), want *writerBusyError -- a held lock "+
				"must read as busy, not as an I/O failure", err, err)
		}
		if busy.lockPath != dbPath+".lock" {
			t.Errorf("busy error names %q, want %q", busy.lockPath, dbPath+".lock")
		}
	}

	first()
	third, err := acquireWriterLock(dbPath)
	if err != nil {
		t.Fatalf("acquire after release: %v -- releasing did not release", err)
	}
	third()

	// Never deleted: unlinking a lock file another process may be opening is
	// how two writers end up holding locks on two different inodes.
	if _, err := os.Stat(dbPath + ".lock"); err != nil {
		t.Errorf("the lock file is gone after release: %v", err)
	}
}

// The message is what a person or a CI log sees; it must name the file.
func TestWriterBusyError_NamesTheLockFile(t *testing.T) {
	err := &writerBusyError{lockPath: "/var/db/assay/vulnerability.db.lock"}
	const want = "another assay process is writing this database " +
		"(lock held: /var/db/assay/vulnerability.db.lock); wait for it to finish or stop it, then rerun"
	if err.Error() != want {
		t.Errorf("Error() =\n  %s\nwant\n  %s", err.Error(), want)
	}
}

// The non-busy branch is the one an operator sees for a permission or I/O
// failure on the lock file; its prefix is what tells it apart from a busy
// refusal, so the prefix is held here rather than left to drift.
func TestWriterLockFailed_NonBusyFailureKeepsItsPrefix(t *testing.T) {
	var out bytes.Buffer
	writerLockFailed(&out, errors.New("open /var/db/assay/vulnerability.db.lock: permission denied"))
	const want = "error: lock database for writing: open /var/db/assay/vulnerability.db.lock: permission denied\n"
	if out.String() != want {
		t.Errorf("stderr =\n  %q\nwant\n  %q", out.String(), want)
	}
	out.Reset()
	writerLockFailed(&out, &writerBusyError{lockPath: "x.lock"})
	if strings.Contains(out.String(), "lock database for writing") {
		t.Errorf("a busy refusal must not carry the I/O-failure prefix:\n%s", out.String())
	}
}
