package osv

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
)

// A response Launchpad cut short is transient, however git words it. The
// 2026-10-22 nightly died on the first row's exact message and the
// 2026-10-06 one at the same step: the retry existed, but the classifier
// read a truncated ref listing as permanent, so no second attempt ran. Each
// row fails the first fetch and must succeed on the second.
func TestUbuntuTrackerSync_RetriesAResponseCutShort(t *testing.T) {
	for _, msg := range []string{
		// The 2026-10-22 nightly, verbatim (run 39768961219).
		"git fetch --depth 1 origin HEAD: exit status 128: fatal: expected flush after ref listing",
		"exit status 128: error: RPC failed; curl 18 transfer closed with outstanding read data remaining",
		"exit status 128: fetch-pack: unexpected disconnect while reading sideband packet",
		"exit status 128: fatal: protocol error: bad pack header",
		"exit status 128: fatal: the remote end hung up unexpectedly",
		"exit status 128: error: RPC failed; curl 92 HTTP/2 stream 5 was not closed cleanly: INTERNAL_ERROR (err 2)",
	} {
		t.Run(msg[len(msg)-30:], func(t *testing.T) {
			fastTrackerRetries(t)
			src := initFixtureTrackerRepo(t)
			dst := filepath.Join(t.TempDir(), "spool")
			if _, err := ubuntuTrackerSync(context.Background(), dst, src); err != nil {
				t.Fatal(err)
			}
			old := trackerGitRun
			t.Cleanup(func() { trackerGitRun = old })
			calls := 0
			trackerGitRun = func(ctx context.Context, dir string, args ...string) ([]byte, error) {
				calls++
				if calls == 1 {
					return nil, fmt.Errorf("%s", msg)
				}
				return gitRun(ctx, dir, args...)
			}
			if _, err := ubuntuTrackerSync(context.Background(), dst, src); err != nil {
				t.Fatalf("a response cut short was not retried: %v", err)
			}
			if calls != 2 {
				t.Errorf("fetch attempts = %d, want 2", calls)
			}
		})
	}
}

// What must stay permanent: a repository or credential problem needs an
// operator, and retrying it only delays the failure that says so.
func TestTransientTrackerGit_PermanentStaysPermanent(t *testing.T) {
	for _, msg := range []string{
		"fatal: repository 'https://git.launchpad.net/x/' not found",
		"fatal: Authentication failed for 'https://git.launchpad.net/'",
		"The requested URL returned error: 403",
		"fatal: not a git repository (or any of the parent directories): .git",
	} {
		if transientTrackerGit(fmt.Errorf("%s", msg)) {
			t.Errorf("%q classified transient, want permanent", msg)
		}
	}
}
