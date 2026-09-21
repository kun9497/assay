package osv

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fastTrackerRetries(t *testing.T) {
	t.Helper()
	old := trackerRetryWaits
	trackerRetryWaits = []time.Duration{0, 0}
	t.Cleanup(func() { trackerRetryWaits = old })
}

func TestUbuntuTrackerSync_RetriesFetchAfter503(t *testing.T) {
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
			return nil, fmt.Errorf("RPC failed; HTTP 503 curl 22 The requested URL returned error: 503")
		}
		return gitRun(ctx, dir, args...)
	}
	if _, err := ubuntuTrackerSync(context.Background(), dst, src); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("fetch attempts=%d", calls)
	}
}

func TestUbuntuTrackerSync_RetryCloneDiscardsOnlyItsPartialDirectory(t *testing.T) {
	fastTrackerRetries(t)
	src := initFixtureTrackerRepo(t)
	dst := filepath.Join(t.TempDir(), "spool")
	old := trackerGitRun
	t.Cleanup(func() { trackerGitRun = old })
	var first string
	calls := 0
	trackerGitRun = func(ctx context.Context, dir string, args ...string) ([]byte, error) {
		calls++
		staged := args[len(args)-1]
		if calls == 1 {
			first = staged
			if err := os.WriteFile(filepath.Join(staged, "partial"), []byte("x"), 0600); err != nil {
				return nil, err
			}
			return nil, fmt.Errorf("remote end hung up unexpectedly")
		}
		if staged == first {
			t.Error("reused partial clone")
		}
		if _, err := os.Stat(first); !os.IsNotExist(err) {
			t.Error("failed clone was not removed")
		}
		return gitRun(ctx, dir, args...)
	}
	if _, err := ubuntuTrackerSync(context.Background(), dst, src); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("clone attempts=%d", calls)
	}
	if _, err := os.Stat(filepath.Join(dst, "partial")); !os.IsNotExist(err) {
		t.Fatal("partial data installed")
	}
}

func TestTrackerRetry_PermanentFailureAndCancellation(t *testing.T) {
	fastTrackerRetries(t)
	for _, msg := range []string{"authentication failed", "URL returned error: 403", "repository not found"} {
		calls := 0
		err := retryTrackerGit(context.Background(), func(context.Context) error { calls++; return fmt.Errorf("%s", msg) })
		if err == nil || calls != 1 || !strings.Contains(err.Error(), msg) {
			t.Fatalf("calls=%d err=%v", calls, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := retryTrackerGit(ctx, func(context.Context) error { t.Fatal("called after cancellation"); return nil }); err != context.Canceled {
		t.Fatal(err)
	}
	calls := 0
	if err := retryTrackerGit(context.Background(), func(context.Context) error { calls++; return fmt.Errorf("HTTP 503") }); err == nil || calls != 3 {
		t.Fatalf("unbounded retry: calls=%d err=%v", calls, err)
	}
}

func TestTrackerRetry_PerAttemptTimeout(t *testing.T) {
	fastTrackerRetries(t)
	old := trackerGitTimeout
	trackerGitTimeout = time.Millisecond
	t.Cleanup(func() { trackerGitTimeout = old })
	calls := 0
	err := retryTrackerGit(context.Background(), func(ctx context.Context) error {
		calls++
		if calls == 1 {
			<-ctx.Done()
			return ctx.Err()
		}
		return nil
	})
	if err != nil || calls != 2 {
		t.Fatalf("calls=%d err=%v", calls, err)
	}
}
