package dbcmd

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kun9497/assay/internal/store"
)

// D169. A signature says who built an artifact, not that it is still the
// current one: every artifact ever signed verifies for ever, so a registry or
// mirror serving an old tag replaced a newer database with exit 0 (QA
// 2026-11-20). A tag is followed forward only; going back is named.

var (
	olderBuild = time.Date(2026, 10, 1, 6, 0, 0, 0, time.UTC)
	newerBuild = time.Date(2026, 11, 1, 6, 0, 0, 0, time.UTC)
)

// builtAt writes a database that says it was built at when.
func builtAt(t *testing.T, path string, when time.Time) string {
	t.Helper()
	w, err := store.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.SetMeta(store.Meta{
		BuiltAt:   when,
		Providers: map[string]store.Provenance{"osv": {Source: "https://example.test", DataAsOf: when}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func builtAtOf(t *testing.T, path string) time.Time {
	t.Helper()
	db, err := store.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer db.Close()
	m, err := db.Meta()
	if err != nil {
		t.Fatal(err)
	}
	return m.BuiltAt
}

// olderOverNewer publishes a signed artifact built in October and installs a
// database built in November where the pull will land.
func olderOverNewer(t *testing.T) (ref, dst string) {
	t.Helper()
	ref = publishedFrom(t, builtAt(t, filepath.Join(t.TempDir(), "src.db"), olderBuild), store.SchemaVersion, nil)
	dst = builtAt(t, filepath.Join(t.TempDir(), "vulnerability.db"), newerBuild)
	return ref, dst
}

func TestPull_AnOlderArtifactDoesNotReplaceANewerDatabase(t *testing.T) {
	ref, dst := olderOverNewer(t)

	var out, errOut bytes.Buffer
	if code := Pull(context.Background(), dst, ref, false, &out, &errOut); code != 2 {
		t.Fatalf("Pull = %d, want 2: the artifact is a month older than the installed database (stderr: %s)", code, errOut.String())
	}
	for _, want := range []string{
		"was built 2026-10-01T06:00:00Z, before the database already installed (2026-11-01T06:00:00Z)",
		"--allow-older",
		"@sha256:",
	} {
		if !strings.Contains(errOut.String(), want) {
			t.Errorf("stderr lacks %q:\n%s", want, errOut.String())
		}
	}
	if got := builtAtOf(t, dst); !got.Equal(newerBuild) {
		t.Errorf("installed database is now built %v, want the newer one left in place", got)
	}
	if _, err := os.Stat(dst + ".tmp"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the refused download was left behind (stat err = %v)", err)
	}
}

// Going back is something an operator may do on purpose, in either of two
// ways: the flag, or naming the exact artifact by digest.
func TestPull_AnOlderArtifactIsInstalledWhenTheOperatorNamesIt(t *testing.T) {
	t.Run("--allow-older", func(t *testing.T) {
		ref, dst := olderOverNewer(t)
		var out, errOut bytes.Buffer
		if code := PullWith(context.Background(), dst, ref, PullOptions{AllowOlder: true}, &out, &errOut); code != 0 {
			t.Fatalf("PullWith(AllowOlder) = %d, want 0 (stderr: %s)", code, errOut.String())
		}
		if got := builtAtOf(t, dst); !got.Equal(olderBuild) {
			t.Errorf("installed database is built %v, want the older artifact", got)
		}
	})
	t.Run("by digest", func(t *testing.T) {
		ref, dst := olderOverNewer(t)
		r, digest := digestOf(t, ref)
		pinned := r.Context().String() + "@" + digest
		var out, errOut bytes.Buffer
		if code := Pull(context.Background(), dst, pinned, false, &out, &errOut); code != 0 {
			t.Fatalf("Pull(%s) = %d, want 0: a digest names one artifact (stderr: %s)", pinned, code, errOut.String())
		}
		if got := builtAtOf(t, dst); !got.Equal(olderBuild) {
			t.Errorf("installed database is built %v, want the older artifact", got)
		}
	})
}

// What must keep working without any flag: the ordinary forward update, and
// pulling the artifact already installed.
func TestPull_ANewerOrIdenticalArtifactNeedsNoFlag(t *testing.T) {
	for name, installed := range map[string]time.Time{"newer artifact": olderBuild, "same build": newerBuild} {
		t.Run(name, func(t *testing.T) {
			ref := publishedFrom(t, builtAt(t, filepath.Join(t.TempDir(), "src.db"), newerBuild), store.SchemaVersion, nil)
			dst := builtAt(t, filepath.Join(t.TempDir(), "vulnerability.db"), installed)
			var out, errOut bytes.Buffer
			if code := Pull(context.Background(), dst, ref, false, &out, &errOut); code != 0 {
				t.Fatalf("Pull = %d, want 0 (stderr: %s)", code, errOut.String())
			}
			if rec := artifactOf(t, dst); rec == nil {
				t.Error("the database in place carries no artifact record, so the pull did not install")
			}
		})
	}
}
