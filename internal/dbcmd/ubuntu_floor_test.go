package dbcmd

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kun9497/assay/internal/store"
)

// withUbuntuFixStates builds a database whose osv provider stamped n Ubuntu
// fix states (Provenance.UbuntuFixStates), over Ubuntu:22.04:LTS coverage.
func withUbuntuFixStates(t *testing.T, n int) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vulnerability.db")
	w, err := store.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.SetMeta(store.Meta{
		BuiltAt: time.Date(2026, 10, 30, 6, 0, 0, 0, time.UTC),
		Providers: map[string]store.Provenance{"osv": {
			DataAsOf: time.Date(2026, 10, 29, 0, 0, 0, 0, time.UTC), Ecosystems: []string{"Ubuntu:22.04:LTS"},
			UbuntuFixStates: n,
		}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

// D157 (audit A15), the publish half: the build fails on a tracker that
// yields nothing, but a tracker that loses part of itself (active/ moved,
// retired/ kept) still stamps something. The stamped count rides on the
// artifact, and a candidate below 80% of the published one is refused --
// 2,094,636 states on 2026-10-29, 2,070,238 two days before, so the floor
// leaves room for the tracker's own churn and none for losing a release.
func TestPush_D157_RefusesToLoseUbuntuFixStates(t *testing.T) {
	for _, tc := range []struct {
		name     string
		incoming int
		code     int
	}{
		{"all of them", 0, 2},
		{"most of them", 1000, 2},
		{"just under the floor", 7999, 2},
		{"exactly the floor", 8000, 0},
		{"the tracker's own churn", 9900, 0},
		{"more", 12000, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ref := liveRegistry(t)
			var out, errOut bytes.Buffer
			if code := Push(context.Background(), withUbuntuFixStates(t, 10000), ref, false, &out, &errOut); code != 0 {
				t.Fatalf("seeding = %d (%s)", code, errOut.String())
			}
			if got := publishedMeta(t, ref); got.UbuntuFixStates != 10000 || !got.UbuntuFixStatesKnown {
				t.Fatalf("published UbuntuFixStates = %d (known %v), want 10000 on the artifact", got.UbuntuFixStates, got.UbuntuFixStatesKnown)
			}
			signPublished(t, ref)
			errOut.Reset()
			code := Push(context.Background(), withUbuntuFixStates(t, tc.incoming), ref, false, &out, &errOut)
			if code != tc.code {
				t.Errorf("Push of %d over 10000 = %d, want %d (%s)", tc.incoming, code, tc.code, errOut.String())
			}
			if tc.code == 2 && !strings.Contains(errOut.String(), "Ubuntu fix state") {
				t.Errorf("stderr does not name the regression:\n%s", errOut.String())
			}
		})
	}
}

// An artifact published before the annotation existed has no count to hold
// the candidate to; the push is not refused for it, and says so.
func TestPush_D157_AnArtifactWithoutTheCountIsNotCompared(t *testing.T) {
	ref := liveRegistry(t)
	seed(t, ref, time.Time{}, 0) // no Ubuntu coverage, no annotation
	var out, errOut bytes.Buffer
	if code := Push(context.Background(), withUbuntuFixStates(t, 5), ref, false, &out, &errOut); code != 0 {
		t.Errorf("Push = %d, want 0 (%s)", code, errOut.String())
	}
}
