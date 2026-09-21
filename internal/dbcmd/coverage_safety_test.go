package dbcmd

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/dbartifact"
	"github.com/kun9497/assay/internal/provider"
	"github.com/kun9497/assay/internal/provider/nvd"
	"github.com/kun9497/assay/internal/store"
)

func TestUpdate_ResumesNVDFromSeedCheckpoint(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	checkpoint := now.Add(-10 * 24 * time.Hour)
	seedPath := filepath.Join(t.TempDir(), "seed.db")
	w, err := store.Create(seedPath)
	if err != nil {
		t.Fatal(err)
	}
	since := now.Add(-60 * 24 * time.Hour)
	if err := w.SetMeta(store.Meta{Ratings: map[string]store.Provenance{"NVD": {CoversSince: since, CoversSinceKnown: true, CoversUntil: checkpoint, CoversUntilKnown: true}}}); err != nil {
		t.Fatal(err)
	}
	w.Close()
	var gotStart time.Time
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var err error
		gotStart, err = time.Parse(time.RFC3339Nano, r.URL.Query().Get("lastModStartDate"))
		if err != nil {
			t.Error(err)
		}
		io.WriteString(w, `{"totalResults":0,"timestamp":"2026-09-21T00:00:01.000","vulnerabilities":[]}`)
	}))
	defer srv.Close()
	pause := time.Duration(0)
	a := nvd.New(nvd.Options{BaseURL: srv.URL, Since: now.Add(-3 * 24 * time.Hour), Pause: &pause})
	dst := filepath.Join(t.TempDir(), "out.db")
	var logs bytes.Buffer
	if code := Update(context.Background(), dst, seedPath, "", false, nil, []provider.Annotator{a}, nil, nil, io.Discard, &logs); code != 0 {
		t.Fatalf("build=%d: %s", code, &logs)
	}
	if !gotStart.Equal(checkpoint.Add(-24 * time.Hour)) {
		t.Fatalf("seed checkpoint not passed to annotator: %v", gotStart)
	}
	db, err := store.Open(dst)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	m, err := db.Meta()
	if err != nil {
		t.Fatal(err)
	}
	if !m.Ratings["NVD"].CoversSince.Equal(since) || m.Ratings["NVD"].CoversUntil.Before(now) {
		t.Fatalf("wrong merged window: %+v", m.Ratings["NVD"])
	}
}

func TestPush_LegacyManifestStillChecksAdvisoryLoss(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	w, err := store.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Put(advisory.Advisory{ID: "GHSA-legacy", Affected: []advisory.Affected{{Ecosystem: "Go", Name: "a"}}}); err != nil {
		t.Fatal(err)
	}
	if err := w.SetMeta(store.Meta{Providers: map[string]store.Provenance{"osv": {Ecosystems: []string{"Go"}}}}); err != nil {
		t.Fatal(err)
	}
	w.Close()
	img, err := dbartifact.Pack(path, dbartifact.Meta{SchemaVersion: store.SchemaVersion})
	if err != nil {
		t.Fatal(err)
	}
	ref := liveRegistry(t)
	target, err := name.ParseReference(ref)
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.Write(target, img); err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	if code := Push(context.Background(), bounded(t, time.Time{}, 0), ref, false, io.Discard, &logs); code != 2 {
		t.Fatalf("legacy advisory loss published: %d %s", code, &logs)
	}
	before, _ := img.Digest()
	after, err := remote.Image(target)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := after.Digest()
	if before != got {
		t.Fatal("refused push changed the manifest")
	}
}

func TestAdvisoryRegression_WithdrawalsAndMissingCoverage(t *testing.T) {
	base := &dbartifact.AdvisoryCoverage{Total: 100, Counts: map[string]int{"Go": 100}, Ecosystems: []string{"Go"}, Providers: []string{"osv"}}
	for _, tc := range []struct {
		name   string
		next   dbartifact.AdvisoryCoverage
		refuse bool
	}{
		{"small withdrawal", dbartifact.AdvisoryCoverage{Total: 99, Counts: map[string]int{"Go": 99}, Ecosystems: []string{"Go"}, Providers: []string{"osv"}}, false},
		{"boundary", dbartifact.AdvisoryCoverage{Total: 80, Counts: map[string]int{"Go": 80}, Ecosystems: []string{"Go"}, Providers: []string{"osv"}}, false},
		{"large drop", dbartifact.AdvisoryCoverage{Total: 79, Counts: map[string]int{"Go": 79}, Ecosystems: []string{"Go"}, Providers: []string{"osv"}}, true},
		{"provider missing", dbartifact.AdvisoryCoverage{Total: 100, Counts: map[string]int{"Go": 100}, Ecosystems: []string{"Go"}}, true},
		{"ecosystem missing", dbartifact.AdvisoryCoverage{Total: 100, Counts: map[string]int{"Go": 100}, Providers: []string{"osv"}}, true},
		{"masked by another ecosystem", dbartifact.AdvisoryCoverage{Total: 100, Counts: map[string]int{"Go": 1, "npm": 99}, Ecosystems: []string{"Go", "npm"}, Providers: []string{"osv"}}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := advisoryRegression(base, &tc.next); (got != "") != tc.refuse {
				t.Fatalf("reason=%q refuse=%v", got, tc.refuse)
			}
		})
	}
}

func TestRatingCountRegression_SnapshotsMayShrinkButNVDMayNot(t *testing.T) {
	cur := dbartifact.Meta{RatingCounts: map[string]int{"NVD": 100, "KEV": 5}}
	for _, tc := range []struct {
		counts map[string]int
		refuse bool
	}{
		{map[string]int{"NVD": 100, "KEV": 4}, false},
		{map[string]int{"NVD": 99, "KEV": 100}, true},
		{map[string]int{"NVD": 100}, true},
		{map[string]int{"NVD": 100, "KEV": 0}, false},
	} {
		t.Run(fmt.Sprint(tc.counts), func(t *testing.T) {
			if got := ratingCountRegression(cur, dbartifact.Meta{RatingCounts: tc.counts}); (got != "") != tc.refuse {
				t.Fatalf("reason=%q refuse=%v", got, tc.refuse)
			}
		})
	}
}

func TestMergeRatingCoverage_ConnectedSpansKeepTheLaterEnd(t *testing.T) {
	date := func(day int) time.Time { return time.Date(2026, 9, day, 0, 0, 0, 0, time.UTC) }
	for _, tc := range []struct{ s1, e1, s2, e2, start, end int }{{1, 10, 1, 8, 1, 10}, {1, 10, 1, 20, 1, 20}, {5, 10, 1, 20, 1, 20}, {1, 20, 5, 10, 1, 20}} {
		s := store.Provenance{CoversSince: date(tc.s1), CoversSinceKnown: true, CoversUntil: date(tc.e1), CoversUntilKnown: true}
		f := store.Provenance{CoversSince: date(tc.s2), CoversSinceKnown: true, CoversUntil: date(tc.e2), CoversUntilKnown: true}
		got := mergeRatingCoverage(s, f)
		if !got.CoversSince.Equal(date(tc.start)) || !got.CoversUntil.Equal(date(tc.end)) {
			t.Fatalf("%+v: %+v", tc, got)
		}
	}
}
