package dbcmd

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/dbartifact"
	"github.com/kun9497/assay/internal/provider"
	"github.com/kun9497/assay/internal/store"
)

func TestBuildSafety_RatingsOnlyRemovesDeletedKEV(t *testing.T) {
	seedPath := filepath.Join(t.TempDir(), "seed.db")
	w, err := store.Create(seedPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.PutRating(advisory.Rating{CVE: "CVE-2026-1111", Source: "KEV", KEV: true}); err != nil {
		t.Fatal(err)
	}
	if err := w.PutRating(advisory.Rating{CVE: "CVE-2026-3333", Source: "KEV", KEV: true}); err != nil {
		t.Fatal(err)
	}
	if err := w.SetMeta(store.Meta{Ratings: map[string]store.Provenance{"KEV": {CoversSinceKnown: true}}}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	ref := liveRegistry(t)
	if code := Push(context.Background(), seedPath, ref, false, io.Discard, io.Discard); code != 0 {
		t.Fatalf("seed publish=%d", code)
	}
	dst := filepath.Join(t.TempDir(), "out.db")
	a := fakeAnnotator{name: "KEV", coversSinceKnown: true, ratings: []advisory.Rating{{CVE: "CVE-2026-2222", Source: "KEV", KEV: true}}}
	if code := Update(context.Background(), dst, seedPath, "", true, nil, []provider.Annotator{a}, nil, nil, io.Discard, io.Discard); code != 0 {
		t.Fatalf("build=%d", code)
	}
	db, err := store.Open(dst)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, cve := range []string{"CVE-2026-1111", "CVE-2026-3333"} {
		rs, err := db.RatingsFor(cve)
		if err != nil {
			t.Fatal(err)
		}
		if len(rs) != 0 {
			t.Fatalf("removed KEV entry survives fresh full-feed annotation: %+v", rs)
		}
	}
	if rs, err := db.RatingsFor("CVE-2026-2222"); err != nil || len(rs) != 1 || !rs[0].KEV {
		t.Fatalf("fresh KEV missing: %v %v", rs, err)
	}
	var logs bytes.Buffer
	if code := Push(context.Background(), dst, ref, false, io.Discard, &logs); code != 0 {
		t.Fatalf("legitimate KEV snapshot shrink blocked: %d %s", code, &logs)
	}
}

func TestBuildSafety_RatingsOnlyClearsDisabledSnapshots(t *testing.T) {
	seedPath := filepath.Join(t.TempDir(), "seed.db")
	w, err := store.Create(seedPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, source := range []string{"NVD", "KEV", "EPSS"} {
		if err := w.PutRating(advisory.Rating{CVE: "CVE-2026-1111", Source: source, KEV: source == "KEV"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.SetMeta(store.Meta{Ratings: map[string]store.Provenance{"NVD": {}, "KEV": {}, "EPSS": {}}}); err != nil {
		t.Fatal(err)
	}
	w.Close()
	dst := filepath.Join(t.TempDir(), "out.db")
	if code := Update(context.Background(), dst, seedPath, "", true, nil, []provider.Annotator{fakeAnnotator{name: "NVD"}}, nil, nil, io.Discard, io.Discard); code != 0 {
		t.Fatalf("build=%d", code)
	}
	db, err := store.Open(dst)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rs, err := db.RatingsFor("CVE-2026-1111")
	if err != nil || len(rs) != 1 || rs[0].Source != "NVD" {
		t.Fatalf("wrong ratings after disabling snapshots: %+v %v", rs, err)
	}
	m, err := db.Meta()
	if err != nil {
		t.Fatal(err)
	}
	for _, source := range []string{"KEV", "EPSS"} {
		if _, ok := m.Ratings[source]; ok {
			t.Fatalf("stale %s provenance survived", source)
		}
	}
}

func TestBuildSafety_ForwardGapMustNotClaimContinuousCoverage(t *testing.T) {
	date := func(s string) time.Time {
		d, err := time.Parse("2006-01-02", s)
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	seeded := store.Provenance{CoversSince: date("2026-01-01"), CoversSinceKnown: true, CoversUntil: date("2026-09-10"), CoversUntilKnown: true}
	fetched := store.Provenance{CoversSince: date("2026-09-18"), CoversSinceKnown: true, CoversUntil: date("2026-09-21"), CoversUntilKnown: true}
	got := mergeRatingCoverage(seeded, fetched)
	if !got.CoversSince.Equal(fetched.CoversSince) || !got.CoversUntil.Equal(fetched.CoversUntil) || !strings.Contains(got.Window, "does not reach") {
		t.Fatalf("must retain the new contiguous span and disclose the gap: %+v", got)
	}
}

func TestBuildSafety_RegistryReadFailureMustBlockPush(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusForbidden) }))
	defer srv.Close()
	ref, err := name.ParseReference(strings.TrimPrefix(srv.URL, "http://") + "/assay-db:v9")
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	code := refuseCoverageRegression(context.Background(), ref, dbartifact.Meta{RatingCount: 0}, false, &logs)
	if code == 0 {
		t.Fatalf("guard allows publishing after registry 403: %s", logs.String())
	}
	if code := refuseCoverageRegression(context.Background(), ref, dbartifact.Meta{}, true, &logs); code != 0 || !strings.Contains(logs.String(), "--force") {
		t.Fatalf("explicit override failed: %d %s", code, &logs)
	}
}

func TestBuildSafety_AdvisoryLossMustBlockPush(t *testing.T) {
	ref := liveRegistry(t)
	p := fakeProvider{name: "osv", covers: []string{"Go"}, advs: []advisory.Advisory{{ID: "GHSA-probe", Source: "osv", Database: "GHSA", Kind: advisory.KindVulnerability, Affected: []advisory.Affected{{Ecosystem: "Go", Name: "example.org/vulnerable"}}}}}
	p.advs = append(p.advs, advisory.Advisory{ID: "GHSA-dropped", Source: "osv", Database: "GHSA", Kind: advisory.KindVulnerability, Affected: []advisory.Affected{{Ecosystem: "Go", Name: "example.org/dropped"}}})
	a := fakeAnnotator{name: "NVD", coversSinceKnown: true, ratings: []advisory.Rating{{CVE: "CVE-2026-1111", Source: "NVD"}}}
	baseline := filepath.Join(t.TempDir(), "baseline.db")
	if code := Update(context.Background(), baseline, "", "", false, []provider.Provider{p}, []provider.Annotator{a}, nil, nil, io.Discard, io.Discard); code != 0 {
		t.Fatalf("baseline build=%d", code)
	}
	if code := Push(context.Background(), baseline, ref, false, io.Discard, io.Discard); code != 0 {
		t.Fatalf("baseline push=%d", code)
	}
	dst := filepath.Join(t.TempDir(), "empty.db")
	p.advs = p.advs[:1]
	if code := Update(context.Background(), dst, baseline, "", false, []provider.Provider{p}, []provider.Annotator{a}, nil, nil, io.Discard, io.Discard); code != 0 {
		t.Fatalf("build failed before publish guard could be exercised: %d", code)
	}
	var logs bytes.Buffer
	if code := Push(context.Background(), dst, ref, false, io.Discard, &logs); code == 0 {
		t.Fatalf("advisory count fell from 2 to 1, coverage and rating count stayed unchanged, push allowed: %s", logs.String())
	}
}
