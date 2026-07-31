package osv

import (
	"archive/zip"
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"sort"
	"testing"

	"github.com/kun9497/assay/internal/advisory"
)

func zipWith(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestFetch(t *testing.T) {
	body := zipWith(t, map[string]string{
		"GHSA-keep.json": `{"id":"GHSA-keep","affected":[{"package":{"name":"x","ecosystem":"Go"},
			"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.0.0"}]}]}]}`,
		"GHSA-gone.json": `{"id":"GHSA-gone","withdrawn":"2024-01-01T00:00:00Z",
			"affected":[{"package":{"name":"y","ecosystem":"Go"},
			"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}]}`,
		"MAL-2024-1.json": `{"id":"MAL-2024-1","affected":[{"package":{"name":"z","ecosystem":"Go"},
			"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}]}`,
	})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/Go/all.zip" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Last-Modified", "Tue, 29 Jul 2026 00:00:00 GMT")
		w.Write(body)
	}))
	defer srv.Close()

	p := New([]string{"Go"}, srv.URL)
	var got []advisory.Advisory
	prov, err := p.Fetch(context.Background(), func(a advisory.Advisory) error {
		got = append(got, a)
		return nil
	})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(got) != 1 || got[0].ID != "GHSA-keep" {
		t.Fatalf("Fetch emitted %d advisories (%v), want only GHSA-keep", len(got), got)
	}
	if prov.Records != 1 {
		t.Errorf("Provenance.Records = %d, want 1", prov.Records)
	}
	// DataAsOf must come from the upstream response, not from time.Now (D12).
	if prov.DataAsOf.Year() != 2026 || prov.DataAsOf.Month() != 7 || prov.DataAsOf.Day() != 29 {
		t.Errorf("Provenance.DataAsOf = %v, want 2026-07-29 from Last-Modified", prov.DataAsOf)
	}
	if prov.Source == "" {
		t.Error("Provenance.Source is empty; the URL actually fetched must be recorded")
	}
}

func TestFetch_UnknownTimestampMakesAggregateUnknown(t *testing.T) {
	// One ecosystem without Last-Modified makes the whole aggregate unknown.
	// Reporting min(the ones we could date) would claim a floor on staleness
	// that the undated one may well be below.
	body := zipWith(t, map[string]string{
		"GHSA-a.json": `{"id":"GHSA-a","affected":[{"package":{"name":"x","ecosystem":"Go"},
			"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}]}`,
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/Go/all.zip" {
			w.Header().Set("Last-Modified", "Tue, 29 Jul 2026 00:00:00 GMT")
		}
		// The npm response deliberately carries no Last-Modified.
		w.Write(body)
	}))
	defer srv.Close()

	p := New([]string{"Go", "npm"}, srv.URL)
	prov, err := p.Fetch(context.Background(), func(advisory.Advisory) error { return nil })
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if !prov.DataAsOf.IsZero() {
		t.Errorf("DataAsOf = %v, want zero: one ecosystem could not be dated", prov.DataAsOf)
	}
}

func TestFetch_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	defer srv.Close()

	p := New([]string{"Go"}, srv.URL)
	_, err := p.Fetch(context.Background(), func(advisory.Advisory) error { return nil })
	if err == nil {
		t.Error("Fetch over a failing server = nil error, want error")
	}
}

// A 200 response whose body is not valid JSON must fail loudly through the
// same path a real corrupted upstream file would take: Convert's decode
// error, propagated by fetchOne. This is distinct from TestFetch_HTTPError
// (a transport-level failure) — a malformed body arrives as a successful
// response with unusable content, and both must be caught.
func TestFetch_MalformedRecordBody(t *testing.T) {
	body := zipWith(t, map[string]string{
		"GHSA-broken.json": `{not json`,
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(body)
	}))
	defer srv.Close()

	p := New([]string{"Go"}, srv.URL)
	_, err := p.Fetch(context.Background(), func(advisory.Advisory) error { return nil })
	if err == nil {
		t.Error("Fetch over a malformed record body = nil error, want error")
	}
}

// Alpine ships a single archive covering every release (measured: the
// per-release archives are a frozen 2024-10-09 export, so only the
// unversioned "Alpine/" path is fetched). Fetching it must still give the two
// properties D16 and the slice-1 cross-ecosystem fix promise elsewhere, not
// just assume them here: a withdrawn record is dropped, and a record whose
// affected[] spans two releases keeps both entries.
func TestFetch_AlpineKeepsEveryRelease(t *testing.T) {
	body := zipWith(t, map[string]string{
		"CVE-keep.json": `{"id":"CVE-keep","affected":[
			{"package":{"name":"libssl3","ecosystem":"Alpine:v3.19"},
				"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"3.1.4-r0"}]}]},
			{"package":{"name":"libssl3","ecosystem":"Alpine:v3.24"},
				"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"3.3.0-r0"}]}]}
		]}`,
		"CVE-withdrawn.json": `{"id":"CVE-withdrawn","withdrawn":"2024-01-01T00:00:00Z",
			"affected":[{"package":{"name":"busybox","ecosystem":"Alpine:v3.19"},
				"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]}]}`,
	})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/Alpine/all.zip" {
			http.NotFound(w, r)
			return
		}
		w.Write(body)
	}))
	defer srv.Close()

	p := New([]string{"Alpine"}, srv.URL)
	var got []advisory.Advisory
	prov, err := p.Fetch(context.Background(), func(a advisory.Advisory) error {
		got = append(got, a)
		return nil
	})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(got) != 1 || got[0].ID != "CVE-keep" {
		t.Fatalf("Fetch emitted %d advisories (%v), want only CVE-keep", len(got), got)
	}
	if prov.Records != 1 {
		t.Errorf("Provenance.Records = %d, want 1 (withdrawn record must not count)", prov.Records)
	}

	var releases []string
	for _, aff := range got[0].Affected {
		releases = append(releases, aff.Ecosystem)
	}
	sort.Strings(releases)
	want := []string{"Alpine:v3.19", "Alpine:v3.24"}
	if !slices.Equal(releases, want) {
		t.Errorf("Affected ecosystems = %v, want %v (both releases must survive a single-archive fetch)", releases, want)
	}
}

// An archive fetched under the "Alpine" ecosystem that names no Alpine:*
// package is the failure discovery's hard-fail used to guard against, one
// layer in: there is no second archive to fall back on, so this must not
// succeed silently. A database built from it would report every subsequent
// Alpine scan as clean.
func TestFetch_AlpineZeroRecordsIsAnError(t *testing.T) {
	body := zipWith(t, map[string]string{
		// Well-formed, but names an ecosystem the Alpine archive would never
		// actually carry — simulating a shape change or a broken family match.
		"GHSA-unrelated.json": `{"id":"GHSA-unrelated","affected":[{"package":{"name":"x","ecosystem":"Go"},
			"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}]}`,
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/Alpine/all.zip" {
			http.NotFound(w, r)
			return
		}
		w.Write(body)
	}))
	defer srv.Close()

	p := New([]string{"Alpine"}, srv.URL)
	_, err := p.Fetch(context.Background(), func(advisory.Advisory) error { return nil })
	if err == nil {
		t.Error("Fetch of an Alpine archive with zero Alpine:* records = nil error; " +
			"a database built from this silently has no Alpine coverage")
	}
}
