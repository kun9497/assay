package osv

import (
	"archive/zip"
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/kun9497/assay/internal/advisory"
)

// The bucket listing is the only place the versioned keys appear:
// ecosystems.txt has none (52 entries, zero colons).
func TestAlpineEcosystems(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"prefixes":["Alpine/","Alpine:v3.19/","Alpine:v3.2/","Alpine:v3.20/"]}`)
	}))
	defer srv.Close()

	got, err := alpineEcosystemsFrom(context.Background(), srv.Client(), srv.URL)
	if err != nil {
		t.Fatalf("alpineEcosystemsFrom: %v", err)
	}
	want := []string{"Alpine:v3.2", "Alpine:v3.19", "Alpine:v3.20"}
	if !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// An unversioned key cannot match a release-qualified package (D6). Ingesting it
// would put records under a key no lookup ever uses — invisible dead weight.
// The listing also carries one real release, so this test isolates the drop
// from the "nothing survived" failure case below.
func TestAlpineEcosystems_DropsUnversioned(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"prefixes":["Alpine/","Alpine:v3.19/"]}`)
	}))
	defer srv.Close()

	got, err := alpineEcosystemsFrom(context.Background(), srv.Client(), srv.URL)
	if err != nil {
		t.Fatalf("alpineEcosystemsFrom: %v", err)
	}
	want := []string{"Alpine:v3.19"}
	if !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// A listing that is well-formed 200 JSON but contains only the unversioned
// "Alpine/" prefix must still fail: filtering leaves nothing to fetch, and
// this is exactly the shape OSV renaming its key scheme would produce (say to
// "Alpine-3.19/" instead of "Alpine:v3.19/") — a readable response with zero
// usable releases in it. Silently returning an empty list here means `db
// update` succeeds having fetched no Alpine data, and every subsequent Alpine
// scan reports "no known vulnerabilities found": a false negative with no
// error anywhere in the chain.
func TestAlpineEcosystems_AllUnversionedIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"prefixes":["Alpine/"]}`)
	}))
	defer srv.Close()

	_, err := alpineEcosystemsFrom(context.Background(), srv.Client(), srv.URL)
	if err == nil {
		t.Error("listing with only the unversioned prefix returned nil error; " +
			"a database built from this silently has zero Alpine records")
	}
}

// A listing we cannot read must fail loudly. Returning an empty list would build
// a database with no Alpine data and report success.
func TestAlpineEcosystems_EmptyListingIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{}`)
	}))
	defer srv.Close()

	if _, err := alpineEcosystemsFrom(context.Background(), srv.Client(), srv.URL); err == nil {
		t.Error("empty listing returned nil error; a silent empty database is worse than a failure")
	}
}

// A malformed or unreachable listing (bad JSON, wrong status) must also fail
// loudly rather than degrade to an empty release list.
func TestAlpineEcosystems_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	defer srv.Close()

	if _, err := alpineEcosystemsFrom(context.Background(), srv.Client(), srv.URL); err == nil {
		t.Error("HTTP error returned nil error, want error")
	}
}

// AllEcosystems is what `db update` actually calls. A discovery failure must
// come back as an error here too, not get swallowed into "just the language
// list" — that swallow point is where the damage becomes invisible: main.go
// only sees a nil error and proceeds to build a database with no Alpine data.
func TestAllEcosystems_DiscoveryErrorPropagates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	defer srv.Close()

	orig := alpineListingURL
	alpineListingURL = srv.URL
	defer func() { alpineListingURL = orig }()

	got, err := AllEcosystems(context.Background())
	if err == nil {
		t.Fatalf("AllEcosystems = %v, nil error; a discovery failure must not degrade to the language-only list", got)
	}
	if got != nil {
		t.Errorf("AllEcosystems returned %v on error, want nil", got)
	}
}

func zipWithAlpine(t *testing.T, files map[string]string) []byte {
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

// Fetching one Alpine release must give the two properties D16 and the
// slice-1 cross-ecosystem fix already promise, not just assume them:
//   - a withdrawn record is dropped at ingestion (D16), and
//   - a record whose affected[] spans several releases keeps every entry, so
//     fetching Alpine:v3.19 also indexes that record's Alpine:v3.16 entry.
//     That is extra coverage, not a substitute for fetching v3.16 directly —
//     v3.16's own archive has 71 entries v3.19's never mentions.
func TestFetch_AlpineWithdrawnAndCrossReleaseKept(t *testing.T) {
	body := zipWithAlpine(t, map[string]string{
		"CVE-keep.json": `{"id":"CVE-keep","affected":[
			{"package":{"name":"libssl3","ecosystem":"Alpine:v3.19"},
				"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"3.1.4-r0"}]}]},
			{"package":{"name":"libssl3","ecosystem":"Alpine:v3.16"},
				"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"3.0.8-r0"}]}]}
		]}`,
		"CVE-withdrawn.json": `{"id":"CVE-withdrawn","withdrawn":"2024-01-01T00:00:00Z",
			"affected":[{"package":{"name":"busybox","ecosystem":"Alpine:v3.19"},
				"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]}]}`,
	})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/Alpine:v3.19/all.zip" {
			http.NotFound(w, r)
			return
		}
		w.Write(body)
	}))
	defer srv.Close()

	p := New([]string{"Alpine:v3.19"}, srv.URL)
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
	slices.Sort(releases)
	want := []string{"Alpine:v3.16", "Alpine:v3.19"}
	if !slices.Equal(releases, want) {
		t.Errorf("Affected ecosystems = %v, want %v (the v3.16 entry must survive a v3.19-scoped fetch)", releases, want)
	}
}
