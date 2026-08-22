package eol

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kun9497/assay/internal/store"
)

func serveJSON(t *testing.T, body string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(body))
	}))
}

// realShapedFixture is trimmed from a real /api/v1/products/full response
// sampled 2026-08-21, keeping field names and nesting exactly as measured:
// one non-distro product (adonisjs, a JS framework) that must be filtered
// out, and four distro products exercising the slug->os-release-ID table
// (debian identical, amazon-linux->amzn and oracle-linux->ol both requiring
// the mandatory static mapping since v1's own "aliases" does not cover
// either, and alpine-linux->alpine). debian's releases carry the
// labels.eol/labels.eoes prose and the isEol-yet-isMaintained shape that
// motivates storing labels at all (D87) -- bookworm here stands in for that
// shape with trimmed dates.
const realShapedFixture = `{
  "schema_version": "1.2.1",
  "generated_at": "2026-08-21T07:44:48+00:00",
  "total": 5,
  "result": [
    {
      "name": "adonisjs",
      "label": "AdonisJS",
      "labels": {"eoas": null, "discontinued": null, "eol": "Security Support", "eoes": null},
      "releases": [
        {"name": "7", "eolFrom": null, "eoasFrom": null, "isEol": false, "isEoas": false,
         "eoesFrom": null, "isMaintained": true, "isLts": false}
      ]
    },
    {
      "name": "debian",
      "label": "Debian",
      "labels": {"eoas": null, "discontinued": null, "eol": "Debian Security Support", "eoes": "Debian LTS"},
      "releases": [
        {"name": "13", "codename": "Trixie", "eolFrom": "2028-08-09", "isEol": false,
         "isEoas": false, "eoasFrom": null, "isEoes": false, "eoesFrom": "2030-06-30",
         "isMaintained": true, "isLts": false},
        {"name": "12", "codename": "Bookworm", "eolFrom": "2026-07-11", "isEol": true,
         "isEoas": false, "eoasFrom": null, "isEoes": false, "eoesFrom": "2028-06-30",
         "isMaintained": true, "isLts": false}
      ]
    },
    {
      "name": "amazon-linux",
      "label": "Amazon Linux",
      "labels": {"eoas": "Standard Support", "discontinued": null, "eol": "Security Support", "eoes": null},
      "releases": [
        {"name": "2", "eolFrom": "2026-06-30", "isEol": true, "isMaintained": false, "isLts": false}
      ]
    },
    {
      "name": "oracle-linux",
      "label": "Oracle Linux",
      "labels": {"eoas": null, "discontinued": null, "eol": "Basic/Premier Support", "eoes": "Extended Support"},
      "releases": [
        {"name": "9", "eolFrom": "2032-06-30", "isEol": false, "isMaintained": true, "isLts": false}
      ]
    },
    {
      "name": "alpine-linux",
      "label": "Alpine Linux",
      "labels": {"eoas": null, "discontinued": null, "eol": "Security Support", "eoes": null},
      "releases": [
        {"name": "3.19", "eolFrom": "2025-11-01", "isEol": true, "isMaintained": false, "isLts": false}
      ]
    }
  ]
}`

// rowFor returns the single row matching distroID/release, failing the test
// if there is not exactly one -- collision-free lookup rather than trusting
// slice order.
func rowFor(t *testing.T, rows []store.EOLRelease, distroID, release string) store.EOLRelease {
	t.Helper()
	var found []store.EOLRelease
	for _, r := range rows {
		if r.DistroID == distroID && r.Release == release {
			found = append(found, r)
		}
	}
	if len(found) != 1 {
		t.Fatalf("rowFor(%s, %s) matched %d row(s), want 1: %+v", distroID, release, len(found), rows)
	}
	return found[0]
}

// TestFetch_EmitsTypedRowsFromRealShapedCatalog is the caller-first test: it
// drives Fetch against a fixture trimmed from the real catalog and checks
// every typed field EOLRelease carries (D87), not just that something was
// returned. It also proves the two halves the design calls out specifically:
// a non-distro product (adonisjs) is filtered out, and the slug->os-release
// mapping is NOT the identity function for amzn/ol (their whole reason to be
// a mandatory static table rather than reading v1's own "aliases").
func TestFetch_EmitsTypedRowsFromRealShapedCatalog(t *testing.T) {
	srv := serveJSON(t, realShapedFixture)
	defer srv.Close()

	p := New(Options{URL: srv.URL})
	rows, prov, err := p.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	// 2 debian + 1 amazon-linux + 1 oracle-linux + 1 alpine-linux = 5. If
	// adonisjs leaked through this would be 6.
	if len(rows) != 5 {
		t.Fatalf("Fetch returned %d row(s), want 5 (adonisjs must be filtered out): %+v", len(rows), rows)
	}
	for _, r := range rows {
		if r.DistroID == "adonisjs" {
			t.Fatalf("a non-distro product reached the store: %+v", r)
		}
	}

	// The mandatory slug table, not the identity function: "amazon-linux"
	// and "oracle-linux" must map to "amzn" and "ol", the os-release IDs a
	// scan's Target.Distro.ID actually carries -- v1's own "aliases" field
	// does not cover either (2026-08-21 measurement).
	amzn := rowFor(t, rows, "amzn", "2")
	if amzn.EOLFrom != "2026-06-30" {
		t.Errorf("amzn 2 EOLFrom = %q, want 2026-06-30", amzn.EOLFrom)
	}
	ol := rowFor(t, rows, "ol", "9")
	if ol.EOLFrom != "2032-06-30" {
		t.Errorf("ol 9 EOLFrom = %q, want 2032-06-30", ol.EOLFrom)
	}
	alpine := rowFor(t, rows, "alpine", "3.19")
	if alpine.EOLFrom != "2025-11-01" {
		t.Errorf("alpine 3.19 EOLFrom = %q, want 2025-11-01", alpine.EOLFrom)
	}

	// debian:12 (bookworm) is the isEol-yet-isMaintained shape D87 exists
	// for: every field asserted individually, field by field rather than ==,
	// since a wrong EOLLabel/EOESLabel would otherwise pass a bare
	// length/presence check.
	bookworm := rowFor(t, rows, "debian", "12")
	want := store.EOLRelease{
		DistroID:     "debian",
		Release:      "12",
		EOLFrom:      "2026-07-11",
		EOASFrom:     "",
		EOESFrom:     "2028-06-30",
		IsLTS:        false,
		IsMaintained: true,
		EOLLabel:     "Debian Security Support",
		EOESLabel:    "Debian LTS",
	}
	if bookworm != want {
		t.Errorf("debian 12 row = %+v, want %+v", bookworm, want)
	}
	// isEol itself must never be read into EOLRelease at all -- D87's whole
	// point is that the boolean goes stale, so there is no field on
	// store.EOLRelease it could even land in. Asserted here by construction:
	// `want` above has no IsEOL field, so this test would not compile if one
	// were added without a corresponding assertion, and bookworm/want being
	// struct-equal already proves nothing extra rode along.

	if prov.Source != srv.URL {
		t.Errorf("Provenance.Source = %q, want %q", prov.Source, srv.URL)
	}
	wantAsOf := time.Date(2026, 8, 21, 7, 44, 48, 0, time.UTC)
	if !prov.DataAsOf.Equal(wantAsOf) {
		t.Errorf("Provenance.DataAsOf = %v, want %v (generated_at, not fetch time)", prov.DataAsOf, wantAsOf)
	}
	if prov.Records != 5 {
		t.Errorf("Provenance.Records = %d, want 5", prov.Records)
	}
}

// allSlugsFixture carries one product per wantSlugs entry (all 11), each
// with a release name distinct enough to prove which slug it came from, plus
// one non-distro product to keep the filter exercised alongside the mapping.
// This is the only fixture in the package that reaches every row of
// wantSlugs -- realShapedFixture above deliberately covers only four, per
// its own doc comment.
const allSlugsFixture = `{
  "schema_version": "1.2.1",
  "generated_at": "2026-08-21T07:44:48+00:00",
  "total": 12,
  "result": [
    {"name": "adonisjs", "labels": {"eoas": null, "discontinued": null, "eol": "x", "eoes": null},
     "releases": [{"name": "7", "eolFrom": null, "isEol": false, "isMaintained": true, "isLts": false}]},
    {"name": "debian", "labels": {"eoas": null, "discontinued": null, "eol": "x", "eoes": null},
     "releases": [{"name": "debian-release", "eolFrom": "2028-08-09", "isEol": false, "isMaintained": true, "isLts": false}]},
    {"name": "ubuntu", "labels": {"eoas": null, "discontinued": null, "eol": "x", "eoes": null},
     "releases": [{"name": "ubuntu-release", "eolFrom": "2027-04-01", "isEol": false, "isMaintained": true, "isLts": false}]},
    {"name": "rhel", "labels": {"eoas": null, "discontinued": null, "eol": "x", "eoes": null},
     "releases": [{"name": "rhel-release", "eolFrom": "2032-05-31", "isEol": false, "isMaintained": true, "isLts": false}]},
    {"name": "alpine-linux", "labels": {"eoas": null, "discontinued": null, "eol": "x", "eoes": null},
     "releases": [{"name": "alpine-release", "eolFrom": "2025-11-01", "isEol": true, "isMaintained": false, "isLts": false}]},
    {"name": "rocky-linux", "labels": {"eoas": null, "discontinued": null, "eol": "x", "eoes": null},
     "releases": [{"name": "rocky-release", "eolFrom": "2029-05-31", "isEol": false, "isMaintained": true, "isLts": false}]},
    {"name": "almalinux", "labels": {"eoas": null, "discontinued": null, "eol": "x", "eoes": null},
     "releases": [{"name": "almalinux-release", "eolFrom": "2029-05-31", "isEol": false, "isMaintained": true, "isLts": false}]},
    {"name": "amazon-linux", "labels": {"eoas": null, "discontinued": null, "eol": "x", "eoes": null},
     "releases": [{"name": "amazon-release", "eolFrom": "2026-06-30", "isEol": true, "isMaintained": false, "isLts": false}]},
    {"name": "oracle-linux", "labels": {"eoas": null, "discontinued": null, "eol": "x", "eoes": null},
     "releases": [{"name": "oracle-release", "eolFrom": "2032-06-30", "isEol": false, "isMaintained": true, "isLts": false}]},
    {"name": "fedora", "labels": {"eoas": null, "discontinued": null, "eol": "x", "eoes": null},
     "releases": [{"name": "fedora-release", "eolFrom": "2027-05-13", "isEol": false, "isMaintained": true, "isLts": false}]},
    {"name": "sles", "labels": {"eoas": null, "discontinued": null, "eol": "x", "eoes": null},
     "releases": [{"name": "sles-release", "eolFrom": "2031-07-31", "isEol": false, "isMaintained": true, "isLts": false}]},
    {"name": "opensuse", "labels": {"eoas": null, "discontinued": null, "eol": "x", "eoes": null},
     "releases": [{"name": "opensuse-release", "eolFrom": "2026-12-01", "isEol": false, "isMaintained": true, "isLts": false}]}
  ]
}`

// TestFetch_MapsEverySlugToItsDistroID is the caller-first test wantSlugs
// itself has never had: one row per product slug, driven through Fetch, each
// asserted against the os-release ID the mapping's own doc comment promises.
// wantSlugs' comment says a wrong key leaves a distro "silently
// unlookupable" -- rowFor makes that failure loud instead: a mismatched
// DistroID means rowFor finds zero rows for the expected key and fails the
// test, rather than the row silently existing under some other name.
func TestFetch_MapsEverySlugToItsDistroID(t *testing.T) {
	srv := serveJSON(t, allSlugsFixture)
	defer srv.Close()

	p := New(Options{URL: srv.URL})
	rows, _, err := p.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	want := map[string]string{
		"debian":        "debian-release",
		"ubuntu":        "ubuntu-release",
		"rhel":          "rhel-release",
		"alpine":        "alpine-release",
		"rocky":         "rocky-release",
		"almalinux":     "almalinux-release",
		"amzn":          "amazon-release",
		"ol":            "oracle-release",
		"fedora":        "fedora-release",
		"sles":          "sles-release",
		"opensuse-leap": "opensuse-release",
	}
	for distroID, release := range want {
		// rowFor itself fails the test (t.Fatalf) if the row is missing --
		// exactly the "silently unlookupable" failure wantSlugs' comment
		// warns about, made loud.
		rowFor(t, rows, distroID, release)
	}
	if len(rows) != len(want) {
		t.Errorf("Fetch returned %d row(s), want %d (one per wantSlugs entry, adonisjs filtered out): %+v", len(rows), len(want), rows)
	}
}

// TestFetch_RefusesATotalMismatch is the integrity guard: a "total" that
// disagrees with the actual result array length means a truncated download
// or a reshaped payload, and Fetch must refuse rather than silently store a
// partial catalog.
func TestFetch_RefusesATotalMismatch(t *testing.T) {
	body := `{"schema_version":"1.2.1","generated_at":"2026-08-21T07:44:48+00:00","total":99,"result":[
		{"name":"debian","labels":{"eoas":null,"discontinued":null,"eol":"x","eoes":null},
		 "releases":[{"name":"12","eolFrom":"2026-07-11","isEol":true,"isMaintained":true,"isLts":false}]}
	]}`
	srv := serveJSON(t, body)
	defer srv.Close()

	p := New(Options{URL: srv.URL})
	rows, _, err := p.Fetch(context.Background())
	if err == nil {
		t.Fatalf("Fetch with total=99/len(result)=1 = nil error, want a refusal (got %d rows)", len(rows))
	}
	if !strings.Contains(err.Error(), "total=99") {
		t.Errorf("error %q does not name the declared total", err.Error())
	}
}

// TestFetch_RefusesAnEmptyDistroSubset is the D78 zero-topics register,
// applied here: total and len(result) agree, but none of the products in
// the payload are among the 11 this package keeps (an upstream rename or a
// reshaped slug would look exactly like this). A shape change must not ship
// a silently EOL-less database that then answers every EOL lookup with "not
// EOL" instead of "unknown".
func TestFetch_RefusesAnEmptyDistroSubset(t *testing.T) {
	body := `{"schema_version":"1.2.1","generated_at":"2026-08-21T07:44:48+00:00","total":1,"result":[
		{"name":"adonisjs","labels":{"eoas":null,"discontinued":null,"eol":"x","eoes":null},
		 "releases":[{"name":"7","eolFrom":null,"isEol":false,"isMaintained":true,"isLts":false}]}
	]}`
	srv := serveJSON(t, body)
	defer srv.Close()

	p := New(Options{URL: srv.URL})
	rows, _, err := p.Fetch(context.Background())
	if err == nil {
		t.Fatalf("Fetch with an empty distro subset = nil error, want a refusal (got %d rows)", len(rows))
	}
	if !strings.Contains(err.Error(), "matched 0 of") {
		t.Errorf("error %q does not name the zero-match refusal", err.Error())
	}
}

// fetchBackoffForTest shrinks the retry backoff to keep the retry tests
// fast, restoring the shipped schedule afterward -- epss.fetchBackoffForTest
// and kev's own copy take the identical shape, for the identical reason: a
// test must not be able to silently zero the production backoff for every
// other test in the package.
func fetchBackoffForTest() func() {
	orig := fetchBackoff
	fetchBackoff = func(int) time.Duration { return time.Millisecond }
	return func() { fetchBackoff = orig }
}

// TestFetch_AnHTTPErrorPropagatesAfterRetrying is the caller-first proof for
// the retry pattern, mirroring epss's and kev's own copy of this test
// exactly: a server that never answers 200 must still fail the build after
// the bounded retry schedule, and it must actually retry more than once
// rather than fail on the first transient response -- the reason
// EOL_ENABLE's default-on posture feeding --fail-on-eol is safe against a
// two-second blip.
func TestFetch_AnHTTPErrorPropagatesAfterRetrying(t *testing.T) {
	defer fetchBackoffForTest()()

	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	p := New(Options{URL: srv.URL})
	if _, _, err := p.Fetch(context.Background()); err == nil {
		t.Fatal("Fetch succeeded against a server returning 503 on every attempt")
	}
	if calls != fetchAttempts {
		t.Errorf("server saw %d call(s), want exactly %d (the full retry schedule)", calls, fetchAttempts)
	}
}

// TestFetch_RetriesATransientFailureThenSucceeds is the other half: failing
// once (503) and succeeding on the next attempt must still emit the
// catalog's rows, proving attempt 2 is not merely counted but actually used.
// This is the test that pins fetchAttempts itself -- with the retry schedule
// shrunk to 1, the loop has no second attempt left after the first 503 and
// Fetch returns an error instead of succeeding.
func TestFetch_RetriesATransientFailureThenSucceeds(t *testing.T) {
	defer fetchBackoffForTest()()

	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(realShapedFixture))
	}))
	defer srv.Close()

	p := New(Options{URL: srv.URL})
	rows, _, err := p.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if calls < 2 {
		t.Fatalf("server saw %d call(s), want at least 2 (a retry after the first failure)", calls)
	}
	if len(rows) != 5 {
		t.Errorf("Fetch returned %d row(s) after the retry succeeded, want 5", len(rows))
	}
}

// TestFetch_A4xxOtherThan429IsNotRetried proves the deny-list narrows in the
// direction it must: a request that is simply wrong must fail fast, not
// spend the whole retry schedule repeating a mistake.
func TestFetch_A4xxOtherThan429IsNotRetried(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	p := New(Options{URL: srv.URL})
	if _, _, err := p.Fetch(context.Background()); err == nil {
		t.Fatal("Fetch succeeded against a 404")
	}
	if calls != 1 {
		t.Errorf("server saw %d call(s), want exactly 1 (a 404 is not retried)", calls)
	}
}

// TestFetch_RefusesAMalformedGeneratedAt is D12's own refusal, one door
// over from epss.parseHeaderComment's and kev.Annotate's identical checks:
// without a parseable generated_at there is nowhere for DataAsOf to come
// from, and Fetch must fail rather than fall back to wall-clock fetch time.
func TestFetch_RefusesAMalformedGeneratedAt(t *testing.T) {
	body := `{"schema_version":"1.2.1","generated_at":"not-a-date","total":1,"result":[
		{"name":"debian","labels":{"eoas":null,"discontinued":null,"eol":"x","eoes":null},
		 "releases":[{"name":"12","eolFrom":"2026-07-11","isEol":true,"isMaintained":true,"isLts":false}]}
	]}`
	srv := serveJSON(t, body)
	defer srv.Close()

	p := New(Options{URL: srv.URL})
	if _, _, err := p.Fetch(context.Background()); err == nil {
		t.Fatal("Fetch with an unparseable generated_at = nil error, want a refusal")
	}
}
