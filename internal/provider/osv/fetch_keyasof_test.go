package osv

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kun9497/assay/internal/advisory"
)

// D113 revised (2026-11-09): each key is dated by the archive that declared
// it (Provenance.KeyAsOf), beside the provider-wide minimum DataAsOf keeps.
// Measured cause: Debian:11's D110 freeze was dated 2026-08-19 -- the
// CleanStart archive's stale Last-Modified, the oldest of the fourteen
// archives -- not Debian's own.
func TestFetch_KeyAsOfDatesEachKeyByItsOwnArchive(t *testing.T) {
	goArchive := zipWith(t, map[string]string{
		"GHSA-go.json": `{"id":"GHSA-go","affected":[{"package":{"name":"x","ecosystem":"Go"},
			"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}]}`,
	})
	debianArchive := zipWith(t, map[string]string{
		"DEBIAN-CVE-1.json": `{"id":"DEBIAN-CVE-1","affected":[
			{"package":{"name":"zlib","ecosystem":"Debian:11"},
			 "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]},
			{"package":{"name":"zlib","ecosystem":"Debian:12"},
			 "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1:1.3.dfsg-3"}]}]}]}`,
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/Go/all.zip":
			// The stale archive: it sets the provider's minimum...
			w.Header().Set("Last-Modified", "Wed, 19 Aug 2026 00:00:00 GMT")
			w.Write(goArchive)
		case "/Debian/all.zip":
			// ...and must not date Debian's keys.
			w.Header().Set("Last-Modified", "Sun, 30 Aug 2026 00:00:00 GMT")
			w.Write(debianArchive)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	p := New([]string{"Go", "Debian"}, srv.URL)
	prov, err := p.Fetch(context.Background(), func(advisory.Advisory) error { return nil })
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	stale := time.Date(2026, 8, 19, 0, 0, 0, 0, time.UTC)
	fresh := time.Date(2026, 8, 30, 0, 0, 0, 0, time.UTC)
	if !prov.DataAsOf.Equal(stale) {
		t.Errorf("DataAsOf = %v, want the provider-wide minimum %v, unchanged by the revision", prov.DataAsOf, stale)
	}
	for key, want := range map[string]time.Time{"Go": stale, "Debian:11": fresh, "Debian:12": fresh} {
		if got, ok := prov.KeyAsOf[key]; !ok || !got.Equal(want) {
			t.Errorf("KeyAsOf[%s] = %v (present %v), want %v -- the date of the archive that declared it", key, got, ok, want)
		}
	}
	if len(prov.KeyAsOf) != 3 {
		t.Errorf("KeyAsOf has %d keys (%v), want exactly the three declared", len(prov.KeyAsOf), prov.KeyAsOf)
	}
}

// An archive with no Last-Modified dates none of its keys: they are left out
// of KeyAsOf, so a reader falls back to DataAsOf -- which the same undated
// archive turns unknown -- rather than borrowing the dated archive's date.
func TestFetch_KeyAsOfLeavesAnUndatedArchivesKeysOut(t *testing.T) {
	goArchive := zipWith(t, map[string]string{
		"GHSA-go.json": `{"id":"GHSA-go","affected":[{"package":{"name":"x","ecosystem":"Go"},
			"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}]}`,
	})
	npmArchive := zipWith(t, map[string]string{
		"GHSA-npm.json": `{"id":"GHSA-npm","affected":[{"package":{"name":"left-pad","ecosystem":"npm"},
			"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}]}`,
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/Go/all.zip":
			w.Header().Set("Last-Modified", "Wed, 19 Aug 2026 00:00:00 GMT")
			w.Write(goArchive)
		case "/npm/all.zip":
			// Deliberately undated.
			w.Write(npmArchive)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	p := New([]string{"Go", "npm"}, srv.URL)
	prov, err := p.Fetch(context.Background(), func(advisory.Advisory) error { return nil })
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if !prov.DataAsOf.IsZero() {
		t.Errorf("DataAsOf = %v, want zero: one archive could not be dated", prov.DataAsOf)
	}
	if got, ok := prov.KeyAsOf["Go"]; !ok || !got.Equal(time.Date(2026, 8, 19, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("KeyAsOf[Go] = %v (present %v), want the Go archive's own date", got, ok)
	}
	if got, ok := prov.KeyAsOf["npm"]; ok {
		t.Errorf("KeyAsOf[npm] = %v, want it absent: the npm archive carried no date", got)
	}
}
