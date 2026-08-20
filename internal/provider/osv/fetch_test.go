package osv

import (
	"archive/zip"
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

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

// The same hard-fail as Alpine's above (TestFetch_AlpineZeroRecordsIsAnError),
// extended to Debian, Ubuntu and Rocky Linux (D71): an archive fetched under
// any family name that names no matching record is the exact regression the
// guard's own comment records happening to Debian when it first joined this
// list, and only the Alpine arm was ever held by a test. Narrowing the
// guard's condition to "eco == Alpine" alone leaves the whole suite green,
// because nothing else in this file, or anywhere in the package, drives a
// Debian, Ubuntu or Rocky Linux fetch through zero matching records.
func TestFetch_DebianUbuntuAndRockyZeroRecordsIsAnError(t *testing.T) {
	for _, eco := range []string{"Debian", "Ubuntu", "Rocky Linux"} {
		t.Run(eco, func(t *testing.T) {
			body := zipWith(t, map[string]string{
				// Well-formed, but names an ecosystem this archive would never
				// actually carry -- simulating a shape change or a broken family
				// match, exactly as the Alpine case does.
				"GHSA-unrelated.json": `{"id":"GHSA-unrelated","affected":[{"package":{"name":"x","ecosystem":"Go"},
					"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}]}`,
			})
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/"+eco+"/all.zip" {
					http.NotFound(w, r)
					return
				}
				w.Write(body)
			}))
			defer srv.Close()

			p := New([]string{eco}, srv.URL)
			_, err := p.Fetch(context.Background(), func(advisory.Advisory) error { return nil })
			if err == nil {
				t.Fatalf("Fetch of a %s archive with zero %s:* records = nil error; "+
					"a database built from this silently has no %s coverage", eco, eco, eco)
			}
			if !strings.Contains(err.Error(), eco) {
				t.Errorf("error %q does not name the family %q that broke", err, eco)
			}
		})
	}
}

// D12: the OLDEST upstream timestamp wins, checked across two DATED
// ecosystems. TestFetch above pins a single ecosystem's own timestamp, and
// TestFetch_UnknownTimestampMakesAggregateUnknown zeroes the aggregate via an
// UNDATED second ecosystem -- neither one exercises the actual "older wins"
// comparison, so flipping Before to After (newest wins) leaves both green
// while over-claiming DataAsOf and hiding a stale mirror behind a freshly
// fetched one.
func TestFetch_OldestOfTwoDatedTimestampsWins(t *testing.T) {
	body := zipWith(t, map[string]string{
		"GHSA-a.json": `{"id":"GHSA-a","affected":[{"package":{"name":"x","ecosystem":"Go"},
			"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}]}`,
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/Go/all.zip":
			// Fetched FIRST (Ecosystems lists Go before npm below) and NEWER.
			w.Header().Set("Last-Modified", "Wed, 05 Aug 2026 00:00:00 GMT")
		case "/npm/all.zip":
			// Fetched SECOND and OLDER -- this is the one DataAsOf must report.
			w.Header().Set("Last-Modified", "Mon, 06 Jul 2026 00:00:00 GMT")
		}
		w.Write(body)
	}))
	defer srv.Close()

	p := New([]string{"Go", "npm"}, srv.URL)
	prov, err := p.Fetch(context.Background(), func(advisory.Advisory) error { return nil })
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	want := time.Date(2026, 7, 6, 0, 0, 0, 0, time.UTC)
	if !prov.DataAsOf.Equal(want) {
		t.Errorf("Provenance.DataAsOf = %v, want %v -- the OLDER of the two timestamps, "+
			"carried by the SECOND archive fetched, not the newer first one", prov.DataAsOf, want)
	}
}

// D20's coverage set is built here, and this is the only test that holds it.
//
// The two obvious wrong versions both leave the rest of the suite green:
// recording every affected ecosystem restores the over-claim this fix existed
// to remove (a Go archive would declare Maven), and recording only the fetched
// name makes an Alpine database declare a bare "Alpine" and omit all 23 release
// keys, so every Alpine scan exits 2.
func TestFetch_CoverageIsTheFamilyFetchedNotEveryEcosystemNamed(t *testing.T) {
	goArchive := zipWith(t, map[string]string{
		"GHSA-go.json": `{"id":"GHSA-go","affected":[
			{"package":{"name":"github.com/x/y","ecosystem":"Go"},
			 "ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"2.0.0"}]}]},
			{"package":{"name":"org.x:y","ecosystem":"Maven"},
			 "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"3.0"}]}]}]}`,
	})
	alpineArchive := zipWith(t, map[string]string{
		"ALPINE-CVE-1.json": `{"id":"ALPINE-CVE-1","affected":[
			{"package":{"name":"busybox","ecosystem":"Alpine:v3.19"},
			 "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.36.1-r21"}]}]},
			{"package":{"name":"busybox","ecosystem":"Alpine:v3.24"},
			 "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.37.0-r1"}]}]},
			{"package":{"name":"github.com/x/y","ecosystem":"Go"},
			 "ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"2.0.0"}]}]}]}`,
	})

	tests := []struct {
		name    string
		fetch   string
		archive []byte
		want    []string
	}{
		{
			// Maven is named by the record and is NOT fetched. Declaring it
			// would certify a database holding stray Maven keys, and every
			// Maven scan would report clean once a Maven comparer exists.
			name:  "a foreign entry does not become coverage",
			fetch: "Go", archive: goArchive, want: []string{"Go"},
		},
		{
			// The Alpine archive is fetched under one name and covers many
			// release keys. Recording only the fetched name would declare a key
			// nothing is ever looked up under (D6) and omit the ones that are.
			name:  "a family fetch covers the release keys it contains",
			fetch: "Alpine", archive: alpineArchive,
			want: []string{"Alpine:v3.19", "Alpine:v3.24"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Write(tt.archive)
			}))
			defer srv.Close()

			prov, err := New([]string{tt.fetch}, srv.URL).Fetch(
				context.Background(), func(advisory.Advisory) error { return nil })
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(prov.Ecosystems, tt.want) {
				t.Errorf("Provenance.Ecosystems = %v, want %v", prov.Ecosystems, tt.want)
			}
		})
	}
}

// TestFetch_RockyLinuxPathIsURLEncoded pins the one thing that makes "Rocky
// Linux" different from every other entry in Ecosystems: the archive family
// name contains a space, and an unescaped one would be sent as a literal space
// in the request line -- not the %20 GCS actually serves the archive under. The
// build already routes every fetch through url.PathEscape(eco) (fetchOne's own
// URL string), so this is a regression guard on that call staying in place for
// Rocky Linux specifically, not a test that the mechanism exists at all.
//
// Checked against r.URL.EscapedPath() rather than r.URL.Path: the latter is
// automatically un-escaped by net/http on the way in, so a server that
// forgot to encode the space would still show a "correct" decoded Path while
// the actual bytes on the wire were wrong.
func TestFetch_RockyLinuxPathIsURLEncoded(t *testing.T) {
	body := zipWith(t, map[string]string{
		"RLSA-2026-0001.json": `{"id":"RLSA-2026-0001","affected":[{"package":{"name":"x","ecosystem":"Rocky Linux:9"},
			"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]}]}`,
	})
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.EscapedPath()
		w.Write(body)
	}))
	defer srv.Close()

	p := New([]string{"Rocky Linux"}, srv.URL)
	if _, err := p.Fetch(context.Background(), func(advisory.Advisory) error { return nil }); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if gotPath != "/Rocky%20Linux/all.zip" {
		t.Errorf("request path = %q, want /Rocky%%20Linux/all.zip -- the archive "+
			"name has a space, and an unescaped one is a different URL that GCS "+
			"does not serve", gotPath)
	}
}

// TestFetch_RockyLinux is the end-to-end shape D71 rests on: one RLSA record,
// keyed "Rocky Linux:9" the way the real archive is (measured 2026-08-19), a
// CVE reachable through `upstream` (D3 -- Rocky's own linkage, at 99.3%
// coverage) rather than `aliases`, and a CVSS v3 vector (84.1% of the archive
// carries one). Fetch must emit it with all three intact and report the
// release-qualified key as covered (D20), not the bare archive name.
func TestFetch_RockyLinux(t *testing.T) {
	body := zipWith(t, map[string]string{
		"RLSA-2026-0001.json": `{"id":"RLSA-2026-0001","upstream":["CVE-2026-30001"],
			"severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
			"affected":[{"package":{"name":"nodejs","ecosystem":"Rocky Linux:9"},
				"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1:20.18.1-1.el9"}]}]}]}`,
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/Rocky Linux/all.zip" {
			http.NotFound(w, r)
			return
		}
		w.Write(body)
	}))
	defer srv.Close()

	p := New([]string{"Rocky Linux"}, srv.URL)
	var got []advisory.Advisory
	prov, err := p.Fetch(context.Background(), func(a advisory.Advisory) error {
		got = append(got, a)
		return nil
	})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(got) != 1 || got[0].ID != "RLSA-2026-0001" {
		t.Fatalf("Fetch emitted %d advisories (%v), want only RLSA-2026-0001", len(got), got)
	}
	if len(got[0].Upstream) != 1 || got[0].Upstream[0] != "CVE-2026-30001" {
		t.Errorf("Upstream = %v, want [CVE-2026-30001] -- D3 reads this field for the CVE join", got[0].Upstream)
	}
	if len(got[0].Affected) != 1 || got[0].Affected[0].Ecosystem != "Rocky Linux:9" {
		t.Fatalf("Affected = %v, want one entry keyed Rocky Linux:9", got[0].Affected)
	}
	if len(got[0].Severity) != 1 || got[0].Severity[0].Type != "CVSS_V3" {
		t.Errorf("Severity = %v, want the CVSS_V3 vector carried through", got[0].Severity)
	}
	if !slices.Contains(prov.Ecosystems, "Rocky Linux:9") {
		t.Errorf("Provenance.Ecosystems = %v, want it to include Rocky Linux:9", prov.Ecosystems)
	}
}
