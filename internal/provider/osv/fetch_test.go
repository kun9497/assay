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
// extended to Debian, Ubuntu, Rocky Linux (D71), AlmaLinux (D72), Chainguard
// (D88), MinimOS and Echo (D92), and now Azure Linux (D94): an archive
// fetched under any family name that names no matching record is the exact
// regression the guard's own comment records happening to Debian when it
// first joined this list, and only the Alpine arm was ever held by a test.
// Narrowing the guard's condition to "eco == Alpine" alone leaves the whole
// suite green, because nothing else in this file, or anywhere in the
// package, drives a Debian, Ubuntu, Rocky Linux, AlmaLinux, Chainguard,
// MinimOS, Echo or Azure Linux fetch through zero matching records. This is
// what makes the Azure Linux row caller-first for fetch.go's guard condition
// specifically: deleting "Azure Linux" from the "eco == ..." chain in
// fetch.go turns its own row red here, while every pre-existing row (Debian,
// Ubuntu, ...) stays green.
//
// "Wolfi" is deliberately NOT one of the rows here: nothing in this
// package's default Ecosystems ever fetches under that literal name (D88),
// so New([]string{"Wolfi"}, ...) is not a shape production code produces --
// it is still covered in the guard's own condition in fetch.go, for any
// caller that constructs a Provider directly with it, but there is no
// end-to-end path through this test to drive it.
func TestFetch_DebianUbuntuRockyAlmaChainguardMinimOSEchoAndAzureLinuxZeroRecordsIsAnError(t *testing.T) {
	for _, eco := range []string{"Debian", "Ubuntu", "Rocky Linux", "AlmaLinux", "Chainguard", "MinimOS", "Echo", "Azure Linux"} {
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

// TestFetch_AlmaLinux is the end-to-end shape D72 rests on, and it is the
// mirror image of TestFetch_RockyLinux's fixture on purpose: AlmaLinux's
// measured archive (2026-08-19) carries its CVE ONLY in `related` (aliases
// and upstream are empty on every record) and 0% CVSS anywhere, so the
// severity comes from the summary's word prefix instead. Fetch must emit the
// record with Related populated and a VENDOR_WORD severity entry, and report
// the release-qualified key as covered (D20), not the bare archive name.
func TestFetch_AlmaLinux(t *testing.T) {
	body := zipWith(t, map[string]string{
		"ALSA-2026-0001.json": `{"id":"ALSA-2026-0001","related":["CVE-2026-40001"],
			"summary":"Important: openssh security update",
			"affected":[{"package":{"name":"openssh","ecosystem":"AlmaLinux:9"},
				"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"8.7p1-38.el9"}]}]}]}`,
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/AlmaLinux/all.zip" {
			http.NotFound(w, r)
			return
		}
		w.Write(body)
	}))
	defer srv.Close()

	p := New([]string{"AlmaLinux"}, srv.URL)
	var got []advisory.Advisory
	prov, err := p.Fetch(context.Background(), func(a advisory.Advisory) error {
		got = append(got, a)
		return nil
	})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(got) != 1 || got[0].ID != "ALSA-2026-0001" {
		t.Fatalf("Fetch emitted %d advisories (%v), want only ALSA-2026-0001", len(got), got)
	}
	if len(got[0].Upstream) != 0 || len(got[0].Aliases) != 0 {
		t.Errorf("Upstream=%v Aliases=%v, want both empty -- AlmaLinux's measured shape "+
			"carries the CVE nowhere else", got[0].Upstream, got[0].Aliases)
	}
	if len(got[0].Related) != 1 || got[0].Related[0] != "CVE-2026-40001" {
		t.Errorf("Related = %v, want [CVE-2026-40001] -- D72's whole reason for reading "+
			"this field at all", got[0].Related)
	}
	if len(got[0].Affected) != 1 || got[0].Affected[0].Ecosystem != "AlmaLinux:9" {
		t.Fatalf("Affected = %v, want one entry keyed AlmaLinux:9", got[0].Affected)
	}
	if len(got[0].Severity) != 1 || got[0].Severity[0].Type != "VENDOR_WORD" || got[0].Severity[0].Score != "Important" {
		t.Errorf("Severity = %v, want one VENDOR_WORD entry scored \"Important\" from the summary", got[0].Severity)
	}
	if !slices.Contains(prov.Ecosystems, "AlmaLinux:9") {
		t.Errorf("Provenance.Ecosystems = %v, want it to include AlmaLinux:9", prov.Ecosystems)
	}
}

// TestFetch_AlmaLinuxDropsBugfixAndEnhancementErrata drives the ALBA/ALEA
// drop through Fetch rather than only through Convert directly (the
// caller-first rule): ALBA (bugfix) and ALEA (enhancement) errata name no
// vulnerability at all, and a served archive mixing all three AlmaLinux
// namespaces must yield only the ALSA (security) record. AlmaLinux has no
// separate drop-count stat (D72 mirrors the withdrawn/MAL-* pattern, which
// has none either), so this only asserts what a real archive fetch would
// show: the two non-security records never reach emit.
func TestFetch_AlmaLinuxDropsBugfixAndEnhancementErrata(t *testing.T) {
	body := zipWith(t, map[string]string{
		"ALSA-2026-0001.json": `{"id":"ALSA-2026-0001","related":["CVE-2026-40001"],
			"summary":"Important: openssh security update",
			"affected":[{"package":{"name":"openssh","ecosystem":"AlmaLinux:9"},
				"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"8.7p1-38.el9"}]}]}]}`,
		"ALBA-2026-0002.json": `{"id":"ALBA-2026-0002","related":["CVE-2026-40002"],
			"summary":"bash bugfix update",
			"affected":[{"package":{"name":"bash","ecosystem":"AlmaLinux:9"},
				"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"5.1.8-9.el9"}]}]}]}`,
		"ALEA-2026-0003.json": `{"id":"ALEA-2026-0003","related":["CVE-2026-40003"],
			"summary":"vim enhancement update",
			"affected":[{"package":{"name":"vim","ecosystem":"AlmaLinux:9"},
				"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"8.2.2637-20.el9"}]}]}]}`,
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/AlmaLinux/all.zip" {
			http.NotFound(w, r)
			return
		}
		w.Write(body)
	}))
	defer srv.Close()

	p := New([]string{"AlmaLinux"}, srv.URL)
	var got []advisory.Advisory
	if _, err := p.Fetch(context.Background(), func(a advisory.Advisory) error {
		got = append(got, a)
		return nil
	}); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(got) != 1 || got[0].ID != "ALSA-2026-0001" {
		t.Fatalf("Fetch emitted %v, want only the ALSA record -- ALBA and ALEA name no "+
			"vulnerability and must never be emitted", got)
	}
}

// TestEcosystems_ChainguardIsTheOnlyFetch pins D88's "one feed, two keys":
// "Chainguard" is in the default fetch list and "Wolfi" is deliberately NOT
// -- fetching Wolfi/all.zip too would be a second, redundant network request
// for data the Chainguard archive already carries in full (measured
// 2026-08-22: every one of Wolfi's 23,961 records is a byte-identical member
// of Chainguard's 43,650; 0 wolfi-only records exist).
func TestEcosystems_ChainguardIsTheOnlyFetch(t *testing.T) {
	if !slices.Contains(Ecosystems, "Chainguard") {
		t.Error(`Ecosystems does not contain "Chainguard"`)
	}
	if slices.Contains(Ecosystems, "Wolfi") {
		t.Error(`Ecosystems contains "Wolfi" -- D88 fetches it only via the ` +
			`Chainguard archive, never as a separate request`)
	}
}

// TestEcosystems_ContainsMinimOSAndEcho is D92's presence guard: unlike
// Wolfi/Chainguard's "one feed, two keys" arrangement above, MinimOS and
// Echo are each fetched directly under their own name (no cross-feed
// duplication was measured), so both must be plain entries in the default
// fetch list. Deleting either turns this red while leaving every other
// Ecosystems-derived test in this file green, since none of them iterate
// the real package-level Ecosystems slice the way this one does.
func TestEcosystems_ContainsMinimOSAndEcho(t *testing.T) {
	if !slices.Contains(Ecosystems, "MinimOS") {
		t.Error(`Ecosystems does not contain "MinimOS"`)
	}
	if !slices.Contains(Ecosystems, "Echo") {
		t.Error(`Ecosystems does not contain "Echo"`)
	}
}

// TestFetch_ChainguardCoversWolfiToo is the end-to-end shape D88 rests on,
// built from the real live-both-ecosystems record measured 2026-08-22
// (CGA-224q-ccj5-2p53, trimmed to two package streams): one CGA record whose
// `affected` list carries entries for BOTH "Chainguard" and "Wolfi", fetched
// under the single archive name "Chainguard". Both ecosystems' entries must
// survive into the emitted advisory, and BOTH keys must land in
// Provenance.Ecosystems from this ONE fetch -- not just "Chainguard", the
// literal name requested. Deleting familyMatches' Chainguard/Wolfi clause
// turns this red on the coverage assertion while every other test in this
// package (which never checks for "Wolfi" specifically) stays green -- the
// exact measured hazard this slice exists to close: a Wolfi image scanned
// against a database built this way would find "Wolfi" absent from
// Meta.Ecosystems and hit D20's uncovered-ecosystem skip despite the record
// being right there in the store.
func TestFetch_ChainguardCoversWolfiToo(t *testing.T) {
	body := zipWith(t, map[string]string{
		"CGA-224q-ccj5-2p53.json": `{"id":"CGA-224q-ccj5-2p53",
			"related":["CVE-2025-32464","GHSA-frg5-h47x-75j9"],
			"affected":[
				{"package":{"name":"haproxy-3.0","ecosystem":"Chainguard","purl":"pkg:apk/chainguard/haproxy-3.0"},
				 "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"3.0.10-r0"}]}]},
				{"package":{"name":"haproxy-3.0","ecosystem":"Wolfi","purl":"pkg:apk/wolfi/haproxy-3.0"},
				 "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"3.0.10-r0"}]}]}
			]}`,
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/Chainguard/all.zip" {
			http.NotFound(w, r)
			return
		}
		w.Write(body)
	}))
	defer srv.Close()

	p := New([]string{"Chainguard"}, srv.URL)
	var got []advisory.Advisory
	prov, err := p.Fetch(context.Background(), func(a advisory.Advisory) error {
		got = append(got, a)
		return nil
	})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(got) != 1 || got[0].ID != "CGA-224q-ccj5-2p53" {
		t.Fatalf("Fetch emitted %d advisories (%v), want only CGA-224q-ccj5-2p53", len(got), got)
	}
	if len(got[0].Related) != 2 || got[0].Related[0] != "CVE-2025-32464" {
		t.Errorf("Related = %v, want [CVE-2025-32464 GHSA-frg5-h47x-75j9] -- D88's CGA "+
			"scope extension (distroAuthored)", got[0].Related)
	}

	var ecos []string
	for _, aff := range got[0].Affected {
		ecos = append(ecos, aff.Ecosystem)
	}
	sort.Strings(ecos)
	if !slices.Equal(ecos, []string{"Chainguard", "Wolfi"}) {
		t.Errorf("Affected ecosystems = %v, want both Chainguard and Wolfi entries kept", ecos)
	}

	if !slices.Contains(prov.Ecosystems, "Chainguard") {
		t.Errorf("Provenance.Ecosystems = %v, want it to include Chainguard -- the "+
			"family actually fetched", prov.Ecosystems)
	}
	if !slices.Contains(prov.Ecosystems, "Wolfi") {
		t.Errorf("Provenance.Ecosystems = %v, want it to ALSO include Wolfi -- the "+
			"one fetch under \"Chainguard\" must mark both keys covered (D88), or "+
			"every Wolfi scan hits D20's uncovered-ecosystem skip despite this "+
			"exact record sitting in the store", prov.Ecosystems)
	}
}

// TestEcosystems_ContainsAzureLinux is D94's presence guard, on the same
// pattern TestEcosystems_ContainsMinimOSAndEcho holds for D92: "Azure Linux"
// has a genuine release axis (unlike MinimOS/Echo), so unlike Wolfi's
// deliberate absence there is no "one feed, two keys" reason to leave it out
// -- it must be a plain entry in the default fetch list.
func TestEcosystems_ContainsAzureLinux(t *testing.T) {
	if !slices.Contains(Ecosystems, "Azure Linux") {
		t.Error(`Ecosystems does not contain "Azure Linux"`)
	}
}

// TestFetch_AzureLinuxPathIsURLEncoded mirrors
// TestFetch_RockyLinuxPathIsURLEncoded exactly: "Azure Linux" has a space in
// its archive family name too, and an unescaped one is a different URL than
// the one GCS actually serves the archive under.
func TestFetch_AzureLinuxPathIsURLEncoded(t *testing.T) {
	body := zipWith(t, map[string]string{
		"AZL-2026-0001.json": `{"id":"AZL-2026-0001","affected":[{"package":{"name":"x","ecosystem":"Azure Linux:3"},
			"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]}]}`,
	})
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.EscapedPath()
		w.Write(body)
	}))
	defer srv.Close()

	p := New([]string{"Azure Linux"}, srv.URL)
	if _, err := p.Fetch(context.Background(), func(advisory.Advisory) error { return nil }); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if gotPath != "/Azure%20Linux/all.zip" {
		t.Errorf("request path = %q, want /Azure%%20Linux/all.zip -- the archive "+
			"name has a space, and an unescaped one is a different URL that GCS "+
			"does not serve", gotPath)
	}
}

// TestFetch_AzureLinux is the end-to-end shape D94 rests on: one AZL record,
// keyed "Azure Linux:3" the way the real archive is (measured 2026-08-26), a
// CVE reachable through `upstream` (D3 -- Azure Linux's own linkage, at 100%
// coverage, unlike AlmaLinux's `related`-only shape) and a real CVSS v3
// vector (58% of the archive carries one). Fetch must emit it with all three
// intact and report the release-qualified key as covered (D20), not the bare
// archive name.
func TestFetch_AzureLinux(t *testing.T) {
	body := zipWith(t, map[string]string{
		"AZL-2026-0001.json": `{"id":"AZL-2026-0001","upstream":["CVE-2026-61001"],
			"severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
			"affected":[{"package":{"name":"grpc","ecosystem":"Azure Linux:3"},
				"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.42.0-7"}]}]}]}`,
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/Azure Linux/all.zip" {
			http.NotFound(w, r)
			return
		}
		w.Write(body)
	}))
	defer srv.Close()

	p := New([]string{"Azure Linux"}, srv.URL)
	var got []advisory.Advisory
	prov, err := p.Fetch(context.Background(), func(a advisory.Advisory) error {
		got = append(got, a)
		return nil
	})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(got) != 1 || got[0].ID != "AZL-2026-0001" {
		t.Fatalf("Fetch emitted %d advisories (%v), want only AZL-2026-0001", len(got), got)
	}
	if len(got[0].Upstream) != 1 || got[0].Upstream[0] != "CVE-2026-61001" {
		t.Errorf("Upstream = %v, want [CVE-2026-61001] -- D3 reads this field for the CVE join", got[0].Upstream)
	}
	if len(got[0].Related) != 0 {
		t.Errorf("Related = %v, want empty -- Azure Linux carries its CVE in upstream, "+
			"unlike AlmaLinux, and never needed the related-join", got[0].Related)
	}
	if len(got[0].Affected) != 1 || got[0].Affected[0].Ecosystem != "Azure Linux:3" {
		t.Fatalf("Affected = %v, want one entry keyed Azure Linux:3", got[0].Affected)
	}
	if len(got[0].Severity) != 1 || got[0].Severity[0].Type != "CVSS_V3" {
		t.Errorf("Severity = %v, want the CVSS_V3 vector carried through", got[0].Severity)
	}
	if !slices.Contains(prov.Ecosystems, "Azure Linux:3") {
		t.Errorf("Provenance.Ecosystems = %v, want it to include Azure Linux:3", prov.Ecosystems)
	}
}

// TestFetch_AzureLinuxBoundedIntroduced pins the 1.2% of records D94 measured
// with a real (non-"0") introduced bound -- an ordinary OSV event needing no
// special handling, but never previously exercised end to end through this
// package's Fetch/Convert path for Azure Linux specifically. The range must
// survive conversion with both events intact, which is what a matcher-level
// test (internal/matcher's own TestMatch_AzureLinuxBoundedIntroduced) then
// checks actually gets ENFORCED as a bound rather than merely stored.
func TestFetch_AzureLinuxBoundedIntroduced(t *testing.T) {
	body := zipWith(t, map[string]string{
		"AZL-2026-0002.json": `{"id":"AZL-2026-0002","upstream":["CVE-2026-61002"],
			"affected":[{"package":{"name":"golang","ecosystem":"Azure Linux:3"},
				"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"1.18.0"},{"fixed":"1.19.0"}]}]}]}`,
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/Azure Linux/all.zip" {
			http.NotFound(w, r)
			return
		}
		w.Write(body)
	}))
	defer srv.Close()

	p := New([]string{"Azure Linux"}, srv.URL)
	var got []advisory.Advisory
	if _, err := p.Fetch(context.Background(), func(a advisory.Advisory) error {
		got = append(got, a)
		return nil
	}); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(got) != 1 || len(got[0].Affected) != 1 || len(got[0].Affected[0].Ranges) != 1 {
		t.Fatalf("Fetch emitted %+v, want one record with one range", got)
	}
	events := got[0].Affected[0].Ranges[0].Events
	if len(events) != 2 || events[0].Introduced != "1.18.0" || events[1].Fixed != "1.19.0" {
		t.Errorf("Events = %+v, want [Introduced:1.18.0 Fixed:1.19.0] carried through unchanged", events)
	}
}
