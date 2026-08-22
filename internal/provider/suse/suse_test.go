package suse

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kun9497/assay/internal/advisory"
)

// nl is a newline, assembled rather than typed (CLAUDE.md's escape-sequence
// hazard).
var nl = string(rune(10))

// fixture reads a checked-in testdata archive. compress/bzip2 has no Writer
// in the Go standard library, so these are generated once by a python
// script and checked in, the same workaround internal/provider/oracle's
// mini-elsa.xml.bz2 uses for the identical gap (see oracle_test.go's doc
// comment). Each was built from the SAME JSON shape csaf_test.go's buildDoc
// produces.
func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatalf("read testdata/%s: %v", name, err)
	}
	return b
}

// feed is a whole SUSE CSAF VEX endpoint: the archive (with its own
// Last-Modified), changes.csv, and the individual documents a delta pass
// fetches.
type feed struct {
	archive         []byte
	archiveModified time.Time // zero means "no Last-Modified header at all"
	// changes is the body served at csaf-vex/changes.csv. Empty means no
	// rows -- a delta pass that finds nothing changed.
	changes string
	// docs are served at their own paths under csaf-vex/; anything listed in
	// changes and absent here 404s (the withdrawn-between-files race).
	docs map[string]string
	// status overrides the response code for a path.
	status map[string]int
	// hits counts requests per path, so a test can assert what was and was
	// not fetched.
	mu   sync.Mutex
	hits map[string]int
}

func serve(t *testing.T, f *feed) *httptest.Server {
	t.Helper()
	f.hits = map[string]int{}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(r.URL.Path, "/")
		f.mu.Lock()
		f.hits[p]++
		f.mu.Unlock()
		if code := f.status[p]; code != 0 {
			http.Error(w, "nope", code)
			return
		}
		switch {
		case p == archiveName:
			if !f.archiveModified.IsZero() {
				w.Header().Set("Last-Modified", f.archiveModified.Format(http.TimeFormat))
			}
			w.Write(f.archive)
		case p == "csaf-vex/"+changesFile:
			fmt.Fprint(w, f.changes)
		case f.docs[strings.TrimPrefix(p, "csaf-vex/")] != "":
			fmt.Fprint(w, f.docs[strings.TrimPrefix(p, "csaf-vex/")])
		case strings.HasPrefix(p, "csaf-vex/") && strings.HasSuffix(p, ".json"):
			// Listed in changes.csv and no longer published.
			http.NotFound(w, r)
		default:
			http.NotFound(w, r)
		}
	})
	s := httptest.NewServer(mux)
	t.Cleanup(s.Close)
	return s
}

func (f *feed) hitsFor(p string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hits[p]
}

func changesCSV(rows ...[2]string) string {
	var b strings.Builder
	for _, r := range rows {
		fmt.Fprintf(&b, "%q,%q"+nl, r[0], r[1])
	}
	return b.String()
}

func fetchAll(t *testing.T, s *httptest.Server) ([]advisory.Advisory, string, error) {
	t.Helper()
	var progress bytes.Buffer
	p := New(Options{BaseURL: s.URL, Progress: &progress})
	var got []advisory.Advisory
	prov, err := p.Fetch(context.Background(), func(a advisory.Advisory) error {
		got = append(got, a)
		return nil
	})
	if err != nil {
		return nil, progress.String(), err
	}
	t.Logf("provenance: source=%s asOf=%s records=%d ecosystems=%v",
		prov.Source, prov.DataAsOf.Format(time.RFC3339), prov.Records, prov.Ecosystems)
	return got, progress.String(), nil
}

var archiveBuilt2026 = time.Date(2026, 8, 19, 0, 47, 14, 0, time.UTC)

func TestFetch(t *testing.T) {
	s := serve(t, &feed{
		archive:         fixture(t, "archive.tar.bz2"),
		archiveModified: archiveBuilt2026,
	})

	got, progress, err := fetchAll(t, s)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("emitted %d advisories, want 2 (CVE-2024-9999 names only a product this "+
			"provider does not ingest): %+v", len(got), got)
	}
	byID := map[string]advisory.Advisory{}
	for _, a := range got {
		byID[a.ID] = a
	}
	fix := byID["CVE-2024-6387"]
	if len(fix.Affected) != 1 || fix.Affected[0].Ecosystem != "SLES:15.SP6" || fix.Affected[0].Name != "openssh" {
		t.Errorf("CVE-2024-6387 affected = %+v", fix.Affected)
	}
	if fix.Database != "SUSE" || fix.Source != SourceName {
		t.Errorf("CVE-2024-6387 identity = %q/%q", fix.Database, fix.Source)
	}

	unfixed := byID["CVE-2002-2439"]
	if len(unfixed.Affected) != 1 || unfixed.Affected[0].Ecosystem != "openSUSE Leap:15.6" || unfixed.Affected[0].Name != "gcc" {
		t.Fatalf("CVE-2002-2439 affected = %+v", unfixed.Affected)
	}
	ev := unfixed.Affected[0].Ranges[0].Events
	if len(ev) != 1 || ev[0].Introduced != "0" || ev[0].Fixed != "" {
		t.Errorf("CVE-2002-2439 events = %+v, want one introduced-0 event and no fixed one", ev)
	}
	// Discards are disclosed, not silent.
	if !strings.Contains(progress, "documents") {
		t.Errorf("progress = %q, want it to account for what was read", progress)
	}
}

// D12: how current the data is comes from the archive's own HTTP
// Last-Modified header, never from the clock on the machine running the
// sync -- SUSE's archive carries no date in its name the way Red Hat's does.
func TestFetch_DataAsOfComesFromTheArchiveHeader(t *testing.T) {
	s := serve(t, &feed{
		archive:         fixture(t, "archive.tar.bz2"),
		archiveModified: archiveBuilt2026,
	})
	p := New(Options{BaseURL: s.URL})
	prov, err := p.Fetch(context.Background(), func(advisory.Advisory) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if !prov.DataAsOf.Equal(archiveBuilt2026) {
		t.Errorf("DataAsOf = %s, want %s -- a mirror serving a stale snapshot fetched today must "+
			"not report as fresh", prov.DataAsOf, archiveBuilt2026)
	}
	want := []string{"SLES:15.SP6", "openSUSE Leap:15.6"}
	if fmt.Sprint(prov.Ecosystems) != fmt.Sprint(want) {
		t.Errorf("Ecosystems = %v, want %v (D20's coverage set)", prov.Ecosystems, want)
	}
}

// A response with no Last-Modified header at all must fail the build rather
// than silently reporting an unknown asOf as "now".
func TestFetch_MissingLastModifiedIsAnError(t *testing.T) {
	s := serve(t, &feed{archive: fixture(t, "archive.tar.bz2")}) // archiveModified left zero
	_, _, err := fetchAll(t, s)
	if err == nil {
		t.Fatal("an archive response with no Last-Modified header was accepted")
	}
	if !strings.Contains(err.Error(), "Last-Modified") {
		t.Errorf("error = %v, want it to name the missing header", err)
	}
}

// A non-200 on the archive HEAD must fail the build before any of the 445 MB
// (in production) is ever requested via GET.
func TestFetch_ArchiveHeadFailureIsAnError(t *testing.T) {
	s := serve(t, &feed{
		archive:         fixture(t, "archive.tar.bz2"),
		archiveModified: archiveBuilt2026,
		status:          map[string]int{archiveName: http.StatusServiceUnavailable},
	})
	_, _, err := fetchAll(t, s)
	if err == nil {
		t.Fatal("a 503 on the archive was accepted")
	}
}

// D20's guard. An archive that yields no SLES or openSUSE Leap records must
// fail the build rather than write a database whose every scan of them
// reports clean.
func TestFetch_NoRecordsIsAnError(t *testing.T) {
	s := serve(t, &feed{
		archive:         fixture(t, "archive_no_records.tar.bz2"),
		archiveModified: archiveBuilt2026,
	})
	_, _, err := fetchAll(t, s)
	if err == nil {
		t.Fatal("an archive with no SLES/Leap records was accepted")
	}
	if !strings.Contains(err.Error(), "no SLES or openSUSE Leap records") {
		t.Errorf("error = %v, want it to name what was missing", err)
	}
}

// One unreadable document is counted and the sync continues.
func TestFetch_OneBadDocumentDoesNotFailTheSync(t *testing.T) {
	s := serve(t, &feed{
		archive:         fixture(t, "archive_with_bad_doc.tar.bz2"),
		archiveModified: archiveBuilt2026,
	})
	got, progress, err := fetchAll(t, s)
	if err != nil {
		t.Fatalf("one unreadable document failed the whole sync: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("emitted %d advisories, want the one that parsed", len(got))
	}
	if !strings.Contains(progress, "1 unreadable documents") {
		t.Errorf("progress = %q, want the unreadable document counted", progress)
	}
}

// The delta pass fetches a document changes.csv lists as changed on or after
// the archive's own Last-Modified, and its emission wins over the archive's
// (last write wins, emitted after the archive walk).
func TestFetch_DeltaFetchesChangedDocuments(t *testing.T) {
	updatedOpenssh := docJSONForTest("CVE-2024-6387",
		[]string{"SUSE Linux Enterprise Server 15 SP6"},
		map[string]string{"openssh-9.6p1-2.1": "pkg:rpm/suse/openssh@9.6p1-2.1?upstream=openssh-9.6p1-2.1.src.rpm"},
		[]string{"SUSE Linux Enterprise Server 15 SP6:openssh-9.6p1-2.1"}, nil)
	newDoc := docJSONForTest("CVE-2026-0001",
		[]string{"openSUSE Leap 15.6"},
		map[string]string{"newpkg-1.0-1.1": "pkg:rpm/suse/newpkg@1.0-1.1?upstream=newpkg-1.0-1.1.src.rpm"},
		[]string{"openSUSE Leap 15.6:newpkg-1.0-1.1"}, nil)

	f := &feed{
		archive:         fixture(t, "archive.tar.bz2"),
		archiveModified: archiveBuilt2026,
		// Ascending order, deliberately NOT sorted newest-first, matching
		// SUSE's real changes.csv (verified live 2026-08-20) -- a row well
		// AFTER the cutoff appears BEFORE an unrelated old row, which would
		// break an early-exit implementation borrowed from Red Hat's.
		changes: changesCSV(
			[2]string{"cve-1999-0003.json", "1999-01-01T00:00:00Z"},
			[2]string{"cve-2024-6387.json", archiveBuilt2026.Add(time.Hour).Format(time.RFC3339)},
			[2]string{"cve-2026-0001.json", archiveBuilt2026.Add(2 * time.Hour).Format(time.RFC3339)},
		),
		docs: map[string]string{
			"cve-2024-6387.json": updatedOpenssh,
			"cve-2026-0001.json": newDoc,
		},
	}
	s := serve(t, f)

	got, _, err := fetchAll(t, s)
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]advisory.Advisory{}
	for _, a := range got {
		byID[a.ID] = a
	}
	if _, ok := byID["CVE-2026-0001"]; !ok {
		t.Fatalf("the delta document was not fetched: %+v", got)
	}
	// Last write wins: the delta's fixed version must be the one that
	// survives, not the archive's.
	fix := byID["CVE-2024-6387"]
	found := false
	for _, r := range fix.Affected[0].Ranges {
		if r.Events[1].Fixed == "9.6p1-2.1" {
			found = true
		}
	}
	if !found {
		t.Errorf("CVE-2024-6387 = %+v, want the delta's fixed version (9.6p1-2.1) to have replaced "+
			"the archive's own (9.6p1-1.1)", fix.Affected)
	}
	// The pre-1999 row, well before the cutoff, must not have been fetched.
	if got := f.hitsFor("csaf-vex/cve-1999-0003.json"); got != 0 {
		t.Errorf("cve-1999-0003.json was fetched %d times, want 0 -- it is well before the cutoff", got)
	}
}

// TestFetch_DeltaOnlyEcosystemSatisfiesTheCoverageGuard is the caller-first
// proof that the delta pass's own covered[a.Ecosystem] write (D20) actually
// feeds Fetch's zero-coverage guard: an archive that yields NOTHING
// (archive_no_records.tar.bz2, the same fixture TestFetch_NoRecordsIsAnError
// uses) paired with a delta document that DOES name a covered platform must
// succeed, with that platform in Provenance.Ecosystems -- not trip the D20
// guard the way an archive-only zero-coverage build would. Every other delta
// test in this file (TestFetch_DeltaFetchesChangedDocuments) starts from an
// archive that already covers something on its own, so none of them can
// tell whether the delta's own write to `covered` did anything at all.
func TestFetch_DeltaOnlyEcosystemSatisfiesTheCoverageGuard(t *testing.T) {
	newDoc := docJSONForTest("CVE-2026-0004",
		[]string{"openSUSE Leap 15.6"},
		map[string]string{"newpkg-1.0-1.1": "pkg:rpm/suse/newpkg@1.0-1.1?upstream=newpkg-1.0-1.1.src.rpm"},
		[]string{"openSUSE Leap 15.6:newpkg-1.0-1.1"}, nil)

	f := &feed{
		archive:         fixture(t, "archive_no_records.tar.bz2"),
		archiveModified: archiveBuilt2026,
		changes: changesCSV(
			[2]string{"cve-2026-0004.json", archiveBuilt2026.Add(time.Hour).Format(time.RFC3339)},
		),
		docs: map[string]string{
			"cve-2026-0004.json": newDoc,
		},
	}
	s := serve(t, f)

	p := New(Options{BaseURL: s.URL})
	var got []advisory.Advisory
	prov, err := p.Fetch(context.Background(), func(a advisory.Advisory) error {
		got = append(got, a)
		return nil
	})
	if err != nil {
		t.Fatalf("Fetch: %v -- a delta-only ecosystem must satisfy D20's coverage guard, not trip it", err)
	}
	if len(got) != 1 {
		t.Fatalf("emitted %d advisories, want 1 (the delta document): %+v", len(got), got)
	}
	want := []string{"openSUSE Leap:15.6"}
	if fmt.Sprint(prov.Ecosystems) != fmt.Sprint(want) {
		t.Errorf("Ecosystems = %v, want %v -- the delta-only platform must reach D20's coverage set",
			prov.Ecosystems, want)
	}
}

// changes.csv is read start to finish, not stopped at the first row before
// the cutoff -- SUSE's own file sorts OLDEST first (verified live), so an
// early exit borrowed from Red Hat's newest-first assumption would return
// NOTHING here: the very first row is always old.
func TestChangedSince_ReadsAscendingFileWithNoEarlyExit(t *testing.T) {
	s := serve(t, &feed{
		changes: changesCSV(
			[2]string{"cve-1999-0003.json", "1999-01-01T00:00:00Z"},
			[2]string{"cve-2010-0001.json", "2010-01-01T00:00:00Z"},
			[2]string{"cve-2026-0002.json", "2026-08-19T12:00:00Z"},
			[2]string{"cve-2026-0003.json", "2026-08-19T13:00:00Z"},
		),
	})
	p := New(Options{BaseURL: s.URL})
	cutoff := time.Date(2026, 8, 19, 0, 0, 0, 0, time.UTC)
	paths, err := p.changedSince(context.Background(), cutoff)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"cve-2026-0002.json": true, "cve-2026-0003.json": true}
	if len(paths) != len(want) {
		t.Fatalf("changedSince = %v, want exactly %v", paths, want)
	}
	for _, p := range paths {
		if !want[p] {
			t.Errorf("changedSince returned %q, not one of the rows on or after the cutoff", p)
		}
	}
}

// A context cancelled mid-stream stops the archive walk, mirroring
// redhat_test.go's TestFetch_HonoursContextCancellation.
func TestFetch_HonoursContextCancellation(t *testing.T) {
	s := serve(t, &feed{
		archive:         fixture(t, "archive_many.tar.bz2"),
		archiveModified: archiveBuilt2026,
	})

	ctx, cancel := context.WithCancel(context.Background())
	emitted := 0
	_, err := New(Options{BaseURL: s.URL}).Fetch(ctx, func(advisory.Advisory) error {
		emitted++
		cancel()
		return nil
	})
	if err == nil {
		t.Fatal("a context cancelled mid-stream did not stop the fetch")
	}
	if emitted > 2 {
		t.Errorf("kept emitting after cancellation: %d advisories", emitted)
	}
}

// docJSONForTest renders one CSAF document in the shape the fixtures use,
// for tests that need to serve one over HTTP directly (the delta path)
// rather than via a checked-in archive.
func docJSONForTest(cve string, platforms []string, packages map[string]string, recommended, knownAffected []string) string {
	var kids []map[string]any
	for _, name := range platforms {
		kids = append(kids, map[string]any{
			"category": "product_name", "name": name,
			"product": map[string]any{"product_id": name},
		})
	}
	for id, purl := range packages {
		kids = append(kids, map[string]any{
			"category": "product_version", "name": id,
			"product": map[string]any{
				"product_id":                    id,
				"product_identification_helper": map[string]any{"purl": purl},
			},
		})
	}
	b, _ := json.Marshal(map[string]any{
		"document":     map[string]any{"title": "test", "tracking": map[string]any{"id": cve}},
		"product_tree": map[string]any{"branches": []any{map[string]any{"category": "vendor", "name": "SUSE", "branches": []any{map[string]any{"category": "product_family", "name": "SUSE Linux Enterprise", "branches": kids}}}}},
		"vulnerabilities": []any{map[string]any{
			"cve": cve,
			"product_status": map[string]any{
				"recommended": recommended, "known_affected": knownAffected,
			},
		}},
	})
	return string(b)
}
