package fedora

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/severity"
)

// buildFixture is one Bodhi update's raw ingredients, rendered to JSON by
// bodhiServer below rather than hand-typed per test -- the real schema
// nests builds and release objects, and a hand-written literal per test
// would drift from bodhi.go's own structs unnoticed.
type updateFixture struct {
	alias      string
	title      string
	notes      string
	severity   string
	typ        string // defaults to "security"
	idPrefix   string // defaults to "FEDORA"
	dateStable string
	builds     []buildFixture
}

type buildFixture struct {
	nvr   string
	epoch *int
	typ   string // defaults to "rpm"
}

// bodhiPageJSON renders one page of Bodhi's own JSON shape.
func bodhiPageJSON(t *testing.T, ups []updateFixture, page, pages, total int) []byte {
	t.Helper()
	type jBuild struct {
		NVR   string `json:"nvr"`
		Epoch *int   `json:"epoch"`
		Type  string `json:"type"`
	}
	type jRelease struct {
		Name     string `json:"name"`
		IDPrefix string `json:"id_prefix"`
		Version  string `json:"version"`
	}
	type jUpdate struct {
		Alias      string   `json:"alias"`
		Title      string   `json:"title"`
		Notes      string   `json:"notes"`
		Severity   string   `json:"severity"`
		Type       string   `json:"type"`
		Release    jRelease `json:"release"`
		Builds     []jBuild `json:"builds"`
		DateStable string   `json:"date_stable"`
	}
	type jPage struct {
		Updates []jUpdate `json:"updates"`
		Page    int       `json:"page"`
		Pages   int       `json:"pages"`
		Total   int       `json:"total"`
	}
	var p jPage
	p.Page, p.Pages, p.Total = page, pages, total
	for _, u := range ups {
		typ := u.typ
		if typ == "" {
			typ = "security"
		}
		idPrefix := u.idPrefix
		if idPrefix == "" {
			idPrefix = "FEDORA"
		}
		ju := jUpdate{
			Alias: u.alias, Title: u.title, Notes: u.notes, Severity: u.severity, Type: typ,
			Release:    jRelease{Name: "F43", IDPrefix: idPrefix, Version: "43"},
			DateStable: u.dateStable,
		}
		for _, b := range u.builds {
			btyp := b.typ
			if btyp == "" {
				btyp = "rpm"
			}
			ju.Builds = append(ju.Builds, jBuild{NVR: b.nvr, Epoch: b.epoch, Type: btyp})
		}
		p.Updates = append(p.Updates, ju)
	}
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// bodhiServer stands up a Bodhi-shaped httptest server. pages maps 1-indexed
// page number to its update fixtures; the total page count is len(pages).
func bodhiServer(t *testing.T, pages map[int][]updateFixture) *httptest.Server {
	t.Helper()
	total := 0
	for _, ups := range pages {
		total += len(ups)
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if got := q.Get("status"); got != "stable" {
			t.Errorf("request did not ask for status=stable, got %q", got)
		}
		if got := q.Get("type"); got != "security" {
			t.Errorf("request did not ask for type=security, got %q", got)
		}
		page := 1
		fmt.Sscanf(q.Get("page"), "%d", &page)
		ups := pages[page]
		w.Header().Set("Content-Type", "application/json")
		w.Write(bodhiPageJSON(t, ups, page, len(pages), total))
	}))
}

// TestFetch_PaginatesAcrossPages is the caller-first proof for item 1: two
// pages behind one httptest server, each with a distinct update, prove page
// advances (page=1 then page=2) rather than looping forever on page 1 or
// stopping after the first page's Pages field is read.
func TestFetch_PaginatesAcrossPages(t *testing.T) {
	srv := bodhiServer(t, map[int][]updateFixture{
		1: {{
			alias: "FEDORA-2026-0001", title: "openssh update", severity: "high",
			dateStable: "2026-01-05 10:00:00",
			builds:     []buildFixture{{nvr: "openssh-8.7p1-1.fc43"}},
		}},
		2: {{
			alias: "FEDORA-2026-0002", title: "curl update", severity: "medium",
			dateStable: "2026-01-06 10:00:00",
			builds:     []buildFixture{{nvr: "curl-8.5.0-1.fc43"}},
		}},
	})
	defer srv.Close()

	p := New(Options{
		Releases: []Release{{Name: "F43", Ecosystem: "Fedora:43"}},
		BaseURL:  srv.URL,
	})
	var got []advisory.Advisory
	prov, err := p.Fetch(context.Background(), func(a advisory.Advisory) error {
		got = append(got, a)
		return nil
	})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("emitted %d advisories, want 2 (one per page): %+v", len(got), got)
	}
	ids := map[string]bool{}
	for _, a := range got {
		ids[a.ID] = true
	}
	if !ids["FEDORA-2026-0001"] || !ids["FEDORA-2026-0002"] {
		t.Errorf("got IDs %v, want both FEDORA-2026-0001 (page 1) and FEDORA-2026-0002 (page 2) -- "+
			"pagination did not actually advance past page 1", ids)
	}
	if prov.Records != 2 {
		t.Errorf("Records = %d, want 2", prov.Records)
	}
	wantAsOf := time.Date(2026, 1, 6, 10, 0, 0, 0, time.UTC)
	if !prov.DataAsOf.Equal(wantAsOf) {
		t.Errorf("DataAsOf = %v, want %v (the latest date_stable across both pages)", prov.DataAsOf, wantAsOf)
	}
}

// TestFetch_ExtractsCVEFromNotesNotJustTitle proves the notes field is
// scanned, not just the title -- the whole point of hazard #2: vunnel's
// title-only method would miss this CVE entirely, and assay's own
// improvement is scanning notes too.
func TestFetch_ExtractsCVEFromNotesNotJustTitle(t *testing.T) {
	srv := bodhiServer(t, map[int][]updateFixture{1: {{
		alias: "FEDORA-2026-1001", title: "bash bugfix and security update",
		notes:      "Fixes an out of bounds read, see CVE-2026-5001 for details.",
		severity:   "low",
		dateStable: "2026-02-01 00:00:00",
		builds:     []buildFixture{{nvr: "bash-5.2-2.fc43"}},
	}}})
	defer srv.Close()

	p := New(Options{Releases: []Release{{Name: "F43", Ecosystem: "Fedora:43"}}, BaseURL: srv.URL})
	var got advisory.Advisory
	if _, err := p.Fetch(context.Background(), func(a advisory.Advisory) error {
		got = a
		return nil
	}); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(got.Related) != 1 || got.Related[0] != "CVE-2026-5001" {
		t.Errorf("Related = %v, want [CVE-2026-5001] extracted from notes", got.Related)
	}
}

// TestFetch_NoExtractableCVEIsCountedNotDropped pins the measured ceiling
// (81.7%, research 2026-08-19): an update whose title+notes carry no CVE at
// all must still become a finding, reachable by its own FEDORA-* id, and
// must be counted in the progress summary rather than silently absent --
// mirroring amazon.TestFetch_NoCVERefsStillEmits's identical proof.
func TestFetch_NoExtractableCVEIsCountedNotDropped(t *testing.T) {
	srv := bodhiServer(t, map[int][]updateFixture{1: {{
		alias: "FEDORA-2026-2002", title: "kernel update", notes: "General stability fixes.",
		severity: "low", dateStable: "2026-02-02 00:00:00",
		builds: []buildFixture{{nvr: "kernel-6.10.5-100.fc43"}},
	}}})
	defer srv.Close()

	var progress strings.Builder
	p := New(Options{
		Releases: []Release{{Name: "F43", Ecosystem: "Fedora:43"}},
		BaseURL:  srv.URL,
		Progress: &progress,
	})
	var got advisory.Advisory
	if _, err := p.Fetch(context.Background(), func(a advisory.Advisory) error {
		got = a
		return nil
	}); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if got.ID != "FEDORA-2026-2002" {
		t.Fatalf("update with no extractable CVE was dropped rather than emitted: %+v", got)
	}
	if len(got.Related) != 0 {
		t.Errorf("Related = %v, want empty", got.Related)
	}
	out := progress.String()
	if !strings.Contains(out, "1 updates carried no extractable CVE") {
		t.Errorf("progress output = %q, want it to count the no-extractable-CVE update loudly", out)
	}
}

// TestFetch_SeverityLadderCoversBodhisOwnWords proves every real Bodhi
// severity word (urgent/high/medium/low) is stored as its own VENDOR_WORD,
// never renamed onto RHSA's vocabulary, and that "unspecified" -- Bodhi's
// own "nobody set one" value -- and a wholly unrecognized word both land as
// no severity entry at all (D17), counted rather than guessed at.
func TestFetch_SeverityLadderCoversBodhisOwnWords(t *testing.T) {
	for _, tt := range []struct {
		word     string
		wantSev  bool
		wantWord string
	}{
		{"urgent", true, "Urgent"},
		{"high", true, "High"},
		{"medium", true, "Medium"},
		{"low", true, "Low"},
		{"unspecified", false, ""},
		{"Sev9000", false, ""}, // never observed; must not be guessed at
	} {
		t.Run(tt.word, func(t *testing.T) {
			srv := bodhiServer(t, map[int][]updateFixture{1: {{
				alias: "FEDORA-2026-3000", title: "CVE-2026-9999 test package update",
				severity: tt.word, dateStable: "2026-03-01 00:00:00",
				builds: []buildFixture{{nvr: "testpkg-1.0-1.fc43"}},
			}}})
			defer srv.Close()

			var progress strings.Builder
			p := New(Options{
				Releases: []Release{{Name: "F43", Ecosystem: "Fedora:43"}},
				BaseURL:  srv.URL,
				Progress: &progress,
			})
			var got advisory.Advisory
			if _, err := p.Fetch(context.Background(), func(a advisory.Advisory) error {
				got = a
				return nil
			}); err != nil {
				t.Fatalf("Fetch: %v", err)
			}
			if tt.wantSev {
				if len(got.Severity) != 1 || got.Severity[0].Type != "VENDOR_WORD" || got.Severity[0].Score != tt.wantWord {
					t.Fatalf("Severity = %+v, want one VENDOR_WORD/%s entry", got.Severity, tt.wantWord)
				}
				// The stored word must actually be scorable, or storing it
				// faithfully was theater: severity.Of must resolve it to a
				// real band, not ErrUnscorable.
				if _, _, err := severity.Of(got.Severity[0].Score); err != nil {
					t.Errorf("severity.Of(%q) = %v, want a real band", got.Severity[0].Score, err)
				}
			} else {
				if len(got.Severity) != 0 {
					t.Errorf("Severity = %+v, want none -- %q must not be guessed at (D17)", got.Severity, tt.word)
				}
			}
		})
	}
}

// TestFetch_UrgentBandsCritical is the direct proof that "urgent" -- Bodhi's
// own top label -- was mapped FAITHFULLY (stored as "Urgent") rather than
// renamed to "Critical", while still banding to severity.Critical.
func TestFetch_UrgentBandsCritical(t *testing.T) {
	srv := bodhiServer(t, map[int][]updateFixture{1: {{
		alias: "FEDORA-2026-4000", title: "CVE-2026-4000 urgent package update",
		severity: "urgent", dateStable: "2026-04-01 00:00:00",
		builds: []buildFixture{{nvr: "urgentpkg-1.0-1.fc43"}},
	}}})
	defer srv.Close()
	p := New(Options{Releases: []Release{{Name: "F43", Ecosystem: "Fedora:43"}}, BaseURL: srv.URL})
	var got advisory.Advisory
	if _, err := p.Fetch(context.Background(), func(a advisory.Advisory) error {
		got = a
		return nil
	}); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(got.Severity) != 1 || got.Severity[0].Score != "Urgent" {
		t.Fatalf("Severity = %+v, want the STORED word to stay \"Urgent\", not renamed to \"Critical\"", got.Severity)
	}
	band, _, err := severity.Of(got.Severity[0].Score)
	if err != nil {
		t.Fatalf("severity.Of(%q): %v", got.Severity[0].Score, err)
	}
	if band != severity.Critical {
		t.Errorf("band = %v, want critical -- \"Urgent\" is Bodhi's own ceiling label", band)
	}
}

// TestFetch_RetriesOn429ThenSucceeds is item 5's 429-then-success proof:
// the first request for a page answers 429, and Fetch must retry rather
// than fail the build.
func TestFetch_RetriesOn429ThenSucceeds(t *testing.T) {
	var calls int32
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		if n == 1 {
			http.Error(w, "slow down", http.StatusTooManyRequests)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(bodhiPageJSON(t, []updateFixture{{
			alias: "FEDORA-2026-5000", title: "CVE-2026-5000 retried package update",
			severity: "low", dateStable: "2026-05-01 00:00:00",
			builds: []buildFixture{{nvr: "retriedpkg-1.0-1.fc43"}},
		}}, 1, 1, 1))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	p := New(Options{Releases: []Release{{Name: "F43", Ecosystem: "Fedora:43"}}, BaseURL: srv.URL})
	var got []advisory.Advisory
	if _, err := p.Fetch(context.Background(), func(a advisory.Advisory) error {
		got = append(got, a)
		return nil
	}); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if atomic.LoadInt32(&calls) < 2 {
		t.Fatalf("server saw %d call(s), want at least 2 (a 429 then a retry)", calls)
	}
	if len(got) != 1 || got[0].ID != "FEDORA-2026-5000" {
		t.Fatalf("emitted %+v, want exactly the one advisory that succeeded after retry", got)
	}
}

// TestFetch_RetriesAMidBodyTruncationThenSucceeds pins the 2026-08-25
// widening: three consecutive nightly publishes died on Bodhi resetting the
// connection mid-body, a transport failure the original 429/5xx-only policy
// deliberately excluded and reality overruled. The first response declares a
// large Content-Length and writes a fragment, so the client's decode dies
// with an unexpected EOF -- the truncation twin of a peer reset, and the
// only one an httptest server can stage portably. The retry must then
// succeed, exactly as TestFetch_RetriesOn429ThenSucceeds does for a status.
func TestFetch_RetriesAMidBodyTruncationThenSucceeds(t *testing.T) {
	var calls int32
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		if n == 1 {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Content-Length", "100000")
			w.Write([]byte(`{"updates": [`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(bodhiPageJSON(t, []updateFixture{{
			alias: "FEDORA-2026-5001", title: "CVE-2026-5001 truncated-once package update",
			severity: "low", dateStable: "2026-05-01 00:00:00",
			builds: []buildFixture{{nvr: "truncpkg-1.0-1.fc43"}},
		}}, 1, 1, 1))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	p := New(Options{Releases: []Release{{Name: "F43", Ecosystem: "Fedora:43"}}, BaseURL: srv.URL})
	var got []advisory.Advisory
	if _, err := p.Fetch(context.Background(), func(a advisory.Advisory) error {
		got = append(got, a)
		return nil
	}); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if atomic.LoadInt32(&calls) < 2 {
		t.Fatalf("server saw %d call(s), want at least 2 (a truncation then a retry)", calls)
	}
	if len(got) != 1 || got[0].ID != "FEDORA-2026-5001" {
		t.Fatalf("emitted %+v, want exactly the one advisory that succeeded after retry", got)
	}
}

// TestFetch_NonRetryable404FailsFast is the other half: a permanent error
// must not be retried at all -- "honest retry ONLY on 429/5xx" means a 404
// exhausts no attempts and fails immediately.
func TestFetch_NonRetryable404FailsFast(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer srv.Close()

	p := New(Options{Releases: []Release{{Name: "F43", Ecosystem: "Fedora:43"}}, BaseURL: srv.URL})
	_, err := p.Fetch(context.Background(), func(advisory.Advisory) error { return nil })
	if err == nil {
		t.Fatal("Fetch: no error, want one for a 404 response")
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("server saw %d call(s), want exactly 1 -- a 404 must not be retried", got)
	}
}

// TestFetch_WrongIDPrefixIsSkippedNotEmitted is the defense-in-depth half of
// hazard #1: even though releases=F43 already scopes the query away from
// EPEL, an update whose release.id_prefix is NOT "FEDORA" must still be
// dropped rather than folded into the Fedora key.
func TestFetch_WrongIDPrefixIsSkippedNotEmitted(t *testing.T) {
	srv := bodhiServer(t, map[int][]updateFixture{1: {
		{alias: "FEDORA-EPEL-2026-0001", title: "CVE-2026-6001 epel package update",
			idPrefix: "FEDORA-EPEL", severity: "high", dateStable: "2026-06-01 00:00:00",
			builds: []buildFixture{{nvr: "epelpkg-1.0-1.el9"}}},
		{alias: "FEDORA-2026-0002", title: "CVE-2026-6002 real fedora package update",
			severity: "high", dateStable: "2026-06-02 00:00:00",
			builds: []buildFixture{{nvr: "fedorapkg-1.0-1.fc43"}}},
	}})
	defer srv.Close()

	p := New(Options{Releases: []Release{{Name: "F43", Ecosystem: "Fedora:43"}}, BaseURL: srv.URL})
	var got []advisory.Advisory
	if _, err := p.Fetch(context.Background(), func(a advisory.Advisory) error {
		got = append(got, a)
		return nil
	}); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(got) != 1 || got[0].ID != "FEDORA-2026-0002" {
		t.Fatalf("emitted %+v, want exactly the one real Fedora update", got)
	}
}

// TestFetch_NonSecurityUpdateIsSkippedNotEmitted is the caller-first half of
// the type=="security" defensive re-check in convertUpdate, mirroring
// amazon's identical test.
func TestFetch_NonSecurityUpdateIsSkippedNotEmitted(t *testing.T) {
	srv := bodhiServer(t, map[int][]updateFixture{1: {
		{alias: "FEDORA-2026-0003", title: "bugfix only", typ: "bugfix",
			severity: "low", dateStable: "2026-07-01 00:00:00",
			builds: []buildFixture{{nvr: "bugfixpkg-1.0-1.fc43"}}},
		{alias: "FEDORA-2026-0004", title: "CVE-2026-7004 real security update",
			severity: "low", dateStable: "2026-07-02 00:00:00",
			builds: []buildFixture{{nvr: "secpkg-1.0-1.fc43"}}},
	}})
	defer srv.Close()

	p := New(Options{Releases: []Release{{Name: "F43", Ecosystem: "Fedora:43"}}, BaseURL: srv.URL})
	var got []advisory.Advisory
	if _, err := p.Fetch(context.Background(), func(a advisory.Advisory) error {
		got = append(got, a)
		return nil
	}); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(got) != 1 || got[0].ID != "FEDORA-2026-0004" {
		t.Fatalf("emitted %+v, want exactly the one security-typed update", got)
	}
}

// TestFetch_EpochIncludedOnlyWhenNonZero pins the rpmEVR convention: a
// nonzero epoch is prefixed, a zero (or absent) one is omitted -- matching
// amazon.rpmEVR's identical convention for the installed side.
func TestFetch_EpochIncludedOnlyWhenNonZero(t *testing.T) {
	zero := 0
	ten := 10
	srv := bodhiServer(t, map[int][]updateFixture{1: {{
		alias: "FEDORA-2026-0005", title: "CVE-2026-8005 epoch package update",
		severity: "low", dateStable: "2026-08-01 00:00:00",
		builds: []buildFixture{
			{nvr: "zero-epoch-1.2.3-4.fc43", epoch: &zero},
			{nvr: "nonzero-epoch-1.5.3-141.fc43", epoch: &ten},
			{nvr: "nil-epoch-2.0.0-1.fc43"},
		},
	}}})
	defer srv.Close()
	p := New(Options{Releases: []Release{{Name: "F43", Ecosystem: "Fedora:43"}}, BaseURL: srv.URL})
	var got advisory.Advisory
	if _, err := p.Fetch(context.Background(), func(a advisory.Advisory) error {
		got = a
		return nil
	}); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	fixed := map[string]string{}
	for _, aff := range got.Affected {
		fixed[aff.Name] = aff.Ranges[0].Events[1].Fixed
	}
	if fixed["zero-epoch"] != "1.2.3-4.fc43" {
		t.Errorf("zero-epoch fixed = %q, want 1.2.3-4.fc43 (no epoch prefix)", fixed["zero-epoch"])
	}
	if fixed["nonzero-epoch"] != "10:1.5.3-141.fc43" {
		t.Errorf("nonzero-epoch fixed = %q, want 10:1.5.3-141.fc43", fixed["nonzero-epoch"])
	}
	if fixed["nil-epoch"] != "2.0.0-1.fc43" {
		t.Errorf("nil-epoch fixed = %q, want 2.0.0-1.fc43 (a null epoch is the same as zero)", fixed["nil-epoch"])
	}
}

// TestFetch_ZeroAdvisoryReleaseErrors is the per-release D20 guard: a
// release whose every update fails conversion (here, no builds at all) must
// fail the build rather than silently produce a database that answers
// every scan of that release with "no advisories" -- mirroring
// amazon.TestFetch_ZeroAdvisoryRepoErrors exactly.
func TestFetch_ZeroAdvisoryReleaseErrors(t *testing.T) {
	srv := bodhiServer(t, map[int][]updateFixture{1: {{
		alias: "FEDORA-2026-0006", title: "CVE-2026-9006 no builds at all",
		severity: "low", dateStable: "2026-08-02 00:00:00",
		// No builds -- buildAffected returns empty, so this is dropped.
	}}})
	defer srv.Close()
	p := New(Options{Releases: []Release{{Name: "F43", Ecosystem: "Fedora:43"}}, BaseURL: srv.URL})
	_, err := p.Fetch(context.Background(), func(advisory.Advisory) error { return nil })
	if err == nil {
		t.Fatal("Fetch: no error, want one -- a release with zero kept advisories must fail the build")
	}
	if !strings.Contains(err.Error(), "Fedora:43") {
		t.Errorf("error %q does not name the release that yielded nothing", err)
	}
}

// TestFetch_PrintsEOLDisclosure is the delete-goes-red test for item 3's
// wiring: if eolDisclosure is ever removed from Fetch, this is the only
// thing that notices -- mirroring amazon.TestFetch_PrintsExtrasDisclosure.
func TestFetch_PrintsEOLDisclosure(t *testing.T) {
	srv := bodhiServer(t, map[int][]updateFixture{1: {{
		alias: "FEDORA-2026-0007", title: "CVE-2026-9007 disclosure test update",
		severity: "low", dateStable: "2026-08-03 00:00:00",
		builds: []buildFixture{{nvr: "disclosurepkg-1.0-1.fc43"}},
	}}})
	defer srv.Close()
	var progress bytes.Buffer
	p := New(Options{
		Releases: []Release{{Name: "F43", Ecosystem: "Fedora:43"}},
		BaseURL:  srv.URL,
		Progress: &progress,
	})
	if _, err := p.Fetch(context.Background(), func(advisory.Advisory) error { return nil }); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	out := progress.String()
	if !strings.Contains(out, "F43") || !strings.Contains(out, "EOL") {
		t.Errorf("progress output = %q, want it to name the fetched release and the EOL-freeze hazard", out)
	}
}

// TestFetch_BuildAffectedUsesSourcePackageName pins the D8 shape the
// research made mandatory: an Affected entry's Name is the SOURCE package
// Koji built ("openssh", not "openssh-server" or any other subpackage),
// exactly what buildAffected must produce for the matcher's
// Package.Source lookup to reach it at all.
func TestFetch_BuildAffectedUsesSourcePackageName(t *testing.T) {
	srv := bodhiServer(t, map[int][]updateFixture{1: {{
		alias: "FEDORA-2026-0008", title: "CVE-2026-9008 source name test update",
		severity: "low", dateStable: "2026-08-04 00:00:00",
		builds: []buildFixture{{nvr: "openssh-8.7p1-1.fc43"}},
	}}})
	defer srv.Close()
	p := New(Options{Releases: []Release{{Name: "F43", Ecosystem: "Fedora:43"}}, BaseURL: srv.URL})
	var got advisory.Advisory
	if _, err := p.Fetch(context.Background(), func(a advisory.Advisory) error {
		got = a
		return nil
	}); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(got.Affected) != 1 || got.Affected[0].Name != "openssh" {
		t.Fatalf("Affected = %+v, want exactly one entry named \"openssh\" (the source package)", got.Affected)
	}
	if got.Affected[0].Ecosystem != "Fedora:43" {
		t.Errorf("Affected[0].Ecosystem = %q, want Fedora:43", got.Affected[0].Ecosystem)
	}
}
