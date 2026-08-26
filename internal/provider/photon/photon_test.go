package photon

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/kun9497/assay/internal/advisory"
)

// rawRow is the wire shape a test builds by hand, kept separate from the
// unexported `row` type this package decodes into: a test fixture should
// look like the real upstream JSON (which also sends cve_score and aff_ver,
// even though this package never decodes them), not like row's own trimmed
// internal shape.
type rawRow struct {
	CVEID    string  `json:"cve_id"`
	Pkg      string  `json:"pkg"`
	CVEScore float64 `json:"cve_score"`
	AffVer   string  `json:"aff_ver"`
	ResVer   string  `json:"res_ver"`
	Status   string  `json:"status"`
}

// photonServer stands up an httptest server serving one JSON array per
// major at "/cve_data_photon<version>.json", the exact path shape Fetch
// builds from Options.BaseURL. lastModified maps a major's version string to
// the Last-Modified header value to send for it; a version absent from the
// map gets none at all, exercising fetchMajor's fallback branch.
func photonServer(t *testing.T, rows map[string][]rawRow, lastModified map[string]string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	for version, rs := range rows {
		version, rs := version, rs
		mux.HandleFunc("/cve_data_photon"+version+".json", func(w http.ResponseWriter, r *http.Request) {
			if lm, ok := lastModified[version]; ok {
				w.Header().Set("Last-Modified", lm)
			}
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(rs); err != nil {
				t.Fatal(err)
			}
		})
	}
	return httptest.NewServer(mux)
}

// threeMajors is the Options.Majors this file's tests drive Fetch with --
// the same three versions/ecosystems DefaultMajors carries, but pointed at
// an httptest server via BaseURL rather than the live host.
var threeMajors = []Major{
	{Version: "3.0", Ecosystem: "Photon OS:3"},
	{Version: "4.0", Ecosystem: "Photon OS:4"},
	{Version: "5.0", Ecosystem: "Photon OS:5"},
}

// oneMajor5 is the single-major Options.Majors every test that only fixtures
// the 5.0 feed drives Fetch with -- using threeMajors there would make Fetch
// request 3.0/4.0 as well and fail on the 404 photonServer serves for a
// major it was given no rows for.
var oneMajor5 = []Major{{Version: "5.0", Ecosystem: "Photon OS:5"}}

// findAdvisory returns the emitted advisory with the given ID, failing the
// test if there is not exactly one -- collision-free lookup rather than
// trusting emission order.
func findAdvisory(t *testing.T, advisories []advisory.Advisory, id string) advisory.Advisory {
	t.Helper()
	var found []advisory.Advisory
	for _, a := range advisories {
		if a.ID == id {
			found = append(found, a)
		}
	}
	if len(found) != 1 {
		t.Fatalf("findAdvisory(%q) matched %d record(s), want 1", id, len(found))
	}
	return found[0]
}

// findAffected returns the one Affected entry matching (ecosystem, name),
// failing the test if there is not exactly one.
func findAffected(t *testing.T, a advisory.Advisory, ecosystem, name string) advisory.Affected {
	t.Helper()
	var found []advisory.Affected
	for _, aff := range a.Affected {
		if aff.Ecosystem == ecosystem && aff.Name == name {
			found = append(found, aff)
		}
	}
	if len(found) != 1 {
		t.Fatalf("findAffected(%q, %q) on %s matched %d entr(y/ies), want 1: %+v",
			ecosystem, name, a.ID, len(found), a.Affected)
	}
	return found[0]
}

// fixedVersions extracts every `fixed` event's version out of aff's ranges,
// sorted, for a compact assertion against a set rather than caring about
// Range/Event nesting in every test.
func fixedVersions(aff advisory.Affected) []string {
	var out []string
	for _, r := range aff.Ranges {
		for _, e := range r.Events {
			if e.Fixed != "" {
				out = append(out, e.Fixed)
			}
		}
	}
	sort.Strings(out)
	return out
}

// runFetch drives Fetch to completion against srv and returns every emitted
// advisory plus the Provenance -- the one seam every test below goes
// through, so a mutation to Fetch's own emit-loop or its final return can
// only pass by actually satisfying every caller-first assertion downstream.
func runFetch(t *testing.T, srv *httptest.Server, majors []Major) ([]advisory.Advisory, advisory.Advisory, error) {
	t.Helper()
	var progress bytes.Buffer
	p := New(Options{Majors: majors, BaseURL: srv.URL + "/", Progress: &progress})
	var emitted []advisory.Advisory
	_, err := p.Fetch(context.Background(), func(a advisory.Advisory) error {
		emitted = append(emitted, a)
		return nil
	})
	if len(emitted) > 0 {
		return emitted, emitted[0], err
	}
	return emitted, advisory.Advisory{}, err
}

// TestFetch_MergesOneCVEAcrossMajorsIntoOneAdvisory is THE caller-first
// proof for this package's central design decision (buildAdvisories' own
// doc comment in feed.go): the same cve_id, fixed for different packages in
// different Photon majors, must land in ONE "PHOTON-"+cve advisory carrying
// BOTH Affected entries -- not two separate advisories that would collide
// in the store's last-writer-wins by-id bucket (D90) and silently lose one
// major's data. Deleting the global merge in buildAdvisories (processing
// each major independently and emitting per-major) would make this test's
// second assertion fail: only the LAST major's Affected entry would survive
// a real store Put, and this test catches that before a store is even
// involved, by checking the emitted advisory itself carries both.
func TestFetch_MergesOneCVEAcrossMajorsIntoOneAdvisory(t *testing.T) {
	srv := photonServer(t, map[string][]rawRow{
		"3.0": {{CVEID: "CVE-2026-10001", Pkg: "krb5", ResVer: "1.20.2-9.ph3", Status: "Fixed"}},
		"4.0": {{CVEID: "CVE-2026-10001", Pkg: "krb5-libs", ResVer: "1.20.2-10.ph4", Status: "Fixed"}},
		"5.0": {{CVEID: "CVE-2026-99999", Pkg: "curl", ResVer: "8.4.0-2.ph5", Status: "Fixed"}},
	}, nil)
	defer srv.Close()

	advisories, _, err := runFetch(t, srv, threeMajors)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(advisories) != 2 {
		t.Fatalf("Fetch emitted %d advisories, want 2 (one per distinct CVE): %+v", len(advisories), advisories)
	}

	merged := findAdvisory(t, advisories, "PHOTON-CVE-2026-10001")
	if len(merged.Affected) != 2 {
		t.Fatalf("PHOTON-CVE-2026-10001 has %d Affected entries, want 2 (one from 3.0, one from 4.0): %+v",
			len(merged.Affected), merged.Affected)
	}
	a3 := findAffected(t, merged, "Photon OS:3", "krb5")
	if got := fixedVersions(a3); len(got) != 1 || got[0] != "1.20.2-9.ph3" {
		t.Errorf("Photon OS:3/krb5 fixed versions = %v, want [1.20.2-9.ph3]", got)
	}
	a4 := findAffected(t, merged, "Photon OS:4", "krb5-libs")
	if got := fixedVersions(a4); len(got) != 1 || got[0] != "1.20.2-10.ph4" {
		t.Errorf("Photon OS:4/krb5-libs fixed versions = %v, want [1.20.2-10.ph4]", got)
	}

	solo := findAdvisory(t, advisories, "PHOTON-CVE-2026-99999")
	if len(solo.Affected) != 1 {
		t.Fatalf("PHOTON-CVE-2026-99999 has %d Affected entries, want 1", len(solo.Affected))
	}
}

// TestFetch_IDIsPrefixedAndAliasCarriesBareCVE pins D90's exact shape for
// this provider: ID is "PHOTON-"+cve (never the bare CVE, which would
// collide with another provider's record in the store's by-id bucket), the
// bare CVE lives in Aliases (what D25's cross-source grouping reads), and
// Database is the record's own namespace. Asserted as exact field equality,
// not Contains -- "PHOTON-CVE-2026-10001" containing "CVE-2026-10001" as a
// substring is expected and correct here, so a substring check would prove
// nothing (CLAUDE.md's substring-assertion hazard).
func TestFetch_IDIsPrefixedAndAliasCarriesBareCVE(t *testing.T) {
	srv := photonServer(t, map[string][]rawRow{
		"5.0": {{CVEID: "CVE-2026-10001", Pkg: "krb5", ResVer: "1.20.2-9.ph5", Status: "Fixed"}},
	}, nil)
	defer srv.Close()

	_, adv, err := runFetch(t, srv, oneMajor5)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if adv.ID != "PHOTON-CVE-2026-10001" {
		t.Errorf("ID = %q, want %q", adv.ID, "PHOTON-CVE-2026-10001")
	}
	if adv.Database != "PHOTON" {
		t.Errorf("Database = %q, want %q", adv.Database, "PHOTON")
	}
	if len(adv.Aliases) != 1 || adv.Aliases[0] != "CVE-2026-10001" {
		t.Errorf("Aliases = %v, want [CVE-2026-10001]", adv.Aliases)
	}
	if adv.Source != SourceName {
		t.Errorf("Source = %q, want %q", adv.Source, SourceName)
	}
}

// TestFetch_NoSeverityIsStored is the caller-first proof that cve_score
// never reaches Advisory.Severity: a bare CVSS number with no vector cannot
// be banded by internal/severity.Of (D13/D17), so a finding's band must
// come from another source's rating joined through Aliases, not from a
// fabricated vector here.
func TestFetch_NoSeverityIsStored(t *testing.T) {
	srv := photonServer(t, map[string][]rawRow{
		"5.0": {{CVEID: "CVE-2026-10001", Pkg: "krb5", CVEScore: 9.8, ResVer: "1.20.2-9.ph5", Status: "Fixed"}},
	}, nil)
	defer srv.Close()

	_, adv, err := runFetch(t, srv, oneMajor5)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(adv.Severity) != 0 {
		t.Errorf("Severity = %+v, want none -- cve_score (9.8) carries no vector to store", adv.Severity)
	}
}

// TestFetch_NotAffectedProducesNoAdvisory proves the schema rule directly at
// the Fetch boundary: a CVE whose only rows, across every major, are
// status=Not Affected must never be emitted at all -- Photon's schema has
// no affected-no-fix state, so this is not a skip to count, it is the
// correct "never affected" answer.
func TestFetch_NotAffectedProducesNoAdvisory(t *testing.T) {
	srv := photonServer(t, map[string][]rawRow{
		"5.0": {
			{CVEID: "CVE-2026-10001", Pkg: "krb5", AffVer: "NA", ResVer: "NA", Status: "Not Affected"},
			// A second CVE with a real Fixed row, so the feed does not trip
			// the zero-advisories guard and this test can tell "correctly
			// excluded" apart from "the whole fetch failed".
			{CVEID: "CVE-2026-99999", Pkg: "curl", ResVer: "8.4.0-2.ph5", Status: "Fixed"},
		},
	}, nil)
	defer srv.Close()

	advisories, _, err := runFetch(t, srv, oneMajor5)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(advisories) != 1 {
		t.Fatalf("Fetch emitted %d advisories, want 1 (only the Fixed CVE): %+v", len(advisories), advisories)
	}
	if advisories[0].ID != "PHOTON-CVE-2026-99999" {
		t.Errorf("the surviving advisory is %q, want PHOTON-CVE-2026-99999 -- "+
			"the Not-Affected-only CVE must not appear at all", advisories[0].ID)
	}
}

// TestFetch_FixedWinsOverNotAffected is policy 1's caller-first proof: a
// (cve, pkg) key carrying BOTH a Fixed row and a Not-Affected row must still
// produce the Fixed range -- the Not-Affected row is dropped, not the
// reverse. TestFetch_NotAffectedProducesNoAdvisory above already proves the
// opposite outcome (no Fixed row at all -> nothing emitted); this proves the
// conflict itself resolves toward keeping data, not discarding it.
func TestFetch_FixedWinsOverNotAffected(t *testing.T) {
	srv := photonServer(t, map[string][]rawRow{
		"5.0": {
			{CVEID: "CVE-2026-10001", Pkg: "krb5", AffVer: "NA", ResVer: "NA", Status: "Not Affected"},
			{CVEID: "CVE-2026-10001", Pkg: "krb5", ResVer: "1.20.2-9.ph5", Status: "Fixed"},
		},
	}, nil)
	defer srv.Close()

	_, adv, err := runFetch(t, srv, oneMajor5)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	aff := findAffected(t, adv, "Photon OS:5", "krb5")
	if got := fixedVersions(aff); len(got) != 1 || got[0] != "1.20.2-9.ph5" {
		t.Errorf("krb5 fixed versions = %v, want [1.20.2-9.ph5] -- Fixed must win over Not-Affected", got)
	}
}

// TestFetch_BDSARecordsAreDroppedNotEmitted is policy 2's caller-first
// proof: a BDSA-* id (no CVE anywhere in the row) must never become an
// advisory of its own -- D25's cross-source grouping has nothing to join it
// through, and there is no public URL for a reader to verify it against.
func TestFetch_BDSARecordsAreDroppedNotEmitted(t *testing.T) {
	srv := photonServer(t, map[string][]rawRow{
		"5.0": {
			{CVEID: "BDSA-2025-0719", Pkg: "krb5", ResVer: "1.17-15.ph4", Status: "Fixed"},
			{CVEID: "CVE-2026-99999", Pkg: "curl", ResVer: "8.4.0-2.ph5", Status: "Fixed"},
		},
	}, nil)
	defer srv.Close()

	advisories, _, err := runFetch(t, srv, oneMajor5)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(advisories) != 1 || advisories[0].ID != "PHOTON-CVE-2026-99999" {
		t.Fatalf("Fetch emitted %+v, want exactly [PHOTON-CVE-2026-99999] -- BDSA-2025-0719 must be dropped", advisories)
	}
}

// TestFetch_SentinelIDsAreDroppedNotEmitted is policy 3's caller-first
// proof, mirroring TestFetch_BDSARecordsAreDroppedNotEmitted for the OTHER
// hazard: a garbled/placeholder id names nothing D25 can join through
// either.
func TestFetch_SentinelIDsAreDroppedNotEmitted(t *testing.T) {
	for _, sentinel := range []string{"Re", "UNK-1", "UNK-2"} {
		t.Run(sentinel, func(t *testing.T) {
			srv := photonServer(t, map[string][]rawRow{
				"5.0": {
					{CVEID: sentinel, Pkg: "curl", AffVer: "NA", ResVer: "NA", Status: "Not Affected"},
					{CVEID: "CVE-2026-99999", Pkg: "curl", ResVer: "8.4.0-2.ph5", Status: "Fixed"},
				},
			}, nil)
			defer srv.Close()

			advisories, _, err := runFetch(t, srv, oneMajor5)
			if err != nil {
				t.Fatalf("Fetch: %v", err)
			}
			if len(advisories) != 1 || advisories[0].ID != "PHOTON-CVE-2026-99999" {
				t.Fatalf("Fetch emitted %+v, want exactly [PHOTON-CVE-2026-99999] -- %q must be dropped",
					advisories, sentinel)
			}
		})
	}
}

// TestFetch_MultipleFixedVersionsBecomeMultipleRanges proves the real (if
// not one of the three user-decided policies) data shape processMajor's
// MultiFixedVersionKeys counts: two distinct Fixed res_ver values for one
// (cve, pkg) key both survive, as two Range entries on one Affected, rather
// than one silently overwriting the other or an arbitrary "last one wins".
func TestFetch_MultipleFixedVersionsBecomeMultipleRanges(t *testing.T) {
	srv := photonServer(t, map[string][]rawRow{
		"5.0": {
			{CVEID: "CVE-2021-43618", Pkg: "gmp", ResVer: "6.2.1-2.ph5", Status: "Fixed"},
			{CVEID: "CVE-2021-43618", Pkg: "gmp", ResVer: "6.2.1-5.1.ph5", Status: "Fixed"},
		},
	}, nil)
	defer srv.Close()

	_, adv, err := runFetch(t, srv, oneMajor5)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	aff := findAffected(t, adv, "Photon OS:5", "gmp")
	got := fixedVersions(aff)
	want := []string{"6.2.1-2.ph5", "6.2.1-5.1.ph5"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("gmp fixed versions = %v, want %v (both distinct Fixed versions, neither dropped)", got, want)
	}
}

// TestFetch_DataAsOfIsTheStalestMajor is D12's caller-first proof: the
// aggregate Provenance.DataAsOf is the OLDEST of the three majors' own
// Last-Modified times, not the newest and not merely one of them picked
// arbitrarily -- a database is only as fresh as its least current source.
func TestFetch_DataAsOfIsTheStalestMajor(t *testing.T) {
	srv := photonServer(t, map[string][]rawRow{
		"3.0": {{CVEID: "CVE-2026-10001", Pkg: "krb5", ResVer: "1.20.2-9.ph3", Status: "Fixed"}},
		"4.0": {{CVEID: "CVE-2026-10002", Pkg: "krb5", ResVer: "1.20.2-9.ph4", Status: "Fixed"}},
		"5.0": {{CVEID: "CVE-2026-10003", Pkg: "krb5", ResVer: "1.20.2-9.ph5", Status: "Fixed"}},
	}, map[string]string{
		"3.0": "Mon, 24 Aug 2026 00:00:00 GMT", // stalest -- must win
		"4.0": "Tue, 25 Aug 2026 00:00:00 GMT",
		"5.0": "Wed, 26 Aug 2026 00:00:00 GMT",
	})
	defer srv.Close()

	var progress bytes.Buffer
	p := New(Options{Majors: threeMajors, BaseURL: srv.URL + "/", Progress: &progress})
	prov, err := p.Fetch(context.Background(), func(advisory.Advisory) error { return nil })
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	want := time.Date(2026, 8, 24, 0, 0, 0, 0, time.UTC)
	if !prov.DataAsOf.Equal(want) {
		t.Errorf("DataAsOf = %v, want %v (the 3.0 file's own Last-Modified, the stalest of the three)",
			prov.DataAsOf, want)
	}
}

// TestFetch_MissingLastModifiedFallsBackAndWarns proves fetchMajor's
// defensive branch (never observed against the live server, per the package
// doc comment, but real code with its own test): a response with no
// Last-Modified header still lets the build proceed, with DataAsOf close to
// "now" rather than zero, and a progress line naming the gap so a build log
// shows it happened.
func TestFetch_MissingLastModifiedFallsBackAndWarns(t *testing.T) {
	srv := photonServer(t, map[string][]rawRow{
		"5.0": {{CVEID: "CVE-2026-10001", Pkg: "krb5", ResVer: "1.20.2-9.ph5", Status: "Fixed"}},
	}, nil) // no Last-Modified for any major
	defer srv.Close()

	var progress bytes.Buffer
	p := New(Options{Majors: []Major{{Version: "5.0", Ecosystem: "Photon OS:5"}}, BaseURL: srv.URL + "/", Progress: &progress})
	before := time.Now().UTC()
	prov, err := p.Fetch(context.Background(), func(advisory.Advisory) error { return nil })
	after := time.Now().UTC()
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if prov.DataAsOf.Before(before) || prov.DataAsOf.After(after) {
		t.Errorf("DataAsOf = %v, want it between %v and %v (the local-clock fallback)", prov.DataAsOf, before, after)
	}
	if !strings.Contains(progress.String(), "no Last-Modified header") {
		t.Errorf("progress does not disclose the missing header:\n%s", progress.String())
	}
}

// TestFetch_ZeroAdvisoriesAcrossAllMajorsErrors is D20's guard, the same
// shape amazon/oracle/fedora each pin for their own feed: a fetch that
// filters everything out (every row BDSA or sentinel, say) must fail loudly
// rather than silently produce an empty-but-successful database.
func TestFetch_ZeroAdvisoriesAcrossAllMajorsErrors(t *testing.T) {
	srv := photonServer(t, map[string][]rawRow{
		"5.0": {{CVEID: "BDSA-2025-0719", Pkg: "krb5", ResVer: "1.17-15.ph4", Status: "Fixed"}},
	}, nil)
	defer srv.Close()

	_, _, err := runFetch(t, srv, []Major{{Version: "5.0", Ecosystem: "Photon OS:5"}})
	if err == nil {
		t.Fatal("Fetch succeeded with zero advisories; want an error naming the shape may have changed")
	}
	if !strings.Contains(err.Error(), "yielded no advisories") {
		t.Errorf("error = %v, want it to name the zero-advisories guard", err)
	}
}

// TestFetch_ProvenanceNamesEveryMajorEcosystemAndSourceURL proves
// Provenance.Ecosystems and Provenance.Source both reach the caller, sorted
// and joined respectively -- the "what does this database cover" answer
// `assay db status` reads directly from these fields (D20).
func TestFetch_ProvenanceNamesEveryMajorEcosystemAndSourceURL(t *testing.T) {
	srv := photonServer(t, map[string][]rawRow{
		"3.0": {{CVEID: "CVE-2026-10001", Pkg: "krb5", ResVer: "1.20.2-9.ph3", Status: "Fixed"}},
		"4.0": {{CVEID: "CVE-2026-10002", Pkg: "krb5", ResVer: "1.20.2-9.ph4", Status: "Fixed"}},
		"5.0": {{CVEID: "CVE-2026-10003", Pkg: "krb5", ResVer: "1.20.2-9.ph5", Status: "Fixed"}},
	}, nil)
	defer srv.Close()

	var progress bytes.Buffer
	p := New(Options{Majors: threeMajors, BaseURL: srv.URL + "/", Progress: &progress})
	prov, err := p.Fetch(context.Background(), func(advisory.Advisory) error { return nil })
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	wantEcos := []string{"Photon OS:3", "Photon OS:4", "Photon OS:5"}
	if len(prov.Ecosystems) != len(wantEcos) {
		t.Fatalf("Ecosystems = %v, want %v", prov.Ecosystems, wantEcos)
	}
	for i, e := range wantEcos {
		if prov.Ecosystems[i] != e {
			t.Errorf("Ecosystems[%d] = %q, want %q", i, prov.Ecosystems[i], e)
		}
	}
	for _, version := range []string{"3.0", "4.0", "5.0"} {
		if !strings.Contains(prov.Source, "cve_data_photon"+version+".json") {
			t.Errorf("Source = %q, does not name the %s feed file", prov.Source, version)
		}
	}
	if prov.Records != 3 {
		t.Errorf("Records = %d, want 3 (one per distinct CVE)", prov.Records)
	}
}

// TestFetch_NameIsStable pins Name() against accidental drift -- it is what
// dbcmd.Status's PROVIDER table and Fetch's own error messages key on.
func TestFetch_NameIsStable(t *testing.T) {
	p := New(Options{})
	if got := p.Name(); got != "Photon OS CVE metadata" {
		t.Errorf("Name() = %q, want %q", got, "Photon OS CVE metadata")
	}
}
