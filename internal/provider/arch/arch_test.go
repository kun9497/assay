package arch

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/store"
)

// rawRow is the wire shape a test builds by hand, kept separate from the
// unexported `row` type this package decodes into: a test fixture should
// look like the real upstream JSON (which also sends severity, type,
// affected, ticket and advisories, even though this package never decodes
// most of them), not like row's own trimmed internal shape.
type rawRow struct {
	Name       string   `json:"name"`
	Packages   []string `json:"packages"`
	Status     string   `json:"status"`
	Severity   string   `json:"severity"`
	Type       string   `json:"type"`
	Affected   string   `json:"affected"`
	Fixed      any      `json:"fixed"` // string or nil -- `any` so a test can send JSON null verbatim
	Ticket     any      `json:"ticket"`
	Issues     []string `json:"issues"`
	Advisories []string `json:"advisories"`
}

// archServer stands up an httptest server serving rows at "/issues/all.json",
// the shape Fetch requests via Options.URL. lastModified, when non-empty, is
// sent as the Last-Modified header; empty exercises fetchAll's fallback
// branch, the ordinary case for this feed (arch.go's own doc comment).
func archServer(t *testing.T, rows []rawRow, lastModified string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/issues/all.json", func(w http.ResponseWriter, r *http.Request) {
		if lastModified != "" {
			w.Header().Set("Last-Modified", lastModified)
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(rows); err != nil {
			t.Fatal(err)
		}
	})
	return httptest.NewServer(mux)
}

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

// runFetch drives Fetch to completion against srv and returns every emitted
// advisory plus its Provenance -- the one seam every test below goes
// through, so a mutation to Fetch's own emit loop or final return can only
// pass by actually satisfying every caller-first assertion downstream.
func runFetch(t *testing.T, srv *httptest.Server) ([]advisory.Advisory, store.Provenance, error) {
	t.Helper()
	var progress bytes.Buffer
	p := New(Options{URL: srv.URL + "/issues/all.json", Progress: &progress})
	var emitted []advisory.Advisory
	prov, err := p.Fetch(context.Background(), func(a advisory.Advisory) error {
		emitted = append(emitted, a)
		return nil
	})
	return emitted, prov, err
}

// TestFetch_FixedStatusProducesAFixedRange is the caller-first proof for
// D97's central status rule: a "Fixed" group becomes one advisory carrying
// a Range whose Fixed event matches the feed's own `fixed` field, keyed
// under the shared "Arch:rolling" sentinel -- and the ID is the bare AVG
// id, never prefixed (D90 does not apply here, unlike photon's own
// PHOTON-prefixed shape -- see feed.go's own doc comment for why).
func TestFetch_FixedStatusProducesAFixedRange(t *testing.T) {
	srv := archServer(t, []rawRow{
		{Name: "AVG-2891", Packages: []string{"roundcubemail"}, Status: "Fixed",
			Fixed: "1.6.11-1", Issues: []string{"CVE-2025-49113"}},
	}, "")
	defer srv.Close()

	advisories, _, err := runFetch(t, srv)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(advisories) != 1 {
		t.Fatalf("Fetch emitted %d advisories, want 1: %+v", len(advisories), advisories)
	}
	adv := advisories[0]
	if adv.ID != "AVG-2891" {
		t.Errorf("ID = %q, want AVG-2891 (bare, no prefix)", adv.ID)
	}
	if adv.Database != "AVG" {
		t.Errorf("Database = %q, want AVG", adv.Database)
	}
	if adv.Source != SourceName {
		t.Errorf("Source = %q, want %q", adv.Source, SourceName)
	}
	if len(adv.Aliases) != 1 || adv.Aliases[0] != "CVE-2025-49113" {
		t.Errorf("Aliases = %v, want [CVE-2025-49113]", adv.Aliases)
	}
	aff := findAffected(t, adv, Ecosystem, "roundcubemail")
	if len(aff.Ranges) != 1 {
		t.Fatalf("Ranges = %+v, want 1", aff.Ranges)
	}
	rng := aff.Ranges[0]
	if rng.FixState != "" {
		t.Errorf("FixState = %q, want empty (a fixed range carries no FixState -- it resolves to fixed by construction)", rng.FixState)
	}
	if len(rng.Events) != 2 || rng.Events[0].Introduced != "0" || rng.Events[1].Fixed != "1.6.11-1" {
		t.Errorf("Events = %+v, want [{Introduced:0} {Fixed:1.6.11-1}]", rng.Events)
	}
}

// TestFetch_VulnerableStatusProducesAFixlessRangeWithNotFixed is D97's other
// half: a "Vulnerable" group (fixed always null) becomes a fix-less range
// with FixState NotFixed -- Arch's own status word is the positive evidence
// D52 requires, not an inference from fixed being absent.
func TestFetch_VulnerableStatusProducesAFixlessRangeWithNotFixed(t *testing.T) {
	srv := archServer(t, []rawRow{
		{Name: "AVG-2907", Packages: []string{"djvulibre"}, Status: "Vulnerable",
			Fixed: nil, Issues: []string{"CVE-2025-53367"}},
	}, "")
	defer srv.Close()

	advisories, _, err := runFetch(t, srv)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	adv := findAdvisory(t, advisories, "AVG-2907")
	aff := findAffected(t, adv, Ecosystem, "djvulibre")
	if len(aff.Ranges) != 1 {
		t.Fatalf("Ranges = %+v, want 1", aff.Ranges)
	}
	rng := aff.Ranges[0]
	if rng.FixState != advisory.FixStateNotFixed {
		t.Errorf("FixState = %q, want %q", rng.FixState, advisory.FixStateNotFixed)
	}
	if len(rng.Events) != 1 || rng.Events[0].Introduced != "0" || rng.Events[0].Fixed != "" {
		t.Errorf("Events = %+v, want [{Introduced:0}] with no Fixed event at all", rng.Events)
	}
}

// TestFetch_TestingStatusProducesAFixedRange proves the branch the live
// feed never exercised (0/2,444 rows measured 2026-08-26): a "Testing"
// group must be treated exactly like "Fixed" -- the fix exists, in the
// testing repository, so the person running the scan can install it, and
// reporting it as unfixable would misreport a real fix as though none
// existed.
func TestFetch_TestingStatusProducesAFixedRange(t *testing.T) {
	srv := archServer(t, []rawRow{
		{Name: "AVG-9001", Packages: []string{"openssl"}, Status: "Testing",
			Fixed: "3.5.5-1", Issues: []string{"CVE-2026-70001"}},
	}, "")
	defer srv.Close()

	advisories, _, err := runFetch(t, srv)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	adv := findAdvisory(t, advisories, "AVG-9001")
	aff := findAffected(t, adv, Ecosystem, "openssl")
	if len(aff.Ranges) != 1 {
		t.Fatalf("Ranges = %+v, want 1", aff.Ranges)
	}
	rng := aff.Ranges[0]
	if rng.FixState != "" {
		t.Errorf("FixState = %q, want empty (Testing resolves like Fixed, not not-fixed)", rng.FixState)
	}
	if len(rng.Events) != 2 || rng.Events[1].Fixed != "3.5.5-1" {
		t.Errorf("Events = %+v, want a Fixed event of 3.5.5-1", rng.Events)
	}
}

// TestFetch_OtherStatusesProduceNoAdvisory is D17's discipline applied to
// this feed's status word: "Not affected" (Arch's own explicit
// never-applied state) and any unrecognized status must never become an
// advisory.
func TestFetch_OtherStatusesProduceNoAdvisory(t *testing.T) {
	for _, status := range []string{"Not affected", "Unknown", "SomeFutureStatus"} {
		t.Run(status, func(t *testing.T) {
			srv := archServer(t, []rawRow{
				{Name: "AVG-1001", Packages: []string{"dropped-pkg"}, Status: status,
					Fixed: "1.0-1", Issues: []string{"CVE-2026-88881"}},
				// A second group with a real Fixed status, so the feed does
				// not trip the zero-advisories guard and this test can tell
				// "correctly excluded" apart from "the whole fetch failed".
				{Name: "AVG-1002", Packages: []string{"kept-pkg"}, Status: "Fixed",
					Fixed: "2.0-1", Issues: []string{"CVE-2026-88882"}},
			}, "")
			defer srv.Close()

			advisories, _, err := runFetch(t, srv)
			if err != nil {
				t.Fatalf("Fetch: %v", err)
			}
			if len(advisories) != 1 || advisories[0].ID != "AVG-1002" {
				t.Fatalf("Fetch emitted %+v, want exactly [AVG-1002] -- status %q must be dropped",
					advisories, status)
			}
		})
	}
}

// TestFetch_NonCVEIssueEntryIsDroppedFromAliases is D17's discipline applied
// to a claimed identifier: even though the live feed measured 100% of
// issues[] entries CVE-shaped, this provider verifies each one rather than
// trusting the field, so a non-CVE entry must never become an alias D25's
// cross-source grouping could join through.
func TestFetch_NonCVEIssueEntryIsDroppedFromAliases(t *testing.T) {
	srv := archServer(t, []rawRow{
		{Name: "AVG-3001", Packages: []string{"somepkg"}, Status: "Fixed", Fixed: "1.0-2",
			Issues: []string{"CVE-2026-77001", "not-a-cve-id"}},
	}, "")
	defer srv.Close()

	advisories, _, err := runFetch(t, srv)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	adv := findAdvisory(t, advisories, "AVG-3001")
	if len(adv.Aliases) != 1 || adv.Aliases[0] != "CVE-2026-77001" {
		t.Errorf("Aliases = %v, want exactly [CVE-2026-77001] -- the non-CVE entry must be dropped", adv.Aliases)
	}
}

// TestFetch_MultiplePackagesEachGetTheirOwnAffected proves a group naming
// more than one package (2.1% of the live feed, 52/2,444 measured
// 2026-08-26) produces one Affected entry per package, all sharing the same
// range, rather than a single entry or a dropped one.
func TestFetch_MultiplePackagesEachGetTheirOwnAffected(t *testing.T) {
	srv := archServer(t, []rawRow{
		{Name: "AVG-2190", Packages: []string{"jre8-openjdk-headless", "jdk8-openjdk"}, Status: "Vulnerable",
			Fixed: nil, Issues: []string{"CVE-2026-23880"}},
	}, "")
	defer srv.Close()

	advisories, _, err := runFetch(t, srv)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	adv := findAdvisory(t, advisories, "AVG-2190")
	if len(adv.Affected) != 2 {
		t.Fatalf("Affected = %+v, want 2 entries (one per package)", adv.Affected)
	}
	findAffected(t, adv, Ecosystem, "jre8-openjdk-headless")
	findAffected(t, adv, Ecosystem, "jdk8-openjdk")
}

// TestFetch_NoSeverityIsStored is the caller-first proof that the tracker's
// severity WORD never reaches Advisory.Severity: a word cannot be banded by
// internal/severity.Of (D13/D17), so a finding's band must come from
// another source's rating joined through Aliases, never a fabricated
// vector here.
func TestFetch_NoSeverityIsStored(t *testing.T) {
	srv := archServer(t, []rawRow{
		{Name: "AVG-4001", Packages: []string{"pkg"}, Status: "Fixed", Fixed: "1.0-1",
			Severity: "Critical", Issues: []string{"CVE-2026-40001"}},
	}, "")
	defer srv.Close()

	advisories, _, err := runFetch(t, srv)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	adv := findAdvisory(t, advisories, "AVG-4001")
	if len(adv.Severity) != 0 {
		t.Errorf("Severity = %+v, want none -- severity=\"Critical\" carries no CVSS vector to store", adv.Severity)
	}
}

// TestFetch_ZeroAdvisoriesErrors is D20's guard: a fetch that filters
// everything out (every row an unrecognized/Not-affected status, say) must
// fail loudly rather than silently produce an empty-but-successful database.
func TestFetch_ZeroAdvisoriesErrors(t *testing.T) {
	srv := archServer(t, []rawRow{
		{Name: "AVG-5001", Packages: []string{"pkg"}, Status: "Not affected", Fixed: nil},
	}, "")
	defer srv.Close()

	_, _, err := runFetch(t, srv)
	if err == nil {
		t.Fatal("Fetch succeeded with zero advisories; want an error naming the shape may have changed")
	}
	if !strings.Contains(err.Error(), "yielded no advisories") {
		t.Errorf("error = %v, want it to name the zero-advisories guard", err)
	}
}

// TestFetch_LastModifiedHeaderIsUsedWhenPresent proves fetchAll's defensive
// header read actually works, even though the live server never sends one
// (arch.go's own doc comment) -- if Arch's server starts sending one, this
// provider must pick it up with no code change.
func TestFetch_LastModifiedHeaderIsUsedWhenPresent(t *testing.T) {
	srv := archServer(t, []rawRow{
		{Name: "AVG-6001", Packages: []string{"pkg"}, Status: "Fixed", Fixed: "1.0-1"},
	}, "Mon, 24 Aug 2026 00:00:00 GMT")
	defer srv.Close()

	_, prov, err := runFetch(t, srv)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	want := time.Date(2026, 8, 24, 0, 0, 0, 0, time.UTC)
	if !prov.DataAsOf.Equal(want) {
		t.Errorf("DataAsOf = %v, want %v", prov.DataAsOf, want)
	}
}

// TestFetch_MissingLastModifiedFallsBackAndWarns proves the ordinary path
// for this feed (unlike photon's, where this is the unobserved branch): no
// Last-Modified header at all still lets the build proceed, with DataAsOf
// close to "now", and a progress line naming the gap.
func TestFetch_MissingLastModifiedFallsBackAndWarns(t *testing.T) {
	srv := archServer(t, []rawRow{
		{Name: "AVG-7001", Packages: []string{"pkg"}, Status: "Fixed", Fixed: "1.0-1"},
	}, "")
	defer srv.Close()

	var progress bytes.Buffer
	p := New(Options{URL: srv.URL + "/issues/all.json", Progress: &progress})
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

// TestFetch_ProvenanceNamesEcosystemAndSourceURL proves Provenance.Ecosystems
// and Provenance.Source both reach the caller -- the "what does this
// database cover" answer `assay db status` reads directly from these
// fields (D20).
func TestFetch_ProvenanceNamesEcosystemAndSourceURL(t *testing.T) {
	srv := archServer(t, []rawRow{
		{Name: "AVG-8001", Packages: []string{"pkg"}, Status: "Fixed", Fixed: "1.0-1"},
	}, "")
	defer srv.Close()

	_, prov, err := runFetch(t, srv)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(prov.Ecosystems) != 1 || prov.Ecosystems[0] != Ecosystem {
		t.Errorf("Ecosystems = %v, want [%s]", prov.Ecosystems, Ecosystem)
	}
	if !strings.Contains(prov.Source, "all.json") {
		t.Errorf("Source = %q, does not name the feed file", prov.Source)
	}
	if prov.Records != 1 {
		t.Errorf("Records = %d, want 1", prov.Records)
	}
}

// TestFetch_NameIsStable pins Name() against accidental drift -- what
// dbcmd.Status's PROVIDER table and Fetch's own error messages key on.
func TestFetch_NameIsStable(t *testing.T) {
	p := New(Options{})
	if got := p.Name(); got != "Arch Linux Security Tracker" {
		t.Errorf("Name() = %q, want %q", got, "Arch Linux Security Tracker")
	}
}
