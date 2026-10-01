package report

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/kun9497/assay/internal/cataloger/cyclonedx"
	"github.com/kun9497/assay/internal/matcher"
	"github.com/kun9497/assay/internal/pkgmeta"
	"github.com/kun9497/assay/internal/store"
)

// D111's helper tests: the branches scancmd's caller tests (coverage_test.go
// there) cannot reach through one real database each — every state in one
// inventory, a hand-built Meta the build would refuse, an empty inventory, and
// the renderers' handling of shapes Run never produces together.

func pkg(name, eco string) pkgmeta.Package {
	return pkgmeta.Package{Name: name, Version: "1.0.0", Ecosystem: eco}
}

func day(s string) time.Time {
	t, err := time.Parse(time.DateOnly, s)
	if err != nil {
		panic(err)
	}
	return t
}

// Every state at once, in an order that is not the sorted one, so sorting is
// observable; and a key frozen in Meta but not covered, and one frozen but
// with no comparer, so the precedence is the matcher's (comparer, then
// coverage, then Frozen) and not "frozen wins".
func TestCoverageOf_StatesCountsAndOrder(t *testing.T) {
	inv := pkgmeta.Target{Packages: []pkgmeta.Package{
		pkg("n1", "npm"),
		pkg("g1", "Go"), pkg("g2", "Go"), pkg("g3", "Go"),
		pkg("a1", "Alpine:v3.18"),
		pkg("u1", ""),
		pkg("b1", "bogus"),
	}}
	m := store.Meta{
		Ecosystems: []string{"Go", "npm"},
		Providers: map[string]store.Provenance{"osv": {
			Ecosystems: []string{"Go", "npm"},
			DataAsOf:   day("2026-09-27"),
			Frozen: map[string]time.Time{
				"npm":          day("2026-06-30"),
				"Alpine:v3.18": day("2026-01-01"), // not covered: not-in-database wins
				"bogus":        day("2026-01-02"), // no comparer: no-comparer wins
			},
		}},
	}
	skipped := []matcher.Skipped{
		// One whole-package skip under Go lowers Go's evaluated count...
		{Package: pkg("g1", "Go"), Reason: "whole"},
		// ...an advisory-scoped one does not: the package was judged.
		{Package: pkg("g2", "Go"), AdvisoryID: "GHSA-x", Reason: "one advisory"},
		{Package: pkg("a1", "Alpine:v3.18"), Reason: "not in db"},
		{Package: pkg("u1", ""), Reason: "no comparer"},
		{Package: pkg("b1", "bogus"), Reason: "no comparer"},
	}
	got := CoverageOf(inv, m, skipped)
	want := []CoverageRecord{
		{Ecosystem: "", Packages: 1, Evaluated: 0, State: CoverageNoComparer},
		{Ecosystem: "Alpine:v3.18", Packages: 1, Evaluated: 0, State: CoverageNotInDatabase},
		{Ecosystem: "Go", Packages: 3, Evaluated: 2, State: CoverageLive, Provider: "osv", DataAsOf: "2026-09-27"},
		{Ecosystem: "bogus", Packages: 1, Evaluated: 0, State: CoverageNoComparer},
		{Ecosystem: "npm", Packages: 1, Evaluated: 1, State: CoverageFrozen, Provider: "osv",
			DataAsOf: "2026-09-27", FrozenSince: "2026-06-30"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("CoverageOf =\n%+v\nwant\n%+v", got, want)
	}
	// The per-key split of Summarize's own evaluated count.
	sum := Summarize(matcher.Result{Skipped: skipped},
		cyclonedx.Stats{Components: len(inv.Packages), Cataloged: len(inv.Packages)}, nil, Coverage{Keys: got})
	var total int
	for _, r := range got {
		total += r.Evaluated
	}
	if total != sum.Evaluated {
		t.Errorf("coverage evaluated sums to %d, Summarize says %d", total, sum.Evaluated)
	}
	if sum.FrozenKeys != 1 {
		t.Errorf("Summary.FrozenKeys = %d, want 1", sum.FrozenKeys)
	}
}

func TestCoverageOf_EmptyInventoryIsAnEmptyArray(t *testing.T) {
	got := CoverageOf(pkgmeta.Target{}, store.Meta{}, nil)
	if got == nil || len(got) != 0 {
		t.Errorf("CoverageOf(empty) = %#v, want a non-nil empty slice", got)
	}
	// And a zero Coverage — what every pre-D111 caller of JSON passes —
	// still encodes the array, with the two target objects absent.
	var buf bytes.Buffer
	if _, err := JSON(&buf, matcher.Result{}, cyclonedx.Stats{}, nil, EOLStatus{}, Coverage{}); err != nil {
		t.Fatal(err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	if string(raw["coverage"]) != "[]" {
		t.Errorf("coverage = %s, want []", raw["coverage"])
	}
	for _, k := range []string{"distro", "inventoryScope"} {
		if v, present := raw[k]; present {
			t.Errorf("%s = %s, want the key absent", k, v)
		}
	}
	var sum map[string]json.RawMessage
	if err := json.Unmarshal(raw["summary"], &sum); err != nil {
		t.Fatal(err)
	}
	if string(sum["frozenKeys"]) != "0" {
		t.Errorf("summary.frozenKeys = %s, want present and 0", sum["frozenKeys"])
	}
}

// The build refuses two providers declaring one key, so Run cannot reach
// this. The tie rule: the provider whose data is oldest — "not recorded"
// counting as oldest — then the first by name; and the earlier freeze date.
func TestCoverageOf_TwoProvidersDeclaringOneKey(t *testing.T) {
	inv := pkgmeta.Target{Packages: []pkgmeta.Package{pkg("g", "Go")}}
	for name, tc := range map[string]struct {
		providers    map[string]store.Provenance
		wantProvider string
		wantAsOf     string
		wantFrozen   string
	}{
		"older data wins over name order": {
			providers: map[string]store.Provenance{
				"a": {Ecosystems: []string{"Go"}, DataAsOf: day("2026-09-27")},
				"b": {Ecosystems: []string{"Go"}, DataAsOf: day("2026-09-20")},
			},
			wantProvider: "b", wantAsOf: "2026-09-20",
		},
		"unrecorded date counts as oldest": {
			providers: map[string]store.Provenance{
				"a": {Ecosystems: []string{"Go"}, DataAsOf: day("2026-09-27")},
				"z": {Ecosystems: []string{"Go"}},
			},
			wantProvider: "z", wantAsOf: "",
		},
		"equal dates fall to the first name": {
			providers: map[string]store.Provenance{
				"m": {Ecosystems: []string{"Go"}, DataAsOf: day("2026-09-27")},
				"c": {Ecosystems: []string{"Go"}, DataAsOf: day("2026-09-27")},
			},
			wantProvider: "c", wantAsOf: "2026-09-27",
		},
		"earlier freeze date wins": {
			providers: map[string]store.Provenance{
				"a": {Ecosystems: []string{"Go"}, DataAsOf: day("2026-09-27"),
					Frozen: map[string]time.Time{"Go": day("2026-07-01")}},
				"b": {Ecosystems: []string{"Go"}, DataAsOf: day("2026-09-27"),
					Frozen: map[string]time.Time{"Go": day("2026-05-01")}},
			},
			wantProvider: "a", wantAsOf: "2026-09-27", wantFrozen: "2026-05-01",
		},
	} {
		t.Run(name, func(t *testing.T) {
			got := CoverageOf(inv, store.Meta{Ecosystems: []string{"Go"}, Providers: tc.providers}, nil)
			if len(got) != 1 {
				t.Fatalf("got %d records, want 1", len(got))
			}
			r := got[0]
			if r.Provider != tc.wantProvider || r.DataAsOf != tc.wantAsOf || r.FrozenSince != tc.wantFrozen {
				t.Errorf("provider/dataAsOf/frozenSince = %q/%q/%q, want %q/%q/%q",
					r.Provider, r.DataAsOf, r.FrozenSince, tc.wantProvider, tc.wantAsOf, tc.wantFrozen)
			}
		})
	}
}

func TestDistroOf(t *testing.T) {
	if got := DistroOf(nil); got != nil {
		t.Errorf("DistroOf(nil) = %+v, want nil", got)
	}
	got := DistroOf(&pkgmeta.Distro{ID: "alpine", VersionID: "3.19.9"})
	want := &DistroRecord{ID: "alpine", VersionID: "3.19.9", Ecosystem: "Alpine:v3.19", Recognized: true}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("DistroOf(alpine) = %+v, want %+v", got, want)
	}
	got = DistroOf(&pkgmeta.Distro{ID: "centos", VersionID: "7"})
	want = &DistroRecord{ID: "centos", VersionID: "7"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("DistroOf(centos) = %+v, want %+v", got, want)
	}
}

// The block's exact wording for every non-live state, in key order, under
// the one line the live keys share — which carries the OLDEST of their dates.
func TestTable_CoverageBlockWording(t *testing.T) {
	cov := Coverage{Keys: []CoverageRecord{
		{Ecosystem: "", Packages: 1, State: CoverageNoComparer},
		{Ecosystem: "Alpine:v3.18", Packages: 1, State: CoverageNotInDatabase},
		{Ecosystem: "Go", Packages: 1, Evaluated: 1, State: CoverageLive, Provider: "osv", DataAsOf: "2026-09-27"},
		{Ecosystem: "PyPI", Packages: 1, Evaluated: 1, State: CoverageLive, Provider: "pypa", DataAsOf: "2026-09-20"},
		{Ecosystem: "npm", Packages: 1, Evaluated: 1, State: CoverageFrozen, Provider: "osv",
			DataAsOf: "2026-09-27", FrozenSince: "2026-06-30"},
	}}
	var buf bytes.Buffer
	if _, err := Table(&buf, matcher.Result{}, cyclonedx.Stats{Components: 5, Cataloged: 5}, nil, EOLStatus{}, cov, false); err != nil {
		t.Fatal(err)
	}
	want := "\ncoverage: 2 key(s) live, data as of 2026-09-20\n" +
		"coverage: \"\" no-comparer\n" +
		"coverage: Alpine:v3.18 not-in-database\n" +
		"coverage: npm frozen since 2026-06-30, osv data as of 2026-09-27\n"
	if !strings.Contains(buf.String(), want) {
		t.Errorf("table lacks the block\n%s\nin:\n%s", want, buf.String())
	}

	// No keys, no block — not "0 key(s) live".
	buf.Reset()
	if _, err := Table(&buf, matcher.Result{}, cyclonedx.Stats{}, nil, EOLStatus{}, Coverage{}, false); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "coverage:") {
		t.Errorf("an empty inventory printed a coverage line:\n%s", buf.String())
	}
}

// A suppressed row carries both ecosystem markers, and each marker's
// footnote prints even when no ACTIVE row earned it — with no coverage
// passed, so the '@' footnote here comes from the row alone.
func TestTable_SuppressedRowCarriesMarkersAndTheirFootnotes(t *testing.T) {
	f := matcher.Finding{
		Package:         pkgmeta.Package{Name: "curl", Version: "8.0", Ecosystem: "openSUSE Leap:15.6"},
		CrossMappedFrom: "SLES:15.SP6",
		FrozenSince:     day("2026-04-30"),
	}
	f.Advisory.ID = "SUSE-2026-0001"
	res := matcher.Result{Suppressed: []matcher.Suppressed{{Finding: f, Reason: "waived", Source: "vex"}}}
	var buf bytes.Buffer
	if _, err := Table(&buf, res, cyclonedx.Stats{Components: 1, Cataloged: 1}, nil, EOLStatus{}, Coverage{}, false); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "  curl  openSUSE Leap:15.6 ~ @  SUSE-2026-0001  (vex: waived)\n") {
		t.Errorf("suppressed row lacks the '~ @' markers:\n%s", out)
	}
	if !strings.Contains(out, "\n~ matched via the SLE codestream it is built from (SLES:15.SP6)") {
		t.Errorf("no '~' footnote for the suppressed row's marker:\n%s", out)
	}
	if !strings.Contains(out, "\n@ advisory data for openSUSE Leap:15.6 includes entries carried forward since 2026-04-30: "+
		"the upstream stopped publishing some or all of it\n") {
		t.Errorf("no '@' footnote for the suppressed row's marker:\n%s", out)
	}
}

// A frozen key that is both in the coverage and under a finding is
// footnoted once, at the earlier of the two dates.
func TestTable_FrozenFootnoteOncePerKey(t *testing.T) {
	f := matcher.Finding{Package: pkg("p", "npm"), FrozenSince: day("2026-06-30")}
	f.Advisory.ID = "GHSA-once-0001"
	cov := Coverage{Keys: []CoverageRecord{{Ecosystem: "npm", Packages: 1, Evaluated: 1,
		State: CoverageFrozen, FrozenSince: "2026-06-29"}}}
	var buf bytes.Buffer
	if _, err := Table(&buf, matcher.Result{Findings: []matcher.Finding{f}}, cyclonedx.Stats{Components: 1, Cataloged: 1},
		nil, EOLStatus{}, cov, false); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if n := strings.Count(out, "@ advisory data for npm"); n != 1 {
		t.Errorf("npm footnoted %d times, want 1:\n%s", n, out)
	}
	if !strings.Contains(out, "carried forward since 2026-06-29:") {
		t.Errorf("footnote does not carry the earlier date:\n%s", out)
	}
}

// Two frozen keys: one rule, two results with distinct fingerprints, the
// target as each result's location (the key when there is no target), and
// coverage beside eol in the invocation's property bag.
func TestSARIF_FrozenDataResultsPerKey(t *testing.T) {
	cov := Coverage{Keys: []CoverageRecord{
		{Ecosystem: "Debian:11", Packages: 1, Evaluated: 1, State: CoverageFrozen, FrozenSince: "2026-08-01"},
		{Ecosystem: "Go", Packages: 1, Evaluated: 1, State: CoverageLive},
		{Ecosystem: "npm", Packages: 1, Evaluated: 1, State: CoverageFrozen, FrozenSince: "2026-06-30"},
	}}
	render := func(target string) sarifDocument {
		t.Helper()
		var buf bytes.Buffer
		if _, err := SARIF(&buf, matcher.Result{}, cyclonedx.Stats{Components: 3, Cataloged: 3}, nil,
			target, "v0", debianBookwormEOL, cov); err != nil {
			t.Fatal(err)
		}
		var doc sarifDocument
		if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
			t.Fatal(err)
		}
		return doc
	}

	doc := render("img:1")
	run := doc.Runs[0]
	var rules int
	for _, r := range run.Tool.Driver.Rules {
		if r.ID == frozenDataRuleID {
			rules++
		}
	}
	if rules != 1 {
		t.Errorf("%s declared %d time(s), want 1", frozenDataRuleID, rules)
	}
	var msgs []string
	prints := map[string]bool{}
	for _, r := range run.Results {
		if r.RuleID != frozenDataRuleID {
			continue
		}
		msgs = append(msgs, r.Message.Text)
		prints[r.PartialFingerprints[fingerprintKey]] = true
		if len(r.Locations) != 1 || r.Locations[0].PhysicalLocation.ArtifactLocation.URI != "img:1" ||
			r.Locations[0].PhysicalLocation.Region != nil {
			t.Errorf("location = %+v, want the target with no region", r.Locations)
		}
	}
	wantMsgs := []string{
		frozenSentence("Debian:11", "2026-08-01"),
		frozenSentence("npm", "2026-06-30"),
	}
	if !reflect.DeepEqual(msgs, wantMsgs) {
		t.Errorf("frozen-data messages = %q, want %q", msgs, wantMsgs)
	}
	if len(prints) != 2 {
		t.Errorf("fingerprints = %v, want two distinct", prints)
	}
	props := run.Invocations[0].Properties
	if _, ok := props["eol"]; !ok {
		t.Errorf("properties lost eol beside coverage: %+v", props)
	}
	if c, ok := props["coverage"].([]any); !ok || len(c) != 3 {
		t.Errorf("properties.coverage = %+v, want the three records", props["coverage"])
	}

	for _, r := range render("").Runs[0].Results {
		if r.RuleID == frozenDataRuleID && !strings.HasPrefix(r.Message.Text, "advisory data for "+
			r.Locations[0].PhysicalLocation.ArtifactLocation.URI+" ") {
			t.Errorf("with no target, location %q is not the result's own key", r.Locations[0].PhysicalLocation.ArtifactLocation.URI)
		}
	}
}

// P1-5: the sentence is true of an entry-level freeze too — it says "some or
// all", never that the release is no longer published at all.
func TestFrozenSentence_CoversEntryLevelFreezes(t *testing.T) {
	got := frozenSentence("Debian:11", "2026-08-01")
	want := "advisory data for Debian:11 includes entries carried forward since 2026-08-01: " +
		"the upstream stopped publishing some or all of it"
	if got != want {
		t.Errorf("frozenSentence = %q\nwant           %q", got, want)
	}
}
