package dbcmd

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/dbartifact"
	"github.com/kun9497/assay/internal/provider"
	"github.com/kun9497/assay/internal/store"
)

// The 2026-10-22 external review's #5, at the call site. A seeded build
// carries NVD's ratings forward (D66); an NVD delta that returned a CVE with
// metrics={} (Rejected, Awaiting Analysis) converted to nothing and emitted
// nothing, so the seed's CVSS 9.8 for that CVE rode forward under every
// later artifact while the checkpoint advanced -- a critical that NVD had
// withdrawn, presented as current. An annotator can now withdraw a rating
// it read as gone, and Update applies that to the seeded copy.

// fakeWithdrawingAnnotator is fakeAnnotator plus a list of CVEs the source
// says no longer carry a rating.
type fakeWithdrawingAnnotator struct {
	fakeAnnotator
	withdraw []string
}

// Ratings are emitted BEFORE the withdrawals, so a CVE in both lists is
// one the source rated and then, a window later, said it had un-rated --
// the order the batch must keep.
func (f fakeWithdrawingAnnotator) AnnotateWithdrawing(ctx context.Context, emit func(advisory.Rating) error, withdraw func(cve string) error) (store.Provenance, error) {
	prov, err := f.fakeAnnotator.Annotate(ctx, emit)
	if err != nil {
		return prov, err
	}
	for _, cve := range f.withdraw {
		if err := withdraw(cve); err != nil {
			return store.Provenance{}, err
		}
	}
	return prov, nil
}

var _ provider.WithdrawingAnnotator = fakeWithdrawingAnnotator{}

func TestUpdate_AnAnnotatorsWithdrawalRemovesOnlyThatSourcesSeededRating(t *testing.T) {
	seed := filepath.Join(t.TempDir(), "seed.db")
	w, err := store.Create(seed)
	if err != nil {
		t.Fatal(err)
	}
	critical := []advisory.Severity{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}
	for _, r := range []advisory.Rating{
		{CVE: "CVE-2026-GONE", Source: "NVD", Severity: critical},  // NVD withdrew this one
		{CVE: "CVE-2026-GONE", Source: "KISA", Severity: critical}, // another authority's opinion stays
		{CVE: "CVE-2026-KEPT", Source: "NVD", Severity: critical},  // outside this run's window, untouched
	} {
		if err := w.PutRating(r); err != nil {
			t.Fatal(err)
		}
	}
	w.SetMeta(store.Meta{
		Providers: map[string]store.Provenance{"osv": {DataAsOf: time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)}},
		Ratings: map[string]store.Provenance{"NVD": {Window: "modified 2026-07-05..2026-08-03",
			CoversSince: time.Date(2026, 7, 5, 0, 0, 0, 0, time.UTC), CoversSinceKnown: true}},
	})
	w.Close()

	p := fakeProvider{name: "osv", covers: []string{"Go"}, advs: []advisory.Advisory{{
		ID: "GHSA-new", Database: "GHSA", Source: "osv", Kind: advisory.KindVulnerability,
		Affected: []advisory.Affected{{Ecosystem: "Go", Name: "new"}},
	}}}
	a := fakeWithdrawingAnnotator{
		fakeAnnotator: fakeAnnotator{name: "NVD", window: "modified 2026-08-03..2026-08-04",
			coversSince: time.Date(2026, 8, 3, 0, 0, 0, 0, time.UTC),
			ratings: []advisory.Rating{
				{CVE: "CVE-2026-NEW", Source: "NVD", Severity: critical},
				// Rated in this run's first window, withdrawn in its second
				// (the boundary repeats): the later word wins, and only if
				// the queued put reaches the store before the withdrawal.
				{CVE: "CVE-2026-FLIP", Source: "NVD", Severity: critical},
			}},
		// CVE-2026-NEVER was never rated: withdrawing it is a no-op and must
		// not count as a removal the publish guard would then tolerate.
		withdraw: []string{"CVE-2026-GONE", "CVE-2026-NEVER", "CVE-2026-FLIP"},
	}

	dst := filepath.Join(t.TempDir(), "vulnerability.db")
	var out, errOut bytes.Buffer
	if code := Update(context.Background(), dst, seed, "",
		false, []provider.Provider{p}, []provider.Annotator{a}, nil, nil, &out, &errOut); code != 0 {
		t.Fatalf("Update = %d, want 0 (stderr: %s)", code, errOut.String())
	}

	db, err := store.Open(dst)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rs, err := db.RatingsFor("CVE-2026-GONE")
	if err != nil {
		t.Fatal(err)
	}
	if len(rs) != 1 || rs[0].Source != "KISA" {
		t.Errorf("RatingsFor(CVE-2026-GONE) = %+v, want only KISA's: NVD withdrew its rating and the seeded copy must go with it", rs)
	}
	if rs, err := db.RatingsFor("CVE-2026-KEPT"); err != nil || len(rs) != 1 {
		t.Errorf("RatingsFor(CVE-2026-KEPT) = %v, %v; a seeded rating outside the withdrawals was lost", rs, err)
	}
	if rs, err := db.RatingsFor("CVE-2026-NEW"); err != nil || len(rs) != 1 {
		t.Errorf("RatingsFor(CVE-2026-NEW) = %v, %v; this run's rating is missing", rs, err)
	}
	if rs, err := db.RatingsFor("CVE-2026-FLIP"); err != nil || len(rs) != 0 {
		t.Errorf("RatingsFor(CVE-2026-FLIP) = %v, %v; rated then withdrawn in one run must end absent -- the queued put outran the withdrawal", rs, err)
	}
	m, err := db.Meta()
	if err != nil {
		t.Fatal(err)
	}
	// The count the publish guard reads: ratings that actually existed and
	// were removed on the source's word, not withdrawals requested.
	if got := m.Ratings["NVD"].Withdrawn; got != 2 {
		t.Errorf("Meta.Ratings[NVD].Withdrawn = %d, want 2 (GONE and FLIP existed, NEVER did not)", got)
	}
	if got := m.RatingCounts["NVD"]; got != 2 {
		t.Errorf("RatingCounts[NVD] = %d, want 2 (KEPT and NEW)", got)
	}
	// And the artifact-side view the guard compares carries the same number.
	am, err := artifactMetaFromDB(dst)
	if err != nil {
		t.Fatal(err)
	}
	if got := am.RatingWithdrawals["NVD"]; got != 2 {
		t.Errorf("artifactMetaFromDB RatingWithdrawals[NVD] = %d, want 2", got)
	}
	if am.RatingCounts["NVD"] != 2 {
		t.Errorf("artifactMetaFromDB RatingCounts[NVD] = %d, want 2", am.RatingCounts["NVD"])
	}
}

// The seed's Withdrawn count is THIS run's, never carried forward: a
// tolerance that accumulated across nights would let a later build lose
// ratings it had no word from NVD about.
func TestUpdate_WithdrawnCountIsThisRunsNotTheSeeds(t *testing.T) {
	seed := filepath.Join(t.TempDir(), "seed.db")
	w, err := store.Create(seed)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.PutRating(advisory.Rating{CVE: "CVE-2026-KEPT", Source: "NVD"}); err != nil {
		t.Fatal(err)
	}
	w.SetMeta(store.Meta{
		Providers: map[string]store.Provenance{"osv": {DataAsOf: time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)}},
		Ratings: map[string]store.Provenance{"NVD": {Window: "modified 2026-07-05..2026-08-03",
			CoversSince: time.Date(2026, 7, 5, 0, 0, 0, 0, time.UTC), CoversSinceKnown: true, Withdrawn: 7}},
	})
	w.Close()
	p := fakeProvider{name: "osv", covers: []string{"Go"}, advs: []advisory.Advisory{{
		ID: "GHSA-new", Database: "GHSA", Source: "osv", Kind: advisory.KindVulnerability,
		Affected: []advisory.Affected{{Ecosystem: "Go", Name: "new"}},
	}}}
	a := fakeAnnotator{name: "NVD", window: "modified 2026-08-03..2026-08-04",
		coversSince: time.Date(2026, 8, 3, 0, 0, 0, 0, time.UTC)}
	for _, tc := range []struct {
		name       string
		annotators []provider.Annotator
	}{
		{"the annotator ran and withdrew nothing", []provider.Annotator{a}},
		{"the annotator did not run this build", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dst := filepath.Join(t.TempDir(), "vulnerability.db")
			var out, errOut bytes.Buffer
			if code := Update(context.Background(), dst, seed, "",
				false, []provider.Provider{p}, tc.annotators, nil, nil, &out, &errOut); code != 0 {
				t.Fatalf("Update = %d, want 0 (stderr: %s)", code, errOut.String())
			}
			db, err := store.Open(dst)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			m, err := db.Meta()
			if err != nil {
				t.Fatal(err)
			}
			if got := m.Ratings["NVD"].Withdrawn; got != 0 {
				t.Errorf("Meta.Ratings[NVD].Withdrawn = %d, want 0: the seed's 7 must not ride forward as this run's tolerance", got)
			}
		})
	}
	// A ratings-only build copies the seed's advisories AND ratings whole,
	// so its counts cannot drop; its tolerance must be zero all the same --
	// including for a source whose annotator is not the one being re-run.
	t.Run("ratings-only build re-running another source", func(t *testing.T) {
		other := fakeAnnotator{name: "OTHER", window: "modified 2026-08-03..2026-08-04",
			coversSince: time.Date(2026, 8, 3, 0, 0, 0, 0, time.UTC),
			ratings:     []advisory.Rating{{CVE: "CVE-2026-OTHER", Source: "OTHER"}}}
		dst := filepath.Join(t.TempDir(), "vulnerability.db")
		var out, errOut bytes.Buffer
		if code := Update(context.Background(), dst, seed, "",
			true, nil, []provider.Annotator{other}, nil, nil, &out, &errOut); code != 0 {
			t.Fatalf("Update = %d, want 0 (stderr: %s)", code, errOut.String())
		}
		db, err := store.Open(dst)
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		m, err := db.Meta()
		if err != nil {
			t.Fatal(err)
		}
		if got := m.Ratings["NVD"].Withdrawn; got != 0 {
			t.Errorf("Meta.Ratings[NVD].Withdrawn = %d, want 0 in a ratings-only build", got)
		}
	})
}

// The publish guard: a drop in a source's count is refused unless this
// build withdrew at least that many on the source's word (D136).
func TestRatingCountRegression_ToleratesExactlyTheWithdrawnCount(t *testing.T) {
	cur := dbartifact.Meta{RatingCounts: map[string]int{"NVD": 100, "KEV": 5}}
	for _, tc := range []struct {
		name        string
		counts      map[string]int
		withdrawals map[string]int
		refuse      bool
	}{
		{"drop covered by withdrawals", map[string]int{"NVD": 98, "KEV": 5}, map[string]int{"NVD": 2}, false},
		{"drop larger than withdrawals", map[string]int{"NVD": 97, "KEV": 5}, map[string]int{"NVD": 2}, true},
		{"drop with no withdrawals", map[string]int{"NVD": 99, "KEV": 5}, nil, true},
		{"withdrawals on another source do not excuse NVD", map[string]int{"NVD": 99, "KEV": 5}, map[string]int{"KISA": 5}, true},
		{"withdrawals larger than the drop", map[string]int{"NVD": 99, "KEV": 5}, map[string]int{"NVD": 50}, false},
		{"all withdrawn is still a vanished source", map[string]int{"NVD": 0, "KEV": 5}, map[string]int{"NVD": 100}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := ratingCountRegression(cur, dbartifact.Meta{RatingCounts: tc.counts, RatingWithdrawals: tc.withdrawals})
			if (got != "") != tc.refuse {
				t.Fatalf("reason=%q refuse=%v", got, tc.refuse)
			}
		})
	}
}
