package dbcmd

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/dbartifact"
	"github.com/kun9497/assay/internal/provider"
	"github.com/kun9497/assay/internal/provider/nvd"
	"github.com/kun9497/assay/internal/store"
)

func TestUpdate_ResumesNVDFromSeedCheckpoint(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	checkpoint := now.Add(-10 * 24 * time.Hour)
	seedPath := filepath.Join(t.TempDir(), "seed.db")
	w, err := store.Create(seedPath)
	if err != nil {
		t.Fatal(err)
	}
	since := now.Add(-60 * 24 * time.Hour)
	if err := w.SetMeta(store.Meta{Ratings: map[string]store.Provenance{"NVD": {CoversSince: since, CoversSinceKnown: true, CoversUntil: checkpoint, CoversUntilKnown: true}}}); err != nil {
		t.Fatal(err)
	}
	w.Close()
	var gotStart time.Time
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var err error
		gotStart, err = time.Parse(time.RFC3339Nano, r.URL.Query().Get("lastModStartDate"))
		if err != nil {
			t.Error(err)
		}
		io.WriteString(w, `{"totalResults":0,"timestamp":"2026-09-21T00:00:01.000","vulnerabilities":[]}`)
	}))
	defer srv.Close()
	pause := time.Duration(0)
	a := nvd.New(nvd.Options{BaseURL: srv.URL, Since: now.Add(-3 * 24 * time.Hour), Pause: &pause})
	dst := filepath.Join(t.TempDir(), "out.db")
	var logs bytes.Buffer
	if code := Update(context.Background(), dst, seedPath, "", false, nil, []provider.Annotator{a}, nil, nil, io.Discard, &logs); code != 0 {
		t.Fatalf("build=%d: %s", code, &logs)
	}
	if !gotStart.Equal(checkpoint.Add(-24 * time.Hour)) {
		t.Fatalf("seed checkpoint not passed to annotator: %v", gotStart)
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
	if !m.Ratings["NVD"].CoversSince.Equal(since) || m.Ratings["NVD"].CoversUntil.Before(now) {
		t.Fatalf("wrong merged window: %+v", m.Ratings["NVD"])
	}
}

func TestPush_LegacyManifestStillChecksAdvisoryLoss(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	w, err := store.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Put(advisory.Advisory{ID: "GHSA-legacy", Affected: []advisory.Affected{{Ecosystem: "Go", Name: "a"}}}); err != nil {
		t.Fatal(err)
	}
	if err := w.SetMeta(store.Meta{Providers: map[string]store.Provenance{"osv": {Ecosystems: []string{"Go"}}}}); err != nil {
		t.Fatal(err)
	}
	w.Close()
	img, err := dbartifact.Pack(path, dbartifact.Meta{SchemaVersion: store.SchemaVersion})
	if err != nil {
		t.Fatal(err)
	}
	ref := liveRegistry(t)
	target, err := name.ParseReference(ref)
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.Write(target, img); err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	if code := Push(context.Background(), bounded(t, time.Time{}, 0), ref, false, io.Discard, &logs); code != 2 {
		t.Fatalf("legacy advisory loss published: %d %s", code, &logs)
	}
	before, _ := img.Digest()
	after, err := remote.Image(target)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := after.Digest()
	if before != got {
		t.Fatal("refused push changed the manifest")
	}
}

func TestAdvisoryRegression_WithdrawalsAndMissingCoverage(t *testing.T) {
	base := &dbartifact.AdvisoryCoverage{Total: 100, Counts: map[string]int{"Go": 100}, Ecosystems: []string{"Go"}, Providers: []string{"osv"}}
	for _, tc := range []struct {
		name   string
		next   dbartifact.AdvisoryCoverage
		refuse bool
	}{
		{"small withdrawal", dbartifact.AdvisoryCoverage{Total: 99, Counts: map[string]int{"Go": 99}, Ecosystems: []string{"Go"}, Providers: []string{"osv"}}, false},
		{"boundary", dbartifact.AdvisoryCoverage{Total: 80, Counts: map[string]int{"Go": 80}, Ecosystems: []string{"Go"}, Providers: []string{"osv"}}, false},
		{"large drop", dbartifact.AdvisoryCoverage{Total: 79, Counts: map[string]int{"Go": 79}, Ecosystems: []string{"Go"}, Providers: []string{"osv"}}, true},
		{"provider missing", dbartifact.AdvisoryCoverage{Total: 100, Counts: map[string]int{"Go": 100}, Ecosystems: []string{"Go"}}, true},
		{"ecosystem missing", dbartifact.AdvisoryCoverage{Total: 100, Counts: map[string]int{"Go": 100}, Providers: []string{"osv"}}, true},
		{"masked by another ecosystem", dbartifact.AdvisoryCoverage{Total: 100, Counts: map[string]int{"Go": 1, "npm": 99}, Ecosystems: []string{"Go", "npm"}, Providers: []string{"osv"}}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := advisoryRegression(base, &tc.next); (got != "") != tc.refuse {
				t.Fatalf("reason=%q refuse=%v", got, tc.refuse)
			}
		})
	}
}

func TestRatingCountRegression_SnapshotsMayShrinkButNVDMayNot(t *testing.T) {
	cur := dbartifact.Meta{RatingCounts: map[string]int{"NVD": 100, "KEV": 5}}
	for _, tc := range []struct {
		counts map[string]int
		refuse bool
	}{
		{map[string]int{"NVD": 100, "KEV": 4}, false},
		{map[string]int{"NVD": 99, "KEV": 100}, true},
		{map[string]int{"NVD": 100}, true},
		{map[string]int{"NVD": 100, "KEV": 0}, false},
	} {
		t.Run(fmt.Sprint(tc.counts), func(t *testing.T) {
			if got := ratingCountRegression(cur, dbartifact.Meta{RatingCounts: tc.counts}); (got != "") != tc.refuse {
				t.Fatalf("reason=%q refuse=%v", got, tc.refuse)
			}
		})
	}
}

// retirementDB builds a database whose one provider declares exactly ecos and
// whose records cover them: nine advisories in ecos[0] and one in each of the
// rest, plus a fixed three NVD ratings.
//
// The proportions are the fixture, not decoration. Dropping the second
// ecosystem costs 10% of the corpus, which is inside advisoryRegression's 20%
// total-drop tolerance, so the refusal in the test below can only come from the
// per-ecosystem rule a retirement actually trips — a fixture where the total
// also collapsed would pass while that rule was deleted. The ratings are held
// constant across every artifact published here for the same reason, so
// ratingCountRegression is never the thing refusing.
//
// One provider rather than two: retiring a RELEASE leaves the provider in
// place, and routing through the provider rule instead would test the wrong
// half of advisoryRegression. "Go" and "Retired-Eco" are neither substrings of
// each other nor of any package name, advisory ID or registry reference in this
// output, so an assertion naming one cannot be satisfied by the other column
// (CLAUDE.md's substring rule).
func retirementDB(t *testing.T, ecos ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vulnerability.db")
	w, err := store.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 9; i++ {
		if err := w.Put(advisory.Advisory{
			ID:       fmt.Sprintf("OSV-2026-%04d", i),
			Affected: []advisory.Affected{{Ecosystem: ecos[0], Name: "alpha"}},
		}); err != nil {
			t.Fatal(err)
		}
	}
	for i, eco := range ecos[1:] {
		if err := w.Put(advisory.Advisory{
			ID:       fmt.Sprintf("OSV-2026-9%03d", i),
			Affected: []advisory.Affected{{Ecosystem: eco, Name: "beta"}},
		}); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 3; i++ {
		if err := w.PutRating(advisory.Rating{CVE: fmt.Sprintf("CVE-2026-%d", i), Source: "NVD"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.SetMeta(store.Meta{
		Providers: map[string]store.Provenance{"osv": {Ecosystems: ecos}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

// publishedCovers reports whether the artifact at ref declares eco in its own
// advisory-coverage annotation — i.e. whether the artifact the NEXT push will
// be measured against still expects that ecosystem.
func publishedCovers(t *testing.T, ref, eco string) bool {
	t.Helper()
	m := publishedMeta(t, ref)
	if m.Advisories == nil {
		t.Fatalf("the published artifact carries no advisory-coverage annotation, so there is "+
			"nothing to ask about %q", eco)
	}
	return slices.Contains(m.Advisories.Ecosystems, eco)
}

// Retiring a release costs exactly ONE forced publish, and the nightly recovers
// by itself afterwards.
//
// Retirement is data-driven here, not date-driven: the Fedora and Photon
// providers enumerate their releases in code, and SUSE and Red Hat recompute
// their covered set from the feed on every run — so an ecosystem key simply
// stops appearing, and the publish guard (refuseCoverageRegression, push.go)
// reads that as the advisory loss it exists to refuse. It is right to refuse:
// the same signal is produced by a provider disabled for one run and by a key
// that flaps between archive snapshots. But no workflow can pass --force
// (db-publish.yml and db-backfill.yml both run `db push <ref>` bare), so until
// an operator pushes once by hand the nightly is refused EVERY day.
//
// The operator's question is how many times that costs, and the answer is the
// whole procedure: Pack writes the coverage annotations from the staged
// database whatever force says (it runs before the guard and takes no force
// parameter), so the forced artifact becomes the baseline and the next ordinary
// push measures the retired state against itself.
//
// Driven through Push four times rather than through advisoryRegression,
// because the helper's "ecosystem missing" row was already covered and proves
// none of this: whether the guard reads the PUBLISHED artifact, whether --force
// reaches the refusal at all, and above all whether the forced push leaves a
// baseline the next unforced one can clear. That last step is the one an
// operator would otherwise discover by hand at 06:00 UTC, and it was verified
// only by a manual registry probe until this test existed.
func TestPush_RetirementCostsOneForcedPublishAndThenRecovers(t *testing.T) {
	// The whole rendered fragment, not the ecosystem name alone: asserting
	// "Retired-Eco" would pass on a message that named the key while dropping
	// what happened to it, and on the PROVIDER branch of the same loop.
	//
	// Pinned to this rule deliberately, and the exit code is not enough to do
	// it. A retirement trips TWO of advisoryRegression's rules at once and
	// always will: an ecosystem that disappears from the declared set also has
	// a per-ecosystem count of zero, because artifactMetaFromDB keys Counts on
	// the declared Ecosystems. Deleting the missing-ecosystem branch therefore
	// still exits 2 — the count rule catches the same loss one case later —
	// and only the message says which rule an operator's nightly log will
	// carry. Verified by mutation: with that branch removed the exit code
	// stayed 2 and this assertion is what went red.
	const refusal = `published ecosystem "Retired-Eco" is missing`

	ref := liveRegistry(t)
	before := retirementDB(t, "Go", "Retired-Eco")
	after := retirementDB(t, "Go")

	// 1. The state before the retirement publishes normally. Asserted rather
	// than assumed: a guard broken enough to refuse everything would make every
	// step below pass for the wrong reason.
	var out, errOut bytes.Buffer
	if code := Push(context.Background(), before, ref, false, &out, &errOut); code != 0 {
		t.Fatalf("publishing the pre-retirement artifact = %d, want 0 (%s)", code, errOut.String())
	}

	// 2. The first nightly built after the retirement is refused...
	out.Reset()
	errOut.Reset()
	if code := Push(context.Background(), after, ref, false, &out, &errOut); code != 2 {
		t.Fatalf("the first post-retirement push = %d, want 2 (%s)", code, errOut.String())
	}
	if !strings.Contains(errOut.String(), refusal) {
		t.Errorf("the refusal does not name the retired ecosystem and what became of it (%q):\n%s",
			refusal, errOut.String())
	}
	// ...and it changed nothing, which is why the block repeats every night
	// instead of clearing itself: the baseline still expects the retired key.
	if !publishedCovers(t, ref, "Retired-Eco") {
		t.Fatal("the refused push replaced the published artifact anyway")
	}

	// 3. --force is the only way through, and it says so rather than going
	// quiet — the thing it permits is publishing a narrower database.
	out.Reset()
	errOut.Reset()
	if code := Push(context.Background(), after, ref, true, &out, &errOut); code != 0 {
		t.Fatalf("the forced post-retirement push = %d, want 0 (%s)", code, errOut.String())
	}
	const warning = `warning: ` + refusal + `; publishing anyway because --force was given`
	if !strings.Contains(errOut.String(), warning) {
		t.Errorf("the forced push does not announce what it overrode (%q):\n%s", warning, errOut.String())
	}
	// Published, not merely permitted. Exit 0 alone would pass on a --force
	// that warns and then declines to write, which leaves step 4 blocked
	// forever while reporting success every night.
	// t.Errorf, not t.Fatal: step 4 below must be allowed to run and report
	// separately. The two say different things — this one that the artifact
	// changed, that one that the nightly recovers — and stopping here would
	// leave the operator-facing half of the claim untested whenever the
	// mechanism breaks.
	if publishedCovers(t, ref, "Retired-Eco") {
		t.Errorf("--force returned 0 without replacing the published artifact, so the " +
			"baseline still expects the retired ecosystem")
	}

	// 4. ...and it is needed exactly once. This is the assertion the whole test
	// exists for: the nightly, which cannot pass --force, publishes again on its
	// own the next day.
	out.Reset()
	errOut.Reset()
	if code := Push(context.Background(), after, ref, false, &out, &errOut); code != 0 {
		t.Fatalf("the next ordinary nightly after the forced publish = %d, want 0 — the "+
			"retirement would need --force every day (%s)", code, errOut.String())
	}
	if strings.Contains(errOut.String(), refusal) {
		t.Errorf("the ordinary push still complains about the retired ecosystem:\n%s", errOut.String())
	}
}

func TestMergeRatingCoverage_ConnectedSpansKeepTheLaterEnd(t *testing.T) {
	date := func(day int) time.Time { return time.Date(2026, 9, day, 0, 0, 0, 0, time.UTC) }
	for _, tc := range []struct{ s1, e1, s2, e2, start, end int }{{1, 10, 1, 8, 1, 10}, {1, 10, 1, 20, 1, 20}, {5, 10, 1, 20, 1, 20}, {1, 20, 5, 10, 1, 20}} {
		s := store.Provenance{CoversSince: date(tc.s1), CoversSinceKnown: true, CoversUntil: date(tc.e1), CoversUntilKnown: true}
		f := store.Provenance{CoversSince: date(tc.s2), CoversSinceKnown: true, CoversUntil: date(tc.e2), CoversUntilKnown: true}
		got := mergeRatingCoverage(s, f)
		if !got.CoversSince.Equal(date(tc.start)) || !got.CoversUntil.Equal(date(tc.end)) {
			t.Fatalf("%+v: %+v", tc, got)
		}
	}
}
