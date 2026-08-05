package dbcmd

import (
	"bytes"
	"context"
	"fmt"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/dbartifact"
	"github.com/kun9497/assay/internal/provider"
	"github.com/kun9497/assay/internal/store"
)

// bounded builds a database with `ratings` NVD ratings whose coverage starts
// at since — zero meaning the whole feed — so a test can publish artifacts
// that differ only in how much they claim to cover.
func bounded(t *testing.T, since time.Time, ratings int) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vulnerability.db")
	w, err := store.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < ratings; i++ {
		if err := w.PutRating(advisory.Rating{CVE: fmt.Sprintf("CVE-2026-%d", i), Source: "NVD"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.SetMeta(store.Meta{
		BuiltAt:   time.Date(2026, 8, 4, 6, 0, 0, 0, time.UTC),
		Providers: map[string]store.Provenance{"osv": {DataAsOf: time.Date(2026, 8, 3, 0, 0, 0, 0, time.UTC)}},
		Ratings:   map[string]store.Provenance{"NVD": {CoversSince: since, CoversSinceKnown: true}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

// liveRegistry starts an in-memory registry and returns a reference into it.
func liveRegistry(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(registry.New())
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return u.Host + "/assay-db:v6"
}

func publishedMeta(t *testing.T, ref string) dbartifact.Meta {
	t.Helper()
	parsed, err := name.ParseReference(ref)
	if err != nil {
		t.Fatal(err)
	}
	img, err := remote.Image(parsed)
	if err != nil {
		t.Fatal(err)
	}
	m, err := dbartifact.MetaOf(img)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// seed publishes a first artifact and fails the test if that push does not
// itself succeed — otherwise a broken guard would make every test below pass
// for the wrong reason.
func seed(t *testing.T, ref string, since time.Time, ratings int) {
	t.Helper()
	var out, errOut bytes.Buffer
	if code := Push(context.Background(), bounded(t, since, ratings), ref, false, &out, &errOut); code != 0 {
		t.Fatalf("seeding the registry failed: %d (%s)", code, errOut.String())
	}
}

// A push that would narrow the published coverage is refused.
//
// The failure this prevents is not hypothetical. The daily workflow seeds
// from this same tag and pushes back to it, so a full build published while
// a delta run is in flight gets overwritten minutes later by an artifact
// seeded from the OLD one. Seven hours of coverage disappears, nothing
// errors, and `db status` goes on reporting the narrower window perfectly
// truthfully — it says what the artifact holds, never that it used to hold
// more.
func TestPush_RefusesToNarrowPublishedCoverage(t *testing.T) {
	ref := liveRegistry(t)
	seed(t, ref, time.Time{}, 5) // published: the whole feed

	var out, errOut bytes.Buffer
	narrow := bounded(t, time.Date(2026, 7, 5, 0, 0, 0, 0, time.UTC), 5)
	if code := Push(context.Background(), narrow, ref, false, &out, &errOut); code != 2 {
		t.Errorf("Push of a narrower artifact = %d, want 2", code)
	}
	if !strings.Contains(errOut.String(), "narrow published coverage") {
		t.Errorf("stderr does not say why:\n%s", errOut.String())
	}
	// And it did not publish anyway. Asserting the exit code alone would
	// pass on a guard that reports the problem and writes regardless.
	if got := publishedMeta(t, ref); !got.RatingsSince.IsZero() {
		t.Errorf("published RatingsSince = %v, want unbounded — the refused push overwrote it", got.RatingsSince)
	}
}

// Narrowing between two bounded artifacts is refused as well.
//
// Split from the unbounded case above because it exercises a different
// branch: comparing two dates, rather than "unbounded versus a date". A
// guard that only handled the unbounded case would still let a 30-day
// artifact replace a 120-day one, which is the shape the daily workflow
// actually produces — it always publishes something bounded.
func TestPush_RefusesToNarrowBetweenTwoBoundedArtifacts(t *testing.T) {
	ref := liveRegistry(t)
	seed(t, ref, time.Date(2026, 4, 6, 0, 0, 0, 0, time.UTC), 5) // ~120 days

	var out, errOut bytes.Buffer
	narrower := bounded(t, time.Date(2026, 7, 5, 0, 0, 0, 0, time.UTC), 5) // ~30 days
	if code := Push(context.Background(), narrower, ref, false, &out, &errOut); code != 2 {
		t.Errorf("Push of a narrower bounded artifact = %d, want 2", code)
	}
	if !strings.Contains(errOut.String(), "2026-04-06") || !strings.Contains(errOut.String(), "2026-07-05") {
		t.Errorf("stderr does not name both bounds:\n%s", errOut.String())
	}
	if got := publishedMeta(t, ref); !got.RatingsSince.Equal(time.Date(2026, 4, 6, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("published RatingsSince = %v, want the original 2026-04-06", got.RatingsSince)
	}
}

// Publishing zero ratings over a rated artifact is the same regression in
// its worst form: the artifact becomes the seed every later delta layers
// onto, so what it drops is never recovered by a later run.
func TestPush_RefusesToPublishFewerRatings(t *testing.T) {
	// Table rather than a single zero case. The first version of this guard
	// refused only zero, and the gap was found by walking into it on the
	// live registry: a 2,903-rating artifact replaced a 23,433-rating one
	// during the run that was demonstrating the guard. Zero is the loudest
	// regression, not the only one.
	for _, tc := range []struct {
		name     string
		incoming int
	}{
		{"none at all", 0},
		{"merely fewer", 3},
		{"one fewer", 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ref := liveRegistry(t)
			seed(t, ref, time.Time{}, 5)

			var out, errOut bytes.Buffer
			if code := Push(context.Background(), bounded(t, time.Time{}, tc.incoming), ref, false, &out, &errOut); code != 2 {
				t.Errorf("Push of %d ratings over 5 = %d, want 2", tc.incoming, code)
			}
			if !strings.Contains(errOut.String(), "rating(s)") {
				t.Errorf("stderr does not name the regression:\n%s", errOut.String())
			}
			if got := publishedMeta(t, ref); got.RatingCount != 5 {
				t.Errorf("published RatingCount = %d, want the original 5", got.RatingCount)
			}
		})
	}

	// The same count is not a regression -- a rebuild that finds nothing new
	// must still be publishable.
	t.Run("the same count is allowed", func(t *testing.T) {
		ref := liveRegistry(t)
		seed(t, ref, time.Time{}, 5)

		var out, errOut bytes.Buffer
		if code := Push(context.Background(), bounded(t, time.Time{}, 5), ref, false, &out, &errOut); code != 0 {
			t.Errorf("Push of an equal count = %d, want 0 (%s)", code, errOut.String())
		}
	})
}

// --force is the deliberate override, and it announces itself rather than
// going quiet — the thing it permits is replacing everyone's database with a
// narrower one.
func TestPush_ForcePublishesTheNarrowerArtifactAndSaysSo(t *testing.T) {
	ref := liveRegistry(t)
	seed(t, ref, time.Time{}, 5)

	var out, errOut bytes.Buffer
	narrow := bounded(t, time.Date(2026, 7, 5, 0, 0, 0, 0, time.UTC), 5)
	if code := Push(context.Background(), narrow, ref, true, &out, &errOut); code != 0 {
		t.Fatalf("Push --force = %d, want 0 (%s)", code, errOut.String())
	}
	if !strings.Contains(errOut.String(), "--force") {
		t.Errorf("a forced narrowing was not announced:\n%s", errOut.String())
	}
	if got := publishedMeta(t, ref); got.RatingsSince.IsZero() {
		t.Error("--force did not actually publish the narrower artifact")
	}
}

// A database that does not record its coverage must publish no coverage
// claim, rather than claiming the broadest possible one.
//
// This is not hypothetical: it happened on the live registry. A database
// built before CoversSince existed has a zero bound, zero was mapped to
// "unbounded", and a 30-day artifact went out claiming the whole feed in its
// own manifest. The give-away is a Provenance that has a Window string but
// no CoversSince — it recorded coverage for a human and not for a machine.
func TestPush_ADatabaseThatDoesNotRecordCoverageClaimsNone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vulnerability.db")
	w, err := store.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.PutRating(advisory.Rating{CVE: "CVE-2026-1", Source: "NVD"}); err != nil {
		t.Fatal(err)
	}
	if err := w.SetMeta(store.Meta{
		Ratings: map[string]store.Provenance{
			"NVD": {Window: "modified 2026-07-05..2026-08-04"},
		},
	}); err != nil {
		t.Fatal(err)
	}
	w.Close()

	ref := liveRegistry(t)
	var out, errOut bytes.Buffer
	if code := Push(context.Background(), path, ref, false, &out, &errOut); code != 0 {
		t.Fatalf("Push = %d, want 0 (%s)", code, errOut.String())
	}
	if got := publishedMeta(t, ref); got.RatingsSinceKnown {
		t.Errorf("published a coverage claim (%v) from a database that records none", got.RatingsSince)
	}
}

// unrecordedCoverage builds a database in the shape a pre-upgrade one has:
// a Window for the reader, nothing a machine can compare.
// ratings is a parameter, not a fixed 1, because this fixture is used
// against seeded registries and the rating-count check is a separate rule:
// a fixture with fewer ratings than the published artifact trips THAT and
// the test stops exercising coverage dates at all. CI caught exactly this —
// the count check landed after the fixture and turned a passing test into
// a failing one for a reason unrelated to what it asserts.
func unrecordedCoverage(t *testing.T, ratings int) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vulnerability.db")
	w, err := store.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < ratings; i++ {
		if err := w.PutRating(advisory.Rating{CVE: fmt.Sprintf("CVE-2026-%d", i), Source: "NVD"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.SetMeta(store.Meta{
		Ratings: map[string]store.Provenance{"NVD": {Window: "modified 2026-07-05..2026-08-04"}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

// Coverage dates cannot be compared when either side does not record them,
// so the guard lets the push through rather than inventing a verdict. The
// rating-count check still applies, which is what stops the worst case.
//
// The published-is-unrecorded direction is the one that matters, and it is
// the live registry's current state: an artifact published before these
// annotations existed carries no claim, and the next push does. Treating a
// missing claim as "unbounded" would make that push look like a narrowing
// and refuse the first honest artifact — a guard that fires hardest exactly
// when it knows least.
func TestPush_UnrecordedCoverageIsNotComparedAsARegression(t *testing.T) {
	t.Run("published records nothing, incoming records a bound", func(t *testing.T) {
		ref := liveRegistry(t)
		var out, errOut bytes.Buffer
		if code := Push(context.Background(), unrecordedCoverage(t, 5), ref, false, &out, &errOut); code != 0 {
			t.Fatalf("seeding failed: %d (%s)", code, errOut.String())
		}
		out.Reset()
		errOut.Reset()
		bounded30 := bounded(t, time.Date(2026, 7, 5, 0, 0, 0, 0, time.UTC), 5)
		if code := Push(context.Background(), bounded30, ref, false, &out, &errOut); code != 0 {
			t.Errorf("Push over an artifact with no coverage claim = %d, want 0 (%s)", code, errOut.String())
		}
	})

	t.Run("published records a bound, incoming records nothing", func(t *testing.T) {
		ref := liveRegistry(t)
		seed(t, ref, time.Time{}, 5)

		var out, errOut bytes.Buffer
		if code := Push(context.Background(), unrecordedCoverage(t, 5), ref, false, &out, &errOut); code != 0 {
			t.Errorf("Push of an artifact with unrecorded coverage = %d, want 0 (%s)", code, errOut.String())
		}
	})
}

// Broadening is never refused. The guard exists to stop coverage going
// backwards, not to freeze it — a full build replacing a windowed one is the
// whole point of having a builder.
func TestPush_AllowsBroadeningCoverage(t *testing.T) {
	ref := liveRegistry(t)
	seed(t, ref, time.Date(2026, 7, 5, 0, 0, 0, 0, time.UTC), 5)

	var out, errOut bytes.Buffer
	if code := Push(context.Background(), bounded(t, time.Time{}, 9), ref, false, &out, &errOut); code != 0 {
		t.Errorf("Push of a BROADER artifact = %d, want 0 (%s)", code, errOut.String())
	}
	if got := publishedMeta(t, ref); !got.RatingsSince.IsZero() {
		t.Errorf("published RatingsSince = %v, want the broader unbounded value", got.RatingsSince)
	}
}

// The first push has nothing to compare against and must not be blocked by
// its own guard. A guard that fails closed on an empty registry would make
// bootstrapping impossible, which is exactly when it is needed least.
func TestPush_FirstPublishIsNotARegression(t *testing.T) {
	ref := liveRegistry(t)

	var out, errOut bytes.Buffer
	narrow := bounded(t, time.Date(2026, 7, 5, 0, 0, 0, 0, time.UTC), 5)
	if code := Push(context.Background(), narrow, ref, false, &out, &errOut); code != 0 {
		t.Errorf("first Push = %d, want 0 (%s)", code, errOut.String())
	}
	if !strings.Contains(errOut.String(), "no published artifact to compare against") {
		t.Errorf("stderr does not explain why the comparison was skipped:\n%s", errOut.String())
	}
}

// Coverage is compared against what the artifact ACTUALLY requested, not
// what the caller asked for. NVD clamps a window wider than its 120-day
// maximum, so a build invoked with a 200-day window really covers 120 — and
// recording the unhonoured request would let it claim to be broader than the
// artifact it is about to replace.
func TestRatingBound_UsesEachSourcesOwnBound(t *testing.T) {
	jul := time.Date(2026, 7, 5, 0, 0, 0, 0, time.UTC)
	may := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)

	// The LATEST bound is the one that limits the artifact: a source
	// covering only since July constrains the whole thing, however far back
	// its neighbour reaches.
	got := ratingBound(store.Meta{Ratings: map[string]store.Provenance{
		"NVD":  {CoversSince: may},
		"KISA": {CoversSince: jul},
	}})
	if !got.Equal(jul) {
		t.Errorf("ratingBound = %v, want the later bound %v", got, jul)
	}

	// An unbounded source does not drag the answer to zero: zero means "no
	// limit", which is broader than any date, so a bounded neighbour still
	// limits the artifact.
	got = ratingBound(store.Meta{Ratings: map[string]store.Provenance{
		"NVD":  {},
		"KISA": {CoversSince: jul},
	}})
	if !got.Equal(jul) {
		t.Errorf("ratingBound = %v, want %v — an unbounded source must not erase a bounded one", got, jul)
	}

	// Every source unbounded is the only case that reports unbounded.
	got = ratingBound(store.Meta{Ratings: map[string]store.Provenance{"NVD": {}}})
	if !got.IsZero() {
		t.Errorf("ratingBound = %v, want zero when nothing is bounded", got)
	}
}

// The scheduled workflow must still be publishable on its second run.
//
// This is the sequence that was broken. The daily build seeds from the
// published artifact and fetches a small window on top, so the entry the
// annotator returns describes three days while the database holds the
// seed's thirty. Publishing that bound made day two look like a narrowing
// of day one, and `db push` refused it -- a workflow that worked perfectly
// the first time and stopped forever the second.
//
// Driven through Update rather than by hand-building Provenance, because
// the defect was in how Update merges, and a fixture that set the merged
// value directly would have passed against the broken code.
func TestPush_ASecondSeededDeltaIsStillPublishable(t *testing.T) {
	ref := liveRegistry(t)

	day := func(n int) time.Time { return time.Date(2026, 8, n, 0, 0, 0, 0, time.UTC) }

	// Day 0: a broad artifact is published.
	seed(t, ref, day(1), 5)

	// Day 1 and day 2: seed from the published artifact, fetch a narrow
	// window on top, publish. Both must succeed.
	for i, fetched := range []time.Time{day(10), day(11)} {
		seedPath := filepath.Join(t.TempDir(), "seed.db")
		var out, errOut bytes.Buffer
		if code := Pull(context.Background(), seedPath, ref, &out, &errOut); code != 0 {
			t.Fatalf("day %d: Pull = %d (%s)", i+1, code, errOut.String())
		}

		built := filepath.Join(t.TempDir(), "vulnerability.db")
		a := fakeAnnotator{
			name:        "NVD",
			ratings:     []advisory.Rating{{CVE: fmt.Sprintf("CVE-2026-new%d", i), Source: "NVD"}},
			window:      "modified narrow",
			coversSince: fetched,
		}
		out.Reset()
		errOut.Reset()
		if code := Update(context.Background(), built, seedPath, ref, nil,
			[]provider.Annotator{a}, &out, &errOut); code != 0 {
			t.Fatalf("day %d: Update = %d (%s)", i+1, code, errOut.String())
		}

		out.Reset()
		errOut.Reset()
		if code := Push(context.Background(), built, ref, false, &out, &errOut); code != 0 {
			t.Fatalf("day %d: Push = %d, want 0 -- the scheduled workflow stops here (%s)",
				i+1, code, errOut.String())
		}
		// And the coverage it publishes is still the seed's, not the narrow
		// fetch: the database holds both.
		if got := publishedMeta(t, ref); !got.RatingsSince.Equal(day(1)) {
			t.Errorf("day %d: published RatingsSince = %v, want the seed's %v", i+1, got.RatingsSince, day(1))
		}
	}
}

// A delta seeded from a FULL-corpus artifact stays full.
//
// This is the case that arrives the moment the unbounded build is
// published: the nightly run seeds from an artifact covering the whole
// feed and fetches three days on top. If the merge let this run's narrow
// bound win, the artifact would claim three days while holding everything,
// and the next push would be refused as a narrowing — the same day-two
// breakage, reintroduced by the broader seed rather than by a narrower one.
func TestPush_ADeltaSeededFromTheWholeFeedStaysWhole(t *testing.T) {
	ref := liveRegistry(t)
	seed(t, ref, time.Time{}, 5) // published: the whole feed

	seedPath := filepath.Join(t.TempDir(), "seed.db")
	var out, errOut bytes.Buffer
	if code := Pull(context.Background(), seedPath, ref, &out, &errOut); code != 0 {
		t.Fatalf("Pull = %d (%s)", code, errOut.String())
	}

	built := filepath.Join(t.TempDir(), "vulnerability.db")
	a := fakeAnnotator{
		name:        "NVD",
		ratings:     []advisory.Rating{{CVE: "CVE-2026-fresh", Source: "NVD"}},
		window:      "modified narrow",
		coversSince: time.Date(2026, 8, 12, 0, 0, 0, 0, time.UTC),
	}
	out.Reset()
	errOut.Reset()
	if code := Update(context.Background(), built, seedPath, ref, nil,
		[]provider.Annotator{a}, &out, &errOut); code != 0 {
		t.Fatalf("Update = %d (%s)", code, errOut.String())
	}

	out.Reset()
	errOut.Reset()
	if code := Push(context.Background(), built, ref, false, &out, &errOut); code != 0 {
		t.Fatalf("Push = %d, want 0 -- a delta on a full seed was refused (%s)", code, errOut.String())
	}
	got := publishedMeta(t, ref)
	if !got.RatingsSinceKnown || !got.RatingsSince.IsZero() {
		t.Errorf("published RatingsSince = %v (known=%v), want unbounded: the database still holds the whole feed",
			got.RatingsSince, got.RatingsSinceKnown)
	}
}
