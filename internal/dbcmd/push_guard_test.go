package dbcmd

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
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
		if code := Update(context.Background(), built, seedPath, ref, false, nil,
			[]provider.Annotator{a}, nil, &out, &errOut); code != 0 {
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
	if code := Update(context.Background(), built, seedPath, ref, false, nil,
		[]provider.Annotator{a}, nil, &out, &errOut); code != 0 {
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

// The enrichment record's own text, named rather than repeated so the test
// that scans the PUBLISHED BYTES for it cannot drift from the fixture that
// wrote it — a sentinel scan looking for a string the fixture no longer
// stores passes unconditionally, which is the worst shape a test can take on
// a guarantee like D29's.
//
// All three are Korean or a URL, so none can be satisfied by another field's
// text (CLAUDE.md's substring rule).
const (
	kisaTitle   = "OpenSSL 보안 업데이트 권고"
	kisaSummary = "원격의 공격자가 임의 코드를 실행할 수 있는 취약점"
	kisaURL     = "https://knvd.krcert.or.kr/info/vuln/notice/detail?id=99"
)

// enrichedDatabase builds a database holding all three record kinds — an
// advisory, a rating and an enrichment — so a D29 test can tell "the strip
// removed the enrichment" from "the strip removed the database".
//
// Its identifiers deliberately do not nest: the advisory ID ALPINE-2025-0001
// does not contain the CVE, and the CVE does not contain the package name, so
// no assertion made against this fixture can be satisfied by a neighbouring
// column (CLAUDE.md's substring rule).
func enrichedDatabase(t *testing.T) string {
	t.Helper()
	return enrichedDatabaseOfSize(t, 1)
}

// enrichedDatabaseOfSize is enrichedDatabase with n enrichment records rather
// than one, all carrying the same prose so a byte scan of the published layer
// counts n copies of it rather than one.
//
// The first record is always the CVE every other D29 test here asks about;
// the rest exist only to make the freed pages numerous enough that page reuse
// cannot explain a clean result away.
func enrichedDatabaseOfSize(t *testing.T, n int) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vulnerability.db")
	w, err := store.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Put(advisory.Advisory{
		ID: "ALPINE-2025-0001", Database: "ALPINE", Source: "osv",
		Kind:     advisory.KindVulnerability,
		Upstream: []string{"CVE-2025-46394"},
		Affected: []advisory.Affected{{Ecosystem: "Alpine:v3.19", Name: "openssl"}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := w.PutRating(advisory.Rating{CVE: "CVE-2025-46394", Source: "NVD"}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		cve := "CVE-2025-46394"
		if i > 0 {
			cve = fmt.Sprintf("CVE-2025-9%04d", i)
		}
		if err := w.PutEnrichment(advisory.Enrichment{
			CVE: cve, Source: "KISA",
			Title:   kisaTitle,
			Summary: kisaSummary,
			URL:     kisaURL,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.SetMeta(store.Meta{
		BuiltAt:    time.Date(2026, 8, 5, 6, 0, 0, 0, time.UTC),
		Providers:  map[string]store.Provenance{"osv": {DataAsOf: time.Date(2026, 8, 4, 0, 0, 0, 0, time.UTC)}},
		Ratings:    map[string]store.Provenance{"NVD": {CoversSinceKnown: true}},
		Enrichment: map[string]store.Provenance{"KISA": {Source: "https://knvd.krcert.or.kr", Records: n}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

// isolateTempDir points os.MkdirTemp at a directory belonging to this test,
// so an assertion about leftover staged copies cannot be answered by another
// test's — `go test ./...` runs packages as concurrent processes, and
// cmd/assay drives `db push` too, so a glob over the shared %TEMP% would be a
// race rather than an assertion.
//
// All three variables are set because os.TempDir reads TMPDIR on Unix (which
// is what CI runs) and TMP or TEMP on Windows (which is what this is written
// on). Verified on both spellings rather than assumed.
func isolateTempDir(t *testing.T) string {
	t.Helper()
	iso := t.TempDir()
	for _, k := range []string{"TMPDIR", "TMP", "TEMP"} {
		t.Setenv(k, iso)
	}
	return iso
}

// D29: enrichment is built locally and never published. KISA's site is
// all-rights-reserved with no 공공누리 mark, which does not restrict scanning
// with the data but does restrict redistributing it — and `db push`
// redistributes.
//
// Asserted by reading the artifact BACK, not by inspecting what Push was
// handed: the guarantee is about what leaves the machine, and a strip
// applied to the wrong copy, or after packing, would satisfy any assertion
// made on the way in. The failure this holds against is silent and its
// consequence is a licensing violation rather than a wrong number, so the
// pull is done exactly the way a user's `db update` does it.
//
// The three other assertions are as load-bearing as the empty bucket:
//
//   - the advisories and the ratings must SURVIVE, or "strip the enrichment"
//     is indistinguishable from "publish an empty database";
//   - the published metadata must claim no enrichment either, or `db status`
//     on a pulled database reports a source and a count for a bucket that
//     holds nothing — the over-claim this repository has already fixed twice;
//   - the LOCAL database must keep its enrichment, because the strip runs on
//     a copy. Stripping in place would take the Korean text away from the one
//     machine allowed to have it, and would do it while a concurrent scan may
//     be reading the file.
func TestPush_NeverPublishesEnrichment(t *testing.T) {
	path := enrichedDatabase(t)

	ref := liveRegistry(t)
	var out, errOut bytes.Buffer
	if code := Push(context.Background(), path, ref, false, &out, &errOut); code != 0 {
		t.Fatalf("Push = %d, want 0 (%s)", code, errOut.String())
	}

	// Pulled the way `assay db update` pulls, into a fresh path.
	pulled := filepath.Join(t.TempDir(), "vulnerability.db")
	out.Reset()
	errOut.Reset()
	if code := Pull(context.Background(), pulled, ref, &out, &errOut); code != 0 {
		t.Fatalf("Pull = %d, want 0 (%s)", code, errOut.String())
	}
	db, err := store.Open(pulled)
	if err != nil {
		t.Fatalf("the published artifact is not a usable database: %v", err)
	}
	defer db.Close()

	if got, err := db.EnrichmentFor("CVE-2025-46394"); err != nil || len(got) != 0 {
		t.Errorf("the published artifact carries %d enrichment record(s) for CVE-2025-46394 (%v), "+
			"want none: D29 says KISA's prose is built locally and never redistributed", len(got), err)
	}
	// The whole bucket, not just the one CVE asked about: a strip that removed
	// the record under test and left the rest would pass the check above.
	published := 0
	if err := db.EachEnrichment(func(advisory.Enrichment) error { published++; return nil }); err != nil {
		t.Fatal(err)
	}
	if published != 0 {
		t.Errorf("the published enrichment bucket holds %d record(s), want none (D29)", published)
	}

	// ...while everything the artifact IS for survives.
	if got, err := db.Lookup("Alpine:v3.19", "openssl"); err != nil || len(got) != 1 {
		t.Errorf("Lookup(Alpine:v3.19, openssl) = %v, %v; the strip took the advisories with it", got, err)
	}
	if got, err := db.RatingsFor("CVE-2025-46394"); err != nil || len(got) != 1 {
		t.Errorf("RatingsFor(CVE-2025-46394) = %v, %v; the strip took the ratings with it", got, err)
	}

	// And the published metadata makes no enrichment claim, so `db status` on
	// a pulled database cannot report a source for an empty bucket.
	m, err := db.Meta()
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Enrichment) != 0 {
		t.Errorf("published Meta.Enrichment = %v, want empty: the artifact names an enrichment "+
			"source whose records it does not carry", m.Enrichment)
	}
	if len(m.EnrichmentCounts) != 0 {
		t.Errorf("published Meta.EnrichmentCounts = %v, want empty", m.EnrichmentCounts)
	}

	// The LOCAL database is untouched: the strip works on a copy, because a
	// concurrent scan may be reading this file and because the machine that
	// fetched the prose is allowed to keep it.
	local, err := store.Open(path)
	if err != nil {
		t.Fatalf("the local database did not survive the push: %v", err)
	}
	defer local.Close()
	if got, err := local.EnrichmentFor("CVE-2025-46394"); err != nil || len(got) != 1 {
		t.Errorf("EnrichmentFor on the LOCAL database = %v, %v, want the record it was built "+
			"with: `db push` stripped the live database instead of a copy", got, err)
	}
}

// The published BYTES carry none of KISA's prose either — not merely the
// published bucket.
//
// This is the sixth D29 bypass and the only one that was not a branch around
// the strip: it was the strip not doing what its name says. StripEnrichment
// deletes the bucket and bbolt FREES those pages rather than zeroing them,
// dbartifact.Pack reads the whole file, and `gunzip | strings` on the layer
// recovers the Korean text verbatim. Measured before the fix on the one-record
// fixture below: one surviving copy of the summary in a 32,768-byte layer, and
// on a 200-record one, 546 in 131,072 bytes.
//
// TestPush_NeverPublishesEnrichment above cannot see any of that. It pulls the
// artifact and asks EnrichmentFor, EachEnrichment and Meta — the level ABOVE
// where the data survives, all three of which correctly answer "nothing"
// while the record sits in the file underneath them. So this asserts on the
// decompressed layer itself, and no assertion here may go back through the
// bucket API: that is precisely what missed it.
//
// Run at two sizes deliberately. One record is the fixture every other D29
// test here uses, so this holds the same artifact those tests call clean; 200
// is the reviewer's own repro, and large enough that no amount of page reuse
// during the strip's own metadata rewrite could account for the result.
func TestPush_ThePublishedBytesCarryNoEnrichment(t *testing.T) {
	for _, records := range []int{1, 200} {
		t.Run(fmt.Sprintf("%d record(s)", records), func(t *testing.T) {
			path := enrichedDatabaseOfSize(t, records)

			ref := liveRegistry(t)
			var out, errOut bytes.Buffer
			if code := Push(context.Background(), path, ref, false, &out, &errOut); code != 0 {
				t.Fatalf("Push = %d, want 0 (%s)", code, errOut.String())
			}
			raw := publishedLayerBytes(t, ref)

			// Every field of the record, because they are stored as one JSON
			// blob and a partial survivor is still a redistribution. The
			// values are Korean and a URL, so none of them can pass or fail
			// from some other column's text the way an ID or a package name
			// could.
			for _, field := range []struct{ name, text string }{
				{"Summary", kisaSummary},
				{"Title", kisaTitle},
				{"URL", kisaURL},
			} {
				if n := bytes.Count(raw, []byte(field.text)); n != 0 {
					t.Errorf("the published layer holds %d occurrence(s) of the enrichment record's %s "+
						"(%q) across %d byte(s): the bucket was deleted rather than the live data copied "+
						"out, so the records are still legible in the freed pages that Pack gzipped. "+
						"`gunzip` and `strings` on this layer recover KISA's prose, which is the "+
						"redistribution D29 forbids", n, field.name, field.text, len(raw))
				}
			}

			// The sentinel scan is only meaningful if these bytes really are
			// the database. A layer that failed to decompress, or one holding
			// something else entirely, would satisfy every assertion above.
			if !bytes.Contains(raw, []byte("ALPINE-2025-0001")) {
				t.Fatalf("the decompressed layer (%d bytes) does not contain the advisory ID the "+
					"fixture was built with, so it is not the database and the scan above proved nothing",
					len(raw))
			}
		})
	}
}

// publishedLayerBytes returns the decompressed database layer of the artifact
// at ref: what a puller receives, before any code of ours interprets it.
func publishedLayerBytes(t *testing.T, ref string) []byte {
	t.Helper()
	target, err := name.ParseReference(ref)
	if err != nil {
		t.Fatal(err)
	}
	img, err := remote.Image(target)
	if err != nil {
		t.Fatal(err)
	}
	layers, err := img.Layers()
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range layers {
		mt, err := l.MediaType()
		if err != nil {
			t.Fatal(err)
		}
		if string(mt) != dbartifact.MediaTypeLayer {
			continue
		}
		rc, err := l.Compressed()
		if err != nil {
			t.Fatal(err)
		}
		defer rc.Close()
		zr, err := gzip.NewReader(rc)
		if err != nil {
			t.Fatal(err)
		}
		defer zr.Close()
		raw, err := io.ReadAll(zr)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	t.Fatalf("the artifact at %s has no %s layer", ref, dbartifact.MediaTypeLayer)
	return nil
}

// Either half of the D29 path failing must publish nothing at all.
//
// These are the D29 path's own error branches, and they are the most
// dangerous lines in the slice: downgrading either `return 2` to a warning
// publishes a file that still holds KISA's prose — the licensing violation,
// silently, with every other test still green. The strip's comment says "we
// tried" is not a defence; this is what makes that a guarantee rather than a
// note.
//
// BOTH seams, because the two failures publish the same violation by
// different routes. A failed strip leaves the records live; a failed
// compaction leaves them in the freed pages of the file that would then be
// packed, which is the sixth bypass arriving through an error path instead of
// the happy one. Falling back to `staged` on a compaction error is the
// natural-looking recovery, and with only the strip case here it would have
// survived the whole suite.
//
// The failures are forced through the seams because neither can be forced
// with a fixture: both paths were created by Push moments earlier, so making
// bbolt refuse one would mean racing the copy.
//
// The assertion that matters is the last one — that the registry holds
// nothing. Exit 2 alone would pass on a Push that reports the problem and
// publishes anyway, which is exactly the shape being guarded against.
//
// Run with --force as well as without it, because --force is an override for
// the COVERAGE guard and must never become one for the licensing guard.
// `err != nil && !force` is a one-token change that reads like consistency
// with the guard beside it, and with only an unforced case here it survived
// the whole suite. The two guards refuse different things: one protects
// everyone's database from getting narrower, and a publisher who means it can
// say so; the other protects data that may not be redistributed at all, and
// there is nobody who may say so.
func TestPush_AFailedStripPublishesNothing(t *testing.T) {
	// Each case breaks ONE seam and leaves the other real, so a case cannot
	// pass because the step it is not testing happened to fail too.
	steps := []struct {
		name    string
		install func(t *testing.T)
		// wantErr is the message AND its cause: Contains(stderr, "strip")
		// alone would pass on a message that dropped the reason, which is
		// the one thing an operator needs to act on.
		wantErr string
	}{
		{
			name: "the strip fails",
			install: func(t *testing.T) {
				orig := stripEnrichment
				stripEnrichment = func(string) error { return errBoom }
				t.Cleanup(func() { stripEnrichment = orig })
			},
			wantErr: "strip enrichment before publishing: boom",
		},
		{
			name: "the compaction fails",
			install: func(t *testing.T) {
				orig := compactInto
				compactInto = func(dst, src string) error { return errBoom }
				t.Cleanup(func() { compactInto = orig })
			},
			wantErr: "compact database for publishing: boom",
		},
	}
	for _, step := range steps {
		for _, force := range []bool{false, true} {
			name_ := step.name + " without --force"
			if force {
				name_ = step.name + " with --force"
			}
			t.Run(name_, func(t *testing.T) {
				iso := isolateTempDir(t)
				step.install(t)

				ref := liveRegistry(t)
				var out, errOut bytes.Buffer
				if code := Push(context.Background(), enrichedDatabase(t), ref, force, &out, &errOut); code != 2 {
					t.Errorf("Push where %s = %d, want 2", step.name, code)
				}
				if !strings.Contains(errOut.String(), step.wantErr) {
					t.Errorf("stderr does not say that %s, and why:\n%s", step.name, errOut.String())
				}
				if out.Len() != 0 {
					t.Errorf("a failed push wrote a digest to stdout, which reads as success: %q", out.String())
				}

				target, err := name.ParseReference(ref)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := remote.Image(target); err == nil {
					t.Errorf("a push where %s published an artifact anyway - that artifact carries "+
						"KISA's prose, which is the licensing violation D29 exists to prevent", step.name)
				}

				// The early return still cleans up after itself.
				if left, _ := filepath.Glob(filepath.Join(iso, "assay-push-*")); len(left) != 0 {
					t.Errorf("a push where %s left its staged copy behind: %v", step.name, left)
				}
			})
		}
	}
}

// The strip keys off NOTHING. It runs on every push, whatever the metadata
// says the database holds.
//
// The fixture is a database whose enrichment BUCKET is populated while its
// Meta.Enrichment is empty, and every other D29 test here sets both — so
// wrapping the strip in `if len(meta.Enrichment) > 0` reads as a harmless
// "nothing to do" optimisation and survives the rest of the suite.
//
// That is this branch's oldest defect arriving on the licensing path: trusting
// a self-report over the stored data, already fixed once for RatingCounts and
// once for EnrichmentCounts. The state is reachable, not hypothetical —
// dropping the provenance write in Update while records still land produces
// exactly it, and so would any future writer that fills the bucket without
// recording a source.
//
// The consequence differs from the earlier two, which were wrong numbers in a
// status table. Here the metadata says "no enrichment", the artifact carries
// it anyway, and nothing in the published database contradicts the claim.
func TestPush_StripsTheBucketEvenWhenTheMetadataClaimsNothingToStrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vulnerability.db")
	w, err := store.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.PutEnrichment(advisory.Enrichment{
		CVE: "CVE-2025-46394", Source: "KISA",
		Title: "OpenSSL 보안 업데이트 권고",
		URL:   "https://knvd.krcert.or.kr/info/vuln/notice/detail?id=99",
	}); err != nil {
		t.Fatal(err)
	}
	// No Enrichment entry: the bucket holds a record that the provenance does
	// not account for.
	if err := w.SetMeta(store.Meta{
		BuiltAt:   time.Date(2026, 8, 5, 6, 0, 0, 0, time.UTC),
		Providers: map[string]store.Provenance{"osv": {DataAsOf: time.Date(2026, 8, 4, 0, 0, 0, 0, time.UTC)}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	// The fixture is only meaningful if it really is in that state, so it is
	// checked rather than assumed: SetMeta derives EnrichmentCounts from the
	// bucket, so a future change there could quietly make this an ordinary
	// database and the test would pass for the wrong reason.
	local, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	m, err := local.Meta()
	local.Close()
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Enrichment) != 0 {
		t.Fatalf("fixture is not in the intended state: Meta.Enrichment = %v, want empty", m.Enrichment)
	}

	ref := liveRegistry(t)
	var out, errOut bytes.Buffer
	if code := Push(context.Background(), path, ref, false, &out, &errOut); code != 0 {
		t.Fatalf("Push = %d, want 0 (%s)", code, errOut.String())
	}
	pulled := filepath.Join(t.TempDir(), "vulnerability.db")
	out.Reset()
	errOut.Reset()
	if code := Pull(context.Background(), pulled, ref, &out, &errOut); code != 0 {
		t.Fatalf("Pull = %d, want 0 (%s)", code, errOut.String())
	}
	db, err := store.Open(pulled)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	published := 0
	if err := db.EachEnrichment(func(advisory.Enrichment) error { published++; return nil }); err != nil {
		t.Fatal(err)
	}
	if published != 0 {
		t.Errorf("the published artifact carries %d enrichment record(s) that the local "+
			"metadata never mentioned - the strip consulted the self-report instead of the "+
			"bucket, and D29's guarantee is only as good as that metadata", published)
	}
}

// Push removes the staged copy it packs from.
//
// Not cosmetic: the copy is the whole database, so a leak is ~244 MB of
// %TEMP% per push on the builder that publishes every night, and nothing
// would ever report it. dbartifact.Pack reads the file eagerly, so no handle
// is open by the time the deferred cleanup runs and this is simply a matter
// of the defer existing.
func TestPush_RemovesItsStagedCopy(t *testing.T) {
	iso := isolateTempDir(t)
	ref := liveRegistry(t)

	var out, errOut bytes.Buffer
	if code := Push(context.Background(), enrichedDatabase(t), ref, false, &out, &errOut); code != 0 {
		t.Fatalf("Push = %d, want 0 (%s)", code, errOut.String())
	}
	left, err := filepath.Glob(filepath.Join(iso, "assay-push-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 0 {
		t.Errorf("Push left its staged copy of the database behind: %v", left)
	}
}

// A published artifact holding NO ratings does not block a push that has some.
//
// This is the bug that broke the nightly publish for a day, and it is the same
// shape RatingsSinceKnown was added for one field over: a zero RatingsSince
// means "no lower bound", which reads as whole-feed coverage — and a build that
// never ran the NVD provider records exactly that while covering nothing at
// all. The v8 artifact was bootstrapped by hand from such a build, and every
// nightly run afterwards was refused for narrowing a window the seed never had.
//
// The fixture is the real situation: published with zero ratings and no bound,
// incoming with real ratings and the bounded window a daily NVD window has.
func TestPush_ZeroRatingArtifactCannotBlockAPushThatHasSome(t *testing.T) {
	ref := liveRegistry(t)
	seed(t, ref, time.Time{}, 0) // published: no ratings, so no coverage to narrow

	var out, errOut bytes.Buffer
	real := bounded(t, time.Date(2026, 7, 5, 0, 0, 0, 0, time.UTC), 5)
	if code := Push(context.Background(), real, ref, false, &out, &errOut); code != 0 {
		t.Fatalf("Push = %d, want 0 — a published artifact with no ratings has no "+
			"window to narrow: %s", code, errOut.String())
	}
	// Published, not merely permitted: a guard that returned 0 and then failed
	// to write would pass an exit-code-only assertion.
	if got := publishedMeta(t, ref); got.RatingCount != 5 {
		t.Errorf("published RatingCount = %d, want 5", got.RatingCount)
	}
}

// registryHost returns a live in-process registry's host, so a test can name
// several tags in the same repository rather than the single one liveRegistry
// hands back.
func registryHost(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(registry.New())
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return u.Host
}

// TestPush_BootstrapComparesAgainstThePreviousSchema is the hole D60 closes,
// and it is a hole this project fell into rather than one anticipated.
//
// A schema bump moves the tag, so the first push to :vN faces no baseline at
// its own tag — and every regression check is skipped at exactly the moment a
// hand-built bootstrap is most likely to be missing something. The v8 bootstrap
// published 0 ratings where :v7 held 355,030, and nothing objected, because
// :v8 did not exist yet.
//
// This drives Push, not the comparison helper: the helper being right proves
// nothing if the bootstrap path never reaches it.
func TestPush_BootstrapComparesAgainstThePreviousSchema(t *testing.T) {
	host := registryHost(t)
	prev := fmt.Sprintf("%s/assay-db:v%d", host, store.SchemaVersion-1)
	cur := fmt.Sprintf("%s/assay-db:v%d", host, store.SchemaVersion)

	// The previous schema holds a real corpus.
	seed(t, prev, time.Time{}, 5000)

	// The bootstrap has none, which is exactly what a build without
	// NVD_ENABLE produces.
	var out, errOut bytes.Buffer
	code := Push(context.Background(), bounded(t, time.Time{}, 0), cur, false, &out, &errOut)
	if code != 2 {
		t.Fatalf("Push = %d, want 2 — a bootstrap dropping 5000 ratings to 0 must be "+
			"refused\nstderr: %s", code, errOut.String())
	}
	s := errOut.String()
	if !strings.Contains(s, "previous schema") {
		t.Errorf("stderr does not say it compared against the previous schema:\n%s", s)
	}
	// And it names WHICH artifact it fell below, or the operator cannot tell a
	// same-tag regression from a bootstrap one.
	if !strings.Contains(s, prev) {
		t.Errorf("stderr does not name %q:\n%s", prev, s)
	}
	// Nothing was published: asserting the exit code alone would pass on a
	// guard that reports the problem and writes anyway.
	if _, err := remote.Image(mustRef(t, cur)); err == nil {
		t.Error("the refused bootstrap published anyway")
	}
}

// TestPush_BootstrapProceedsWhenItCarriesTheCorpus. The guard must not block a
// legitimate schema bump: a bootstrap built the right way carries at least what
// the previous schema had, and refusing that would make every future bump need
// --force, which trains the operator to pass it always.
func TestPush_BootstrapProceedsWhenItCarriesTheCorpus(t *testing.T) {
	host := registryHost(t)
	prev := fmt.Sprintf("%s/assay-db:v%d", host, store.SchemaVersion-1)
	cur := fmt.Sprintf("%s/assay-db:v%d", host, store.SchemaVersion)
	seed(t, prev, time.Time{}, 5000)

	var out, errOut bytes.Buffer
	if code := Push(context.Background(), bounded(t, time.Time{}, 5000), cur,
		false, &out, &errOut); code != 0 {
		t.Fatalf("Push = %d, want 0 — the bootstrap carries the corpus\nstderr: %s",
			code, errOut.String())
	}
	if got := publishedMeta(t, cur).RatingCount; got != 5000 {
		t.Errorf("published RatingCount = %d, want 5000", got)
	}
}

// TestPush_NoPreviousSchemaEitherStillPublishes. A repository with nothing at
// all published must still accept a first push, or the very first release of
// this tool could never ship one.
func TestPush_NoPreviousSchemaEitherStillPublishes(t *testing.T) {
	host := registryHost(t)
	cur := fmt.Sprintf("%s/assay-db:v%d", host, store.SchemaVersion)

	var out, errOut bytes.Buffer
	if code := Push(context.Background(), bounded(t, time.Time{}, 3), cur,
		false, &out, &errOut); code != 0 {
		t.Fatalf("Push = %d, want 0 on an empty repository\nstderr: %s", code, errOut.String())
	}
	if got := publishedMeta(t, cur).RatingCount; got != 3 {
		t.Errorf("published RatingCount = %d, want 3", got)
	}
}

func mustRef(t *testing.T, s string) name.Reference {
	t.Helper()
	r, err := name.ParseReference(s)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// TestPush_SubSecondPrecisionIsNotANarrowing reproduces the failure that
// blocked the 2026-08-13 re-run: the build finished, and `db push` refused with
//
//	the published artifact covers from 2026-08-09 and this one only from 2026-08-09
//
// — a message that contradicts itself, because the two values differ by less
// than a second.
//
// The annotation is written with time.RFC3339, which carries no fractional
// seconds, while the local metadata keeps the nanoseconds time.Now() produced.
// So a republish compares a truncated published value against an untruncated
// incoming one, and the incoming is later by a fraction of a second every
// single time. It is not a narrowing; the coverage is identical.
//
// This blocks EVERY incremental publish once the published artifact carries a
// rating bound at all, which is why it only surfaced now: the artifact it was
// comparing against had none until yesterday's push wrote one.
func TestPush_SubSecondPrecisionIsNotANarrowing(t *testing.T) {
	host := registryHost(t)
	ref := fmt.Sprintf("%s/assay-db:v%d", host, store.SchemaVersion)

	// A bound with nanoseconds, the way time.Now().AddDate() produces one.
	since := time.Date(2026, 8, 9, 7, 23, 41, 123456789, time.UTC)

	// Published: the same instant, as the annotation records it — RFC3339, so
	// the nanoseconds are gone.
	seed(t, ref, since.Truncate(time.Second), 3081)

	// Incoming: the same coverage, carried forward by mergeRatingCoverage, and
	// more ratings than the published artifact holds.
	var out, errOut bytes.Buffer
	code := Push(context.Background(), bounded(t, since, 7249), ref, false, &out, &errOut)
	if code != 0 {
		t.Fatalf("Push = %d, want 0 — identical coverage must not read as a narrowing\nstderr: %s",
			code, errOut.String())
	}
}
