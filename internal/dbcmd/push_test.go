package dbcmd

import (
	"bytes"
	"context"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/kun9497/assay/internal/dbartifact"
	"github.com/kun9497/assay/internal/store"
)

// testBuiltAt is the fixed BuiltAt every fixture in this file writes, so a
// test can assert Push read it back from the LOCAL store rather than
// stamping the clock (fix round 1, finding 1) without repeating the literal
// at every call site.
var testBuiltAt = time.Date(2026, 8, 4, 6, 0, 0, 0, time.UTC)

// pushable builds a real database on disk and returns its path.
func pushable(t *testing.T, dataAsOf time.Time) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vulnerability.db")
	w, err := store.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.SetMeta(store.Meta{
		BuiltAt: testBuiltAt,
		Providers: map[string]store.Provenance{
			"osv": {Source: "https://example.test", DataAsOf: dataAsOf},
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

// The whole point of the slice: a built database becomes something a
// registry serves. Tested against go-containerregistry's own in-memory
// registry, so this needs no network and no credentials.
func TestPush_WritesAPullableArtifact(t *testing.T) {
	srv := httptest.NewServer(registry.New())
	defer srv.Close()
	// must's generic signature can't take Go's "spread a multi-value call
	// into the last N parameters" shorthand alongside a leading t, so the
	// multi-value call is captured first and passed through as two values.
	u, err := url.Parse(srv.URL)
	host := must(t, u, err).Host
	ref := host + "/assay-db:v6"

	asOf := time.Date(2026, 8, 3, 0, 0, 0, 0, time.UTC)
	path := pushable(t, asOf)

	var out, errOut bytes.Buffer
	if code := Push(context.Background(), path, ref, false, &out, &errOut); code != 0 {
		t.Fatalf("Push = %d, want 0 (stderr: %s)", code, errOut.String())
	}

	parsedRef, refErr := name.ParseReference(ref)
	target := must(t, parsedRef, refErr)
	img, err := remote.Image(target)
	if err != nil {
		t.Fatalf("pushed artifact is not pullable: %v", err)
	}
	m, err := dbartifact.MetaOf(img)
	if err != nil {
		t.Fatal(err)
	}
	if m.SchemaVersion != store.SchemaVersion {
		t.Errorf("published schema = %d, want %d", m.SchemaVersion, store.SchemaVersion)
	}
	// D12: the artifact carries the UPSTREAM freshness, not the moment it
	// was pushed. Asserting this is what stops a mirror that re-pushes an
	// old database from presenting it as current.
	if !m.DataAsOf.Equal(asOf) {
		t.Errorf("published DataAsOf = %v, want the database's own %v", m.DataAsOf, asOf)
	}
	// fix round 1, finding 1: BuiltAt must come from the LOCAL database's own
	// recorded metadata, not the moment Push happened to run. Unheld before
	// this assertion existed -- `BuiltAt: time.Now().UTC()` in push.go passed
	// the whole suite.
	if !m.BuiltAt.Equal(testBuiltAt) {
		t.Errorf("published BuiltAt = %v, want the database's own %v", m.BuiltAt, testBuiltAt)
	}

	// fix round 1, finding 2: the pushed digest is the RESULT of `db push`, so
	// it belongs on stdout, not stderr -- a caller pins it with
	// `assay db push ... | ...` or captures it via `$(...)`. Asserted as the
	// rendered pair (name@digest), not a bare "sha256:" substring, which
	// stderr's own error-path text could also contain.
	wantDigest, err := img.Digest()
	if err != nil {
		t.Fatal(err)
	}
	wantLine := target.Context().Name() + "@" + wantDigest.String()
	if !strings.Contains(out.String(), wantLine) {
		t.Errorf("stdout = %q, want it to contain the pushed digest %q", out.String(), wantLine)
	}
	if strings.Contains(errOut.String(), wantLine) {
		t.Errorf("the pushed digest leaked onto stderr, a diagnostics stream, not the result: %q", errOut.String())
	}
}

// TestPushPull_RoundTripsEOLData is the D87 artifact guarantee: dbartifact
// is byte-level (Pack/Unpack move the whole database file, never parsing
// its buckets), so Meta.EOL should ride through a real push-then-pull for
// free -- this proves it rather than assuming it, the same way
// TestPush_WritesAPullableArtifact proves the schema/DataAsOf annotations
// round-trip rather than trusting Pack/Unpack's own doc comment alone.
func TestPushPull_RoundTripsEOLData(t *testing.T) {
	srv := httptest.NewServer(registry.New())
	defer srv.Close()
	u, err := url.Parse(srv.URL)
	host := must(t, u, err).Host
	ref := host + "/assay-db:v" + itoa(store.SchemaVersion)

	path := filepath.Join(t.TempDir(), "vulnerability.db")
	w, err := store.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	want := []store.EOLRelease{
		{DistroID: "debian", Release: "12", EOLFrom: "2026-07-11", EOLLabel: "Debian Security Support",
			EOESFrom: "2028-06-30", EOESLabel: "Debian LTS", IsMaintained: true},
		{DistroID: "alpine", Release: "3.19", EOLFrom: "2028-06-01", EOLLabel: "Security Support"},
	}
	prov := store.Provenance{Source: "https://endoflife.date/api/v1/products/full", Records: len(want)}
	if err := w.SetMeta(store.Meta{
		BuiltAt:       testBuiltAt,
		Providers:     map[string]store.Provenance{"osv": {Source: "https://example.test"}},
		EOL:           want,
		EOLProvenance: &prov,
	}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	var out, errOut bytes.Buffer
	if code := Push(context.Background(), path, ref, false, &out, &errOut); code != 0 {
		t.Fatalf("Push = %d, want 0 (stderr: %s)", code, errOut.String())
	}

	dst := filepath.Join(t.TempDir(), "pulled.db")
	out.Reset()
	errOut.Reset()
	if code := Pull(context.Background(), dst, ref, &out, &errOut); code != 0 {
		t.Fatalf("Pull = %d, want 0 (stderr: %s)", code, errOut.String())
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
	if len(m.EOL) != len(want) {
		t.Fatalf("pulled Meta.EOL = %d row(s), want %d: %+v", len(m.EOL), len(want), m.EOL)
	}
	for i, row := range want {
		if m.EOL[i] != row {
			t.Errorf("pulled Meta.EOL[%d] = %+v, want %+v", i, m.EOL[i], row)
		}
	}
	if m.EOLProvenance == nil {
		t.Fatal("pulled Meta.EOLProvenance = nil, want the pushed provenance")
	}
	if m.EOLProvenance.Source != prov.Source || m.EOLProvenance.Records != prov.Records {
		t.Errorf("pulled Meta.EOLProvenance = %+v, want %+v", *m.EOLProvenance, prov)
	}
}

// An artifact is only as fresh as its stalest provider. Reporting the
// newest would let one recently-synced source vouch for a stale one.
func TestPush_DataAsOfIsTheOldestProvider(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vulnerability.db")
	w, err := store.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	old := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	if err := w.SetMeta(store.Meta{
		BuiltAt: testBuiltAt,
		Providers: map[string]store.Provenance{
			"fresh": {DataAsOf: time.Date(2026, 8, 3, 0, 0, 0, 0, time.UTC)},
			"stale": {DataAsOf: old},
		},
	}); err != nil {
		t.Fatal(err)
	}
	w.Close()

	srv := httptest.NewServer(registry.New())
	defer srv.Close()
	u, err := url.Parse(srv.URL)
	ref := must(t, u, err).Host + "/assay-db:v6"

	var out, errOut bytes.Buffer
	if code := Push(context.Background(), path, ref, false, &out, &errOut); code != 0 {
		t.Fatalf("Push = %d, want 0 (stderr: %s)", code, errOut.String())
	}
	parsedRef, refErr := name.ParseReference(ref)
	img, err := remote.Image(must(t, parsedRef, refErr))
	if err != nil {
		t.Fatal(err)
	}
	m, _ := dbartifact.MetaOf(img)
	if !m.DataAsOf.Equal(old) {
		t.Errorf("DataAsOf = %v, want the OLDEST provider's %v", m.DataAsOf, old)
	}
}

// Finding 1 of the final review: oldestDataAsOf only walked m.Providers, so
// a build seeded from an old published database (--seed carries Ratings
// forward via maps.Copy without touching Providers, D-seed) and re-run
// without NVD_ENABLE published the fresh Providers timestamp while the
// carried-forward NVD ratings were months stale. This asserts the opposite:
// Ratings provenance older than every Providers entry must win, the same
// "oldest wins" rule already applied within Providers alone.
func TestPush_DataAsOfIsTheOldestAcrossProvidersAndRatings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vulnerability.db")
	w, err := store.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	staleRatings := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	if err := w.SetMeta(store.Meta{
		BuiltAt: testBuiltAt,
		Providers: map[string]store.Provenance{
			"osv": {DataAsOf: time.Date(2026, 8, 3, 0, 0, 0, 0, time.UTC)},
		},
		Ratings: map[string]store.Provenance{
			"nvd": {DataAsOf: staleRatings},
		},
	}); err != nil {
		t.Fatal(err)
	}
	w.Close()

	srv := httptest.NewServer(registry.New())
	defer srv.Close()
	u, err := url.Parse(srv.URL)
	ref := must(t, u, err).Host + "/assay-db:v6"

	var out, errOut bytes.Buffer
	if code := Push(context.Background(), path, ref, false, &out, &errOut); code != 0 {
		t.Fatalf("Push = %d, want 0 (stderr: %s)", code, errOut.String())
	}
	parsedRef, refErr := name.ParseReference(ref)
	img, err := remote.Image(must(t, parsedRef, refErr))
	if err != nil {
		t.Fatal(err)
	}
	m, _ := dbartifact.MetaOf(img)
	if !m.DataAsOf.Equal(staleRatings) {
		t.Errorf("DataAsOf = %v, want the stale RATINGS provenance %v, not the fresher Providers one",
			m.DataAsOf, staleRatings)
	}
	// QA round 5: the floor's SOURCE must be attributed too, and correctly
	// when a Ratings entry (not a Provider) set it. Blanking the name on the
	// Ratings loop left this green because no test read DataAsOfSource on a
	// ratings-driven floor.
	if m.DataAsOfSource != "nvd" {
		t.Errorf("DataAsOfSource = %q, want nvd -- the ratings entry that set the floor", m.DataAsOfSource)
	}
}

// TestPush_DataAsOfSourceIsDeterministicOnATie holds sortedKeys' own stated
// purpose (QA round 5): when two providers carry the IDENTICAL oldest
// DataAsOf, the attributed source must be the lexicographically first name
// every build, so byte-identical inputs never publish differing manifests.
// Reverting to direct map iteration passed every other test because no
// fixture had a tie; this one does, and asserts the stable winner.
func TestPush_DataAsOfSourceIsDeterministicOnATie(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vulnerability.db")
	w, err := store.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	tie := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	if err := w.SetMeta(store.Meta{
		BuiltAt: testBuiltAt,
		Providers: map[string]store.Provenance{
			"zebra":  {DataAsOf: tie},
			"amazon": {DataAsOf: tie},
			"osv":    {DataAsOf: time.Date(2026, 8, 3, 0, 0, 0, 0, time.UTC)},
		},
	}); err != nil {
		t.Fatal(err)
	}
	w.Close()

	srv := httptest.NewServer(registry.New())
	defer srv.Close()
	u, err := url.Parse(srv.URL)
	ref := must(t, u, err).Host + "/assay-db:v6"
	var out, errOut bytes.Buffer
	if code := Push(context.Background(), path, ref, false, &out, &errOut); code != 0 {
		t.Fatalf("Push = %d, want 0 (stderr: %s)", code, errOut.String())
	}
	parsedRef, refErr := name.ParseReference(ref)
	img, err := remote.Image(must(t, parsedRef, refErr))
	if err != nil {
		t.Fatal(err)
	}
	m, _ := dbartifact.MetaOf(img)
	if m.DataAsOfSource != "amazon" {
		t.Errorf("DataAsOfSource = %q, want amazon (lexicographically first of the tied sources) -- "+
			"a tie must resolve deterministically, not by map-iteration order", m.DataAsOfSource)
	}
}

// Pushing a database that is not there is a 2 that says so, not a panic
// and not a silent empty artifact.
func TestPush_MissingDatabaseExitsTwo(t *testing.T) {
	srv := httptest.NewServer(registry.New())
	defer srv.Close()
	u, err := url.Parse(srv.URL)
	ref := must(t, u, err).Host + "/assay-db:v6"

	var out, errOut bytes.Buffer
	code := Push(context.Background(), filepath.Join(t.TempDir(), "absent.db"), ref, false, &out, &errOut)
	if code != 2 {
		t.Errorf("Push with no database = %d, want 2", code)
	}
	if !strings.Contains(errOut.String(), "absent.db") {
		t.Errorf("stderr does not name the missing file:\n%s", errOut.String())
	}
}

// fix round 1, finding 3: a malformed reference must fail before Push does
// anything with a registry, and stderr must name the bad reference -- a
// builder scripting several `db push` calls needs to know WHICH one it was.
// Nothing previously supplied an unparseable ref, so a Push that silently
// swallowed name.ParseReference's error and fell through to a false success
// would not have been caught.
func TestPush_UnparseableReferenceExitsTwo(t *testing.T) {
	path := pushable(t, time.Date(2026, 8, 3, 0, 0, 0, 0, time.UTC))

	var out, errOut bytes.Buffer
	code := Push(context.Background(), path, "NOT A REF", false, &out, &errOut)
	if code != 2 {
		t.Errorf("Push with an unparseable ref = %d, want 2", code)
	}
	if !strings.Contains(errOut.String(), "NOT A REF") {
		t.Errorf("stderr does not name the bad reference:\n%s", errOut.String())
	}
	if out.Len() != 0 {
		t.Errorf("error path polluted stdout: %q", out.String())
	}
}

// fix round 1, finding 3: a registry that refuses the connection must not be
// swallowed into a false success -- exit 2, and stderr must say the PUSH
// itself failed, distinct from the "not a valid reference" wording the
// sibling test checks, so an operator debugging a failed publish can tell
// the two apart. 127.0.0.1:1 is a loopback address nothing listens on, so
// this needs no real network access and fails fast.
func TestPush_UnreachableRegistryExitsTwo(t *testing.T) {
	path := pushable(t, time.Date(2026, 8, 3, 0, 0, 0, 0, time.UTC))

	var out, errOut bytes.Buffer
	code := Push(context.Background(), path, "127.0.0.1:1/assay-db:v6", false, &out, &errOut)
	if code != 2 {
		t.Errorf("Push against an unreachable registry = %d, want 2", code)
	}
	if !strings.Contains(errOut.String(), "error: push:") {
		t.Errorf("stderr does not say the push itself failed:\n%s", errOut.String())
	}
	if out.Len() != 0 {
		t.Errorf("error path polluted stdout: %q", out.String())
	}
}

func must[T any](t *testing.T, v T, err error) T {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	return v
}
