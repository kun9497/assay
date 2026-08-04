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
	if code := Push(context.Background(), path, ref, &out, &errOut); code != 0 {
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
	if code := Push(context.Background(), path, ref, &out, &errOut); code != 0 {
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
	if code := Push(context.Background(), path, ref, &out, &errOut); code != 0 {
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
}

// Pushing a database that is not there is a 2 that says so, not a panic
// and not a silent empty artifact.
func TestPush_MissingDatabaseExitsTwo(t *testing.T) {
	srv := httptest.NewServer(registry.New())
	defer srv.Close()
	u, err := url.Parse(srv.URL)
	ref := must(t, u, err).Host + "/assay-db:v6"

	var out, errOut bytes.Buffer
	code := Push(context.Background(), filepath.Join(t.TempDir(), "absent.db"), ref, &out, &errOut)
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
	code := Push(context.Background(), path, "NOT A REF", &out, &errOut)
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
	code := Push(context.Background(), path, "127.0.0.1:1/assay-db:v6", &out, &errOut)
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
