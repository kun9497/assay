package dbcmd

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/kun9497/assay/internal/dbartifact"
	"github.com/kun9497/assay/internal/store"
)

// publishedFrom packs srcPath under the given schema annotation and pushes
// it to a fresh in-memory registry, returning its reference. Pack does not
// validate srcPath's contents -- it reads and compresses whatever bytes are
// there -- so this is also how a test manufactures an artifact with a
// correct manifest annotation but a layer that is not a readable database
// (TestPull_AFailedPullLeavesTheLiveDatabaseAlone).
//
// wrap, if non-nil, lets a test observe the registry's traffic (e.g.
// counting blob fetches, TestPull_RefusesAForeignSchemaWithoutDownloading)
// without duplicating this setup.
func publishedFrom(t *testing.T, srcPath string, schema int, wrap func(http.Handler) http.Handler) string {
	t.Helper()
	var h http.Handler = registry.New()
	if wrap != nil {
		h = wrap(h)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	host := must(t, u, err).Host
	ref := host + "/assay-db:v" + itoa(schema)

	img, err := dbartifact.Pack(srcPath, dbartifact.Meta{
		SchemaVersion: schema,
		BuiltAt:       time.Date(2026, 8, 4, 6, 0, 0, 0, time.UTC),
		DataAsOf:      time.Date(2026, 8, 3, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	parsedRef, refErr := name.ParseReference(ref)
	if err := remote.Write(must(t, parsedRef, refErr), img); err != nil {
		t.Fatal(err)
	}
	return ref
}

// published pushes a real, valid database (pushable's own fixture) to an
// in-memory registry and returns its reference, so pull tests exercise the
// actual artifact Push writes rather than a hand-built approximation that
// could drift from it. The common case every test but the garbage-layer one
// below wants; publishedFrom is the general form.
func published(t *testing.T, schema int) string {
	t.Helper()
	return publishedFrom(t, pushable(t, time.Date(2026, 8, 3, 0, 0, 0, 0, time.UTC)), schema, nil)
}

func itoa(n int) string { return fmt.Sprintf("%d", n) }

// The slice's payoff: a database arrives without a seven-hour build, and it
// is a database -- Open accepts it and Status can read it.
func TestPull_LandsAUsableDatabase(t *testing.T) {
	ref := published(t, store.SchemaVersion)
	dst := filepath.Join(t.TempDir(), "vulnerability.db")

	var out, errOut bytes.Buffer
	if code := Pull(context.Background(), dst, ref, &out, &errOut); code != 0 {
		t.Fatalf("Pull = %d, want 0 (stderr: %s)", code, errOut.String())
	}
	db, err := store.Open(dst)
	if err != nil {
		t.Fatalf("pulled file is not a usable database: %v", err)
	}
	defer db.Close()
	if _, err := db.Meta(); err != nil {
		t.Errorf("pulled database has no readable metadata: %v", err)
	}
}

// A schema mismatch is refused BEFORE the layer is downloaded, and the
// error says what to do. Serving a v5 database to a v6 binary silently
// would be a scan reading records it cannot interpret.
//
// Blob GETs are counted directly against the registry handler, not just
// inferred from the error text and the absence of dst. Fix round 1 found
// that moving the schema check to run AFTER store.Open(tmp) still passes
// every assertion that isn't the GET count: SetMeta always stamps the
// database's Meta.Schema with the CURRENT store.SchemaVersion regardless of
// what the artifact's own annotation claims (pushable -> store.Create ->
// SetMeta), so the packed database really does unpack and open cleanly even
// though it is annotated as a foreign schema -- and dst stays absent either
// way, because the leftover on that later-checking path is dst+".tmp", not
// dst. Only counting the actual blob fetch catches a schema check that
// runs too late.
//
// Both directions are covered (fix round 2, finding 2): `!=` weakened to
// `>` only refuses an artifact annotated NEWER than this binary, silently
// admitting one annotated OLDER, which only the "newer" case here exercises.
//
// What this guard adds over store.Open(tmp)'s own schema check
// (store/bolt.go: `if m.Schema != SchemaVersion`), stated plainly rather
// than asserted as if it were self-evidently non-redundant: for BOTH
// directions tested here, it adds the ENTIRE guarantee, not merely an
// efficiency win. pushable() can only ever build a database at the
// CURRENTLY RUNNING binary's store.SchemaVersion -- there is no way, within
// one test binary, to construct a database that is genuinely a different
// schema on disk. So in every case below, the artifact's REAL content is
// always secretly compatible; only its ANNOTATION lies. store.Open(tmp)
// checks the real, stamped Meta.Schema -- which is correct here regardless
// of the annotation -- so it would pass every one of these artifacts through
// with no complaint at all. A mistagged-but-actually-fine artifact is
// exactly the case the doc comment on Pull's schema check calls out ("a
// mis-tagged artifact is the case the tag cannot catch"), and it is a case
// store.Open(tmp) cannot catch either, by construction of what it checks.
// store.Open(tmp)'s own backstop is for a database that is GENUINELY a
// different schema on disk -- a real cross-version artifact, which is not
// something this suite can build, so it has no direct test here; the
// closest this suite comes is TestPull_AFailedPullLeavesTheLiveDatabaseAlone,
// which proves store.Open(tmp) rejects content that fails to open as a
// database at all (a hard read failure, not a version comparison).
func TestPull_RefusesAForeignSchemaWithoutDownloading(t *testing.T) {
	for _, tc := range []struct {
		name       string
		schema     int
		wantStderr string
	}{
		// != -> > survives this one alone (m.SchemaVersion > store.SchemaVersion
		// is still true), which is why the "older" case below exists.
		{"newer than this binary", store.SchemaVersion + 1, "upgrade assay"},
		// != -> > does NOT catch this: SchemaVersion-1 > SchemaVersion is
		// false, so the mutated check silently admits it, and Pull proceeds
		// to download, unpack, and (since the real content is secretly
		// compatible, see above) successfully install it.
		{"older than this binary", store.SchemaVersion - 1, "upgrade the publisher"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var blobGETs int32
			ref := publishedFrom(t, pushable(t, time.Date(2026, 8, 3, 0, 0, 0, 0, time.UTC)),
				tc.schema,
				func(h http.Handler) http.Handler {
					return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/blobs/") {
							atomic.AddInt32(&blobGETs, 1)
						}
						h.ServeHTTP(w, r)
					})
				})
			// The push above (remote.Write, inside publishedFrom) only ever
			// HEADs, POSTs, PATCHes and PUTs blobs while uploading -- never
			// GETs one -- so the counter is still genuinely zero here, not
			// merely reset to look that way.
			dst := filepath.Join(t.TempDir(), "vulnerability.db")

			var out, errOut bytes.Buffer
			code := Pull(context.Background(), dst, ref, &out, &errOut)
			if code != 2 {
				t.Errorf("Pull of a foreign schema = %d, want 2 (stderr: %s)", code, errOut.String())
			}
			if !strings.Contains(errOut.String(), tc.wantStderr) {
				t.Errorf("stderr does not tell the user what to do:\n%s", errOut.String())
			}
			if _, err := os.Stat(dst); !os.IsNotExist(err) {
				t.Error("a refused pull left a file behind")
			}
			if got := atomic.LoadInt32(&blobGETs); got != 0 {
				t.Errorf("Pull fetched %d layer blob(s) before refusing the schema mismatch, want 0", got)
			}
		})
	}
}

// A pull whose artifact is well-formed at the manifest level -- a correct
// schema annotation -- but whose layer does not decompress to a readable
// database must not destroy whatever database was already on disk. This is
// the property the temp-file dance exists for.
//
// Fix round 1 found the previous form of this test (an unreachable
// registry, now TestPull_UnreachableRegistryExitsTwo below) could not fail
// on the property its name claimed: remote.Image failed three steps before
// Unpack was ever reached, so deleting the temp file entirely, unpacking
// straight over dbPath instead of tmp, or deleting the store.Open(tmp)
// validation all left it green. This version packs genuine garbage as the
// layer (Pack does not validate what it is given) under a CORRECT schema
// annotation, so the schema check passes and Unpack succeeds -- only
// store.Open(tmp) can catch it, which is the guard this test now actually
// exercises.
func TestPull_AFailedPullLeavesTheLiveDatabaseAlone(t *testing.T) {
	dst := pushable(t, time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC))
	before, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}

	garbage := filepath.Join(t.TempDir(), "not-a-database")
	if err := os.WriteFile(garbage, []byte("gzips and unpacks fine; is not a bolt file"), 0o600); err != nil {
		t.Fatal(err)
	}
	ref := publishedFrom(t, garbage, store.SchemaVersion, nil)

	var out, errOut bytes.Buffer
	code := Pull(context.Background(), dst, ref, &out, &errOut)
	if code != 2 {
		t.Errorf("Pull of a garbage artifact = %d, want 2 (stderr: %s)", code, errOut.String())
	}
	after, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("the live database is gone: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Error("a failed pull modified the live database")
	}
	if _, err := os.Stat(dst + ".tmp"); !os.IsNotExist(err) {
		t.Error("a failed pull (rejected by store.Open) left a temp file behind")
	}
}

// The unreachable-registry scenario TestPull_AFailedPullLeavesTheLiveDatabaseAlone
// used to stand in for, named for what it actually exercises: Pull's own
// fetch-error path (pull.go's remote.Image call), distinct from the
// temp-file/validation guarantee the renamed test above now covers.
// 127.0.0.1:1 is loopback with nothing listening, so this needs no real
// network access and fails fast.
func TestPull_UnreachableRegistryExitsTwo(t *testing.T) {
	dst := pushable(t, time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC))
	before, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}

	var out, errOut bytes.Buffer
	code := Pull(context.Background(), dst, "127.0.0.1:1/assay-db:v6", &out, &errOut)
	if code != 2 {
		t.Errorf("Pull from an unreachable registry = %d, want 2", code)
	}
	after, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("the live database is gone: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Error("a failed pull modified the live database")
	}
}

// Pull must install with Update's own retrying replace() (dbcmd.go), not a
// bare, single-attempt os.Rename.
//
// Fix round 1's version of this test forced a persistent rename failure and
// asserted on ELAPSED TIME (>= 300ms, replace()'s ~850ms schedule vs. a
// single attempt's <1ms). Fix round 2 found that threshold could go quietly
// vacuous: replace()'s sleeps are a hard floor, so a mutant can only run
// SLOWER than the fix, never faster -- but Pull's own pre-install work
// (fetch, decompress, open) is NOT bounded, so on a loaded runner that work
// alone can push total elapsed past 300ms even for a single-attempt mutant,
// making the mutant read as correct. It also did not prove what its name
// claimed: {0, 100, 250} (one fewer retry) still elapses ~350ms and clears a
// 300ms floor; the floor could not distinguish "the schedule ran" from "some
// sleeping happened."
//
// Replaced with a deterministic seam instead: renameFn lets this force
// every rename attempt to fail and count exactly how many replace() makes,
// with no wall clock involved at all -- immune to runner load by
// construction, not by a wider margin.
func TestPull_InstallUsesReplacesRetrySchedule(t *testing.T) {
	origWaits, origRename := replaceWaits, renameFn
	t.Cleanup(func() { replaceWaits, renameFn = origWaits, origRename })

	// Zeroes the WAIT DURATIONS but keeps the COUNT from the live var,
	// rather than hardcoding []time.Duration{0, 0, 0, 0}: a hardcoded
	// replacement would silently mask a mutation that shortens
	// replaceWaits itself, since the test would then be defining its own
	// attempt count independent of production's. Deriving the length here,
	// then wiping only the values, keeps that mutation visible.
	replaceWaits = make([]time.Duration, len(replaceWaits))

	var attempts int32
	renameFn = func(string, string) error {
		atomic.AddInt32(&attempts, 1)
		return fmt.Errorf("simulated rename failure")
	}

	dst := filepath.Join(t.TempDir(), "vulnerability.db")
	ref := published(t, store.SchemaVersion)

	var out, errOut bytes.Buffer
	code := Pull(context.Background(), dst, ref, &out, &errOut)
	if code != 2 {
		t.Fatalf("Pull with a permanently failing rename = %d, want 2 (stderr: %s)", code, errOut.String())
	}
	// The number this test actually names: replace()'s own schedule is 4
	// attempts (dbcmd.go). A hardcoded expectation, not len(replaceWaits)
	// after the shrink above -- asserting against the live var here would
	// make this tautological against exactly the mutation it needs to
	// catch, since a shortened production schedule would shrink both what
	// replace() calls AND what this assertion expects, together.
	const wantAttempts = 4
	if got := atomic.LoadInt32(&attempts); got != wantAttempts {
		t.Errorf("renameFn called %d times, want exactly %d (replace()'s retry schedule, dbcmd.go)",
			got, wantAttempts)
	}
	// The other half of the same fix (fix round 1): on failure the temp
	// file is KEPT, not deleted -- a verified, complete download is worth
	// more than a tidy failure.
	if _, err := os.Stat(dst + ".tmp"); err != nil {
		t.Errorf("a failed install must keep the verified download, not delete it: %v", err)
	}
}

// replace()'s retry schedule exists to give a concurrent reader time to
// release the file (dbcmd.go's own doc comment on replace) -- a schedule
// whose delays are all zero still makes the full number of attempts, so
// TestPull_InstallUsesReplacesRetrySchedule would not catch that on its
// own: it zeroes replaceWaits' VALUES itself, for its own speed, so a
// production default that was ALREADY all zero would be indistinguishable
// from a correct one there. Checked directly against the values instead,
// with no wall clock at all -- deterministic, and immune to runner load by
// construction rather than by a timing margin.
func TestReplaceWaits_RetriesActuallyWait(t *testing.T) {
	if len(replaceWaits) < 2 {
		t.Fatalf("replaceWaits has %d entries, too few to ever retry", len(replaceWaits))
	}
	// replaceWaits[0] == 0 is correct and intentional: there is no reason to
	// delay before the very first attempt. Every attempt AFTER that needs a
	// real, positive wait, or it is not meaningfully a retry at all.
	for i, w := range replaceWaits[1:] {
		if w <= 0 {
			t.Errorf("replaceWaits[%d] = %v, want > 0 -- a zero wait between retries gives a "+
				"concurrent reader no time to release the file, defeating replace()'s own purpose",
				i+1, w)
		}
	}
}

// Ref's tag must encode THIS binary's schema version -- store.DefaultPath
// derives its directory from the same constant, and the two silently
// drifting apart is exactly the "asks for artifacts it cannot read" failure
// the doc comment on Ref describes. store.SchemaVersion is currently a
// single digit, so a truncated or malformed format string (e.g. an accidental
// literal suffix) would otherwise pass unnoticed by any test that only
// exercises a hand-built ref, as TestPull_LandsAUsableDatabase does.
func TestRef_EndsInTheCurrentSchemaVersion(t *testing.T) {
	ref := Ref(DefaultRef)
	want := "v" + itoa(store.SchemaVersion)
	if !strings.HasSuffix(ref, want) {
		t.Errorf("Ref(%q) = %q, want it to end in %q", DefaultRef, ref, want)
	}
}

// TestPull_AttributesTheStalestSource holds the D12 attribution added after
// the 2026-08-27 investigation: "upstream data as of 2023-09-25" was genuine
// (six dead AL2 extras topics) but READ as "the whole database is three
// years stale" because the one-liner never said which provider set the
// floor. The line must name the stalest source and point at `db status` for
// the rest -- and the name must be the one that actually produced the
// minimum, not whichever map key happened to iterate first (the fixture's
// two providers are chosen so getting either wrong is visible).
func TestPull_AttributesTheStalestSource(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vulnerability.db")
	w, err := store.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.SetMeta(store.Meta{
		BuiltAt: testBuiltAt,
		Providers: map[string]store.Provenance{
			"osv":    {Source: "https://example.test/osv", DataAsOf: time.Date(2026, 8, 26, 0, 0, 0, 0, time.UTC)},
			"amazon": {Source: "https://example.test/alas", DataAsOf: time.Date(2023, 9, 25, 22, 0, 0, 0, time.UTC)},
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	// Through the REAL Push, not publishedFrom -- that helper hand-builds
	// the artifact Meta and would bypass the very computation under test
	// (which provider set the floor is Push's job to record).
	srv := httptest.NewServer(registry.New())
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	host := must(t, u, err).Host
	ref := host + "/assay-db:v" + itoa(store.SchemaVersion)
	var out, errOut bytes.Buffer
	if code := Push(context.Background(), path, ref, false, &out, &errOut); code != 0 {
		t.Fatalf("Push = %d, want 0 (stderr: %s)", code, errOut.String())
	}

	dst := filepath.Join(t.TempDir(), "vulnerability.db")
	out.Reset()
	errOut.Reset()
	if code := Pull(context.Background(), dst, ref, &out, &errOut); code != 0 {
		t.Fatalf("Pull = %d, want 0 (stderr: %s)", code, errOut.String())
	}
	got := errOut.String()
	want := "upstream data as of 2023-09-25 (stalest source: amazon; per-source dates: assay db status)"
	if !strings.Contains(got, want) {
		t.Errorf("stderr = %q, want it to contain %q", got, want)
	}
}

// TestPull_UnattributedArtifactKeepsTheBareLine is the backward-compat half:
// an artifact published before the source annotation existed (publishedFrom
// hand-builds exactly that shape) must print the original line, not an
// attribution with an empty name — "(stalest source: ;" would read as a
// formatting bug and teach readers to distrust the attribution when present.
func TestPull_UnattributedArtifactKeepsTheBareLine(t *testing.T) {
	ref := published(t, store.SchemaVersion)
	dst := filepath.Join(t.TempDir(), "vulnerability.db")

	var out, errOut bytes.Buffer
	if code := Pull(context.Background(), dst, ref, &out, &errOut); code != 0 {
		t.Fatalf("Pull = %d, want 0 (stderr: %s)", code, errOut.String())
	}
	got := errOut.String()
	if !strings.Contains(got, "upstream data as of 2026-08-03\n") {
		t.Errorf("stderr = %q, want the bare dated line", got)
	}
	if strings.Contains(got, "stalest source") {
		t.Errorf("stderr = %q, must not attribute when the artifact carries no source", got)
	}
}
