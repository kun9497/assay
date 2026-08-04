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
func TestPull_RefusesAForeignSchemaWithoutDownloading(t *testing.T) {
	var blobGETs int32
	ref := publishedFrom(t, pushable(t, time.Date(2026, 8, 3, 0, 0, 0, 0, time.UTC)),
		store.SchemaVersion+1,
		func(h http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/blobs/") {
					atomic.AddInt32(&blobGETs, 1)
				}
				h.ServeHTTP(w, r)
			})
		})
	// The push above (remote.Write, inside publishedFrom) only ever HEADs,
	// POSTs, PATCHes and PUTs blobs while uploading -- never GETs one -- so
	// the counter is still genuinely zero here, not merely reset to look
	// that way.
	dst := filepath.Join(t.TempDir(), "vulnerability.db")

	var out, errOut bytes.Buffer
	code := Pull(context.Background(), dst, ref, &out, &errOut)
	if code != 2 {
		t.Errorf("Pull of a newer schema = %d, want 2", code)
	}
	if !strings.Contains(errOut.String(), "upgrade") {
		t.Errorf("stderr does not tell the user what to do:\n%s", errOut.String())
	}
	if _, err := os.Stat(dst); !os.IsNotExist(err) {
		t.Error("a refused pull left a file behind")
	}
	if got := atomic.LoadInt32(&blobGETs); got != 0 {
		t.Errorf("Pull fetched %d layer blob(s) before refusing the schema mismatch, want 0", got)
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
// bare, single-attempt os.Rename. Fix round 1 found the two are otherwise
// indistinguishable on a rename that simply succeeds, so this forces a
// PERSISTENT rename failure -- dbPath is an existing directory, which
// os.Rename can never succeed against, retried or not, on any platform --
// and asserts on ELAPSED TIME rather than the outcome: both variants return
// exit 2, but only replace()'s four attempts with 0/100/250/500ms sleeps
// between them (dbcmd.go's own schedule; ~850ms measured end to end) take
// meaningfully longer than one immediate attempt (<1ms measured).
//
// Deliberately does not rely on Windows' "rename over a file another
// process holds open fails outright" semantics that motivate replace() in
// the first place: CI runs ubuntu-latest, where that would not reproduce
// (POSIX rename succeeds over an open file). Forcing a directory target
// instead relies only on replace()'s sleep schedule running whenever the
// underlying os.Rename keeps failing, which is plain Go and portable.
//
// Also covers the other half of the same fix: on failure the temp file
// must be KEPT, not deleted, matching Update's own reasoning (dbcmd.go) --
// a verified, complete download is worth more than a tidy failure.
func TestPull_InstallUsesReplacesRetrySchedule(t *testing.T) {
	dirAsDst := t.TempDir() // an existing directory: no rename can ever land here
	ref := published(t, store.SchemaVersion)

	start := time.Now()
	var out, errOut bytes.Buffer
	code := Pull(context.Background(), dirAsDst, ref, &out, &errOut)
	elapsed := time.Since(start)

	if code != 2 {
		t.Fatalf("Pull with an un-renameable destination = %d, want 2 (stderr: %s)", code, errOut.String())
	}
	// 300ms comfortably separates "one immediate attempt" (measured <1ms)
	// from "the retry schedule ran" (measured ~850ms), without sitting close
	// enough to 850ms that ordinary CI jitter could false-fail the other way.
	if elapsed < 300*time.Millisecond {
		t.Errorf("Pull failed to install in %v, too fast for replace()'s retry schedule -- "+
			"want the retrying replace() from dbcmd.go, not a single os.Rename attempt", elapsed)
	}
	if _, err := os.Stat(dirAsDst + ".tmp"); err != nil {
		t.Errorf("a failed install must keep the verified download, not delete it: %v", err)
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
