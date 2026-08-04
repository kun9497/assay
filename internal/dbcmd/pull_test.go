package dbcmd

import (
	"bytes"
	"context"
	"fmt"
	"net/http/httptest"
	"net/url"
	"os"
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

// published pushes a real database to an in-memory registry and returns its
// reference, so pull tests exercise the actual artifact Push writes rather
// than a hand-built approximation that could drift from it.
func published(t *testing.T, schema int) string {
	t.Helper()
	srv := httptest.NewServer(registry.New())
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	host := must(t, u, err).Host
	ref := host + "/assay-db:v" + itoa(schema)

	src := pushable(t, time.Date(2026, 8, 3, 0, 0, 0, 0, time.UTC))
	img, err := dbartifact.Pack(src, dbartifact.Meta{
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
func TestPull_RefusesAForeignSchemaWithoutDownloading(t *testing.T) {
	ref := published(t, store.SchemaVersion+1)
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
}

// A pull that fails partway must not replace a working database. This is
// the same guarantee Update gives, and it matters more here: the failure is
// a network one, so it is the common case rather than the rare one.
func TestPull_AFailedPullLeavesTheLiveDatabaseAlone(t *testing.T) {
	dst := pushable(t, time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC))
	before, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}

	var out, errOut bytes.Buffer
	// A registry that is not there.
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
