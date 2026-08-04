package dbcmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/kun9497/assay/internal/dbartifact"
	"github.com/kun9497/assay/internal/store"
)

// DefaultRef is where `assay db update` looks. The schema version is the
// TAG, mirroring store.DefaultPath deriving its directory from the same
// constant: a binary only ever asks for artifacts it can read, so a schema
// bump produces a clean "not found" rather than a database it would
// misinterpret.
const DefaultRef = "ghcr.io/kun9497/assay-db"

// Ref returns the reference this binary's schema version corresponds to.
func Ref(base string) string {
	return fmt.Sprintf("%s:v%d", base, store.SchemaVersion)
}

// Pull downloads a published database and installs it at dbPath (D28).
//
// This is the only command that fetches a database, and a scan never calls
// it: D14 is not "a scan avoids the network when it can", it is that a scan
// cannot reach vulnerability data at all. A missing database is an exit 2
// with instructions, never an implicit download.
func Pull(ctx context.Context, dbPath, ref string, stdout, stderr io.Writer) int {
	target, err := name.ParseReference(ref)
	if err != nil {
		fmt.Fprintf(stderr, "error: %q is not a valid reference: %v\n", ref, err)
		return 2
	}
	fmt.Fprintf(stderr, "fetching %s…\n", target)
	img, err := remote.Image(target,
		remote.WithContext(ctx),
		remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		fmt.Fprintf(stderr, "error: fetch %s: %v\n", target, err)
		fmt.Fprintln(stderr, "  to build the database yourself instead, run `assay db build`")
		return 2
	}

	// Checked before the layer is touched. remote.Image is lazy, so this
	// costs a manifest fetch rather than the whole database -- which is the
	// point: a schema mismatch is the ordinary state of an out-of-date
	// binary, and making the user download 60 MB to be told no is a bad
	// trade for one HTTP request.
	m, err := dbartifact.MetaOf(img)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 2
	}
	if m.SchemaVersion != store.SchemaVersion {
		fmt.Fprintf(stderr, "error: %s holds schema v%d, but this assay reads v%d\n",
			target, m.SchemaVersion, store.SchemaVersion)
		if m.SchemaVersion > store.SchemaVersion {
			fmt.Fprintln(stderr, "  upgrade assay, or run `assay db build` to build a v"+
				fmt.Sprint(store.SchemaVersion)+" database from source")
		} else {
			fmt.Fprintln(stderr, "  the published database is older than this assay; upgrade the publisher,")
			fmt.Fprintln(stderr, "  or run `assay db build` to build one from source")
		}
		return 2
	}

	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		fmt.Fprintf(stderr, "error: create database directory: %v\n", err)
		return 2
	}
	// Written to a temp file and renamed, exactly as Update does. A pull
	// that dies halfway must not leave a truncated database where a scan
	// will find it and report a confident, wrong, clean result.
	tmp := dbPath + ".tmp"
	_ = os.Remove(tmp)
	if err := dbartifact.Unpack(img, tmp); err != nil {
		os.Remove(tmp)
		fmt.Fprintf(stderr, "error: unpack database: %v\n", err)
		return 2
	}
	// Opened before it is installed: an artifact that unpacks cleanly but
	// is not a database it can read must fail here, while the previous
	// database is still in place.
	db, err := store.Open(tmp)
	if err != nil {
		os.Remove(tmp)
		fmt.Fprintf(stderr, "error: the downloaded file is not a usable database: %v\n", err)
		return 2
	}
	db.Close()

	if err := os.Rename(tmp, dbPath); err != nil {
		os.Remove(tmp)
		fmt.Fprintf(stderr, "error: install database: %v\n", err)
		return 2
	}
	fmt.Fprintf(stderr, "database installed at %s\n", dbPath)
	if !m.DataAsOf.IsZero() {
		fmt.Fprintf(stderr, "upstream data as of %s\n", m.DataAsOf.Format("2006-01-02"))
	}
	return 0
}
