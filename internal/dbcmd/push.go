package dbcmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/kun9497/assay/internal/dbartifact"
	"github.com/kun9497/assay/internal/store"
)

// Push publishes the database at dbPath to ref (D28). It is the builder's
// half of the slice: one machine spends the hours, everyone else pulls the
// result in seconds.
//
// The artifact's freshness comes from the database's own recorded
// provenance, never from the clock. Stamping time.Now() here would make
// every re-push of an old database look current, which is the exact
// failure D12 separates DataAsOf from BuiltAt to prevent.
func Push(ctx context.Context, dbPath, ref string, stdout, stderr io.Writer) int {
	if _, err := os.Stat(dbPath); err != nil {
		fmt.Fprintf(stderr, "error: no database at %s: %v\n", dbPath, err)
		fmt.Fprintln(stderr, "  build one first with `assay db build`")
		return 2
	}
	db, err := store.Open(dbPath)
	if err != nil {
		fmt.Fprintf(stderr, "error: open database: %v\n", err)
		return 2
	}
	meta, err := db.Meta()
	if err != nil {
		db.Close()
		fmt.Fprintf(stderr, "error: read database metadata: %v\n", err)
		return 2
	}
	db.Close()

	img, err := dbartifact.Pack(dbPath, dbartifact.Meta{
		SchemaVersion: store.SchemaVersion,
		BuiltAt:       meta.BuiltAt,
		DataAsOf:      oldestDataAsOf(meta),
	})
	if err != nil {
		fmt.Fprintf(stderr, "error: pack database: %v\n", err)
		return 2
	}

	target, err := name.ParseReference(ref)
	if err != nil {
		fmt.Fprintf(stderr, "error: %q is not a valid reference: %v\n", ref, err)
		return 2
	}
	fmt.Fprintf(stderr, "pushing to %s…\n", target)
	if err := remote.Write(target, img,
		remote.WithContext(ctx),
		remote.WithAuthFromKeychain(authn.DefaultKeychain)); err != nil {
		fmt.Fprintf(stderr, "error: push: %v\n", err)
		return 2
	}
	digest, err := img.Digest()
	if err != nil {
		fmt.Fprintf(stderr, "error: read digest: %v\n", err)
		return 2
	}
	// The digest goes to stdout because it is the result -- a caller
	// pinning this build in a manifest wants to capture it, and stream
	// discipline says a capturable result is not a diagnostic.
	fmt.Fprintf(stdout, "%s@%s\n", target.Context().Name(), digest)
	return 0
}

// oldestDataAsOf is "the oldest upstream wins" (D12), the same rule the NVD
// provider applies across its own pages: an artifact is only as fresh as
// its stalest component. Taking the newest would let one recently-synced
// provider vouch for a database whose other half is months old.
func oldestDataAsOf(m store.Meta) time.Time {
	var oldest time.Time
	for _, p := range m.Providers {
		if p.DataAsOf.IsZero() {
			continue
		}
		if oldest.IsZero() || p.DataAsOf.Before(oldest) {
			oldest = p.DataAsOf
		}
	}
	return oldest
}
