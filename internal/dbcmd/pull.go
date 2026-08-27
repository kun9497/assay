package dbcmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

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

	// The same retrying rename Update uses (dbcmd.go), not a bare os.Rename:
	// on Windows a rename over a file a concurrent scan holds open fails
	// outright, and a scan reading the database is exactly the case the
	// temp-file dance exists to support. On failure the temp file is kept,
	// not removed -- it is a verified, complete database that cost a real
	// download, and losing it because a scan happened to be running is a
	// worse outcome than leaving a file behind (dbcmd.go's own reasoning for
	// Update, applied here since the download makes it matter even more).
	if err := replace(tmp, dbPath); err != nil {
		fmt.Fprintf(stderr, "error: install database: %v\n", err)
		fmt.Fprintf(stderr, "the downloaded database is complete and left at %s\n", tmp)
		fmt.Fprintln(stderr, "close any running scan and move it into place, or re-run `assay db update`")
		return 2
	}
	fmt.Fprintf(stderr, "database installed at %s\n", dbPath)
	if !m.DataAsOf.IsZero() {
		// The date is D12's floor -- the MINIMUM across every source -- and
		// without attribution it reads as "the whole database is this old"
		// (the 2026-08-27 misreading: six dead AL2 extras topics pinned it
		// to 2023 while every other source was days-fresh). Name the source
		// when the artifact says which; older artifacts carry no attribution
		// and keep the bare line.
		if m.DataAsOfSource != "" {
			fmt.Fprintf(stderr, "upstream data as of %s (stalest source: %s; per-source dates: assay db status)\n",
				m.DataAsOf.Format("2006-01-02"), m.DataAsOfSource)
		} else {
			fmt.Fprintf(stderr, "upstream data as of %s\n", m.DataAsOf.Format("2006-01-02"))
		}
	}
	return 0
}

// PullSeed downloads a published database for use as a build's --seed input
// (cmd/assay's `db build --seed <ref>` case calls this instead of Pull).
//
// It exists for the D-seed-bootstrap hazard, the reader's half of the same
// problem push.go's previousSchemaRef and its D60 comment already solve for
// the writer: `db build --seed $(assay db ref)` is what the nightly workflow
// runs every night, and `assay db ref` names THIS binary's own schema tag --
// which cannot exist before the schema's own first push. The first :v9
// publish hit exactly that: the seed fetch failed with MANIFEST_UNKNOWN
// before the build that would have created :v9 had ever run.
//
// Two differences from Pull, both narrowed to what a --seed input alone
// needs, and both left OUT of Pull itself deliberately:
//
//   - On a fetch error for ref whose message names MANIFEST_UNKNOWN, it
//     retries ONCE against the previous schema's tag (previousSchemaRef,
//     push.go, D60) and says so on stderr, in the same voice D60 already
//     uses there. Any other fetch error, or MANIFEST_UNKNOWN on the fallback
//     too, fails exactly as Pull does: same exit code, same guidance lines.
//   - The schema check accepts SchemaVersion or SchemaVersion-1 -- the seed
//     contract store.OpenSeedRatings already guards (D67) -- rather than
//     Pull's exact match. dbcmd.Update's ratings-copy block reads a --seed
//     input through OpenSeedRatings, never through Open, and is exactly as
//     happy with a schema-(N-1) artifact as a current one -- so refusing one
//     here would block a legitimate bootstrap over a mismatch that costs
//     nothing downstream. Pull itself keeps its exact match unchanged:
//     `db update` installs a database this binary reads and scans directly,
//     and the exact match is the guarantee that protects that read.
//
// The downloaded artifact's own validity check uses store.OpenSeedRatings
// for the identical reason -- Pull's own store.Open validation would refuse
// a genuine N-1 seed before dbcmd.Update ever got to read it.
func PullSeed(ctx context.Context, dbPath, ref string, stdout, stderr io.Writer) int {
	target, err := name.ParseReference(ref)
	if err != nil {
		fmt.Fprintf(stderr, "error: %q is not a valid reference: %v\n", ref, err)
		return 2
	}
	fmt.Fprintf(stderr, "fetching %s…\n", target)
	img, fetchErr := remote.Image(target,
		remote.WithContext(ctx),
		remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if fetchErr != nil && strings.Contains(fetchErr.Error(), "MANIFEST_UNKNOWN") {
		// D60's own bootstrap case, one door over: the tag moves on a schema
		// bump, so the FIRST seed pull of a new schema has nothing at its own
		// tag yet. Falling back to the previous schema's tag is exactly the
		// baseline a bootstrap seed should carry forward from.
		if prev, perr := previousSchemaRef(target); perr == nil {
			fmt.Fprintf(stderr, "%s does not exist yet; seeding from %s, the previous schema\n",
				target, prev)
			target = prev
			img, fetchErr = remote.Image(target,
				remote.WithContext(ctx),
				remote.WithAuthFromKeychain(authn.DefaultKeychain))
		}
	}
	if fetchErr != nil {
		fmt.Fprintf(stderr, "error: fetch %s: %v\n", target, fetchErr)
		fmt.Fprintln(stderr, "  to build the database yourself instead, run `assay db build`")
		return 2
	}

	// Checked before the layer is touched, exactly as Pull does it and for
	// the same reason: a schema mismatch is the ordinary state of an
	// out-of-date binary, and a 60 MB download to be told no is a bad trade
	// for one HTTP request.
	m, err := dbartifact.MetaOf(img)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 2
	}
	// SchemaVersion OR SchemaVersion-1 -- the seed contract (D67), not
	// Pull's exact match. See the doc comment above for why that is safe
	// here specifically.
	if m.SchemaVersion != store.SchemaVersion && m.SchemaVersion != store.SchemaVersion-1 {
		fmt.Fprintf(stderr, "error: %s holds schema v%d, but this assay reads v%d (a seed may be one schema behind)\n",
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
	// Written to a temp file and renamed, exactly as Pull does: a seed pull
	// that dies halfway must not leave a truncated file where dbcmd.Update
	// will find and read it next.
	tmp := dbPath + ".tmp"
	_ = os.Remove(tmp)
	if err := dbartifact.Unpack(img, tmp); err != nil {
		os.Remove(tmp)
		fmt.Fprintf(stderr, "error: unpack database: %v\n", err)
		return 2
	}
	// store.OpenSeedRatings, not store.Open: this download is a --seed
	// input, and a schema-(N-1) artifact opening cleanly here is exactly
	// what this function exists to allow. See the doc comment above.
	seed, err := store.OpenSeedRatings(tmp)
	if err != nil {
		os.Remove(tmp)
		fmt.Fprintf(stderr, "error: the downloaded file is not a usable database: %v\n", err)
		return 2
	}
	seed.Close()

	// The same retrying rename Pull and Update both use (dbcmd.go).
	if err := replace(tmp, dbPath); err != nil {
		fmt.Fprintf(stderr, "error: install database: %v\n", err)
		fmt.Fprintf(stderr, "the downloaded database is complete and left at %s\n", tmp)
		fmt.Fprintln(stderr, "close any running scan and move it into place, or re-run `assay db build`")
		return 2
	}
	fmt.Fprintf(stderr, "database installed at %s\n", dbPath)
	if !m.DataAsOf.IsZero() {
		// The date is D12's floor -- the MINIMUM across every source -- and
		// without attribution it reads as "the whole database is this old"
		// (the 2026-08-27 misreading: six dead AL2 extras topics pinned it
		// to 2023 while every other source was days-fresh). Name the source
		// when the artifact says which; older artifacts carry no attribution
		// and keep the bare line.
		if m.DataAsOfSource != "" {
			fmt.Fprintf(stderr, "upstream data as of %s (stalest source: %s; per-source dates: assay db status)\n",
				m.DataAsOf.Format("2006-01-02"), m.DataAsOfSource)
		} else {
			fmt.Fprintf(stderr, "upstream data as of %s\n", m.DataAsOf.Format("2006-01-02"))
		}
	}
	return 0
}
