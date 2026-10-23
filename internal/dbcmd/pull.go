package dbcmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/kun9497/assay/internal/dbartifact"
	"github.com/kun9497/assay/internal/dbcmd/trust"
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
func Pull(ctx context.Context, dbPath, ref string, allowUnsigned bool, stdout, stderr io.Writer) int {
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

	// D137: verified here, after the schema check (one more manifest fetch,
	// still before the layer) and before anything is written or locked, so
	// a refused artifact leaves no temp file and never touched the lock.
	d, err := img.Digest()
	if err != nil {
		fmt.Fprintf(stderr, "error: digest of %s: %v\n", target, err)
		return 2
	}
	keyID, unverified, code := verifyPulled(ctx, target, d, allowUnsigned, "refusing to install",
		"a mirror must copy the signature tag too, or pass --allow-unsigned to install it unverified", stderr)
	if code != 0 {
		return code
	}

	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		fmt.Fprintf(stderr, "error: create database directory: %v\n", err)
		return 2
	}
	// D116, as Update takes it: after the manifest checks, so a pull refused
	// for its schema has written nothing and never touched the lock, and
	// before the temp file, so a second writer never reaches it. Held until
	// the rename has happened or failed.
	release, err := acquireWriterLock(dbPath)
	if err != nil {
		writerLockFailed(stderr, err)
		return 2
	}
	defer release()
	// Written to a temp file and renamed, exactly as Update does. A pull
	// that dies halfway must not leave a truncated database where a scan
	// will find it and report a confident, wrong, clean result.
	tmp := dbPath + ".tmp"
	if err := unpackWithRetry(img, tmp, stderr); err != nil {
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
	// D127. The record of what was pulled goes INTO the verified database
	// before it is installed, so the record and the database it names are
	// one file and one rename: a scan that opens the database has the record
	// of the pull that produced it, never the previous pull's, and the temp
	// file the failure message below tells the user to move into place
	// already names its own artifact. The sidecar this replaced was written
	// after the rename, and a scan between the two renames -- or after a
	// pull that died between them -- paired the new database with the old
	// digest (2026-10-20 external review, #7). A record that cannot be
	// written fails the pull with the previous database still in place: the
	// caller asked for a database a scan can name. The record also says
	// which key verified the artifact, or that none did and the operator
	// said so (D137), so `db status` and every report's provenance can.
	if err := setArtifactFn(tmp, store.ArtifactRecord{
		Reference: target.String(), Digest: d.String(), PulledAt: time.Now().UTC(),
		SignedBy: keyID, Unverified: unverified,
	}); err != nil {
		os.Remove(tmp)
		fmt.Fprintf(stderr, "error: record the pulled artifact: %v\n", err)
		return 2
	}

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
	// A pre-D127 pull's sidecar is read by nothing, but must not survive
	// beside the database to be taken for current. After the rename, under
	// the lock still; a failure here is a warning, not a failed pull -- the
	// installed database carries its own record either way.
	removeLegacySidecar(dbPath, stderr)
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

	// D137, exactly as Pull does it and at the same point, with no way to
	// opt out: the nightly builder is this function's one caller, and a
	// builder seeded from an unsigned database would publish -- and sign --
	// whatever it had been fed.
	d, err := img.Digest()
	if err != nil {
		fmt.Fprintf(stderr, "error: digest of %s: %v\n", target, err)
		return 2
	}
	if _, _, code := verifyPulled(ctx, target, d, false, "refusing to seed from it",
		"a mirror must copy the signature tag too; a hand-pushed artifact is signed by dispatching db-sign.yml with its digest", stderr); code != 0 {
		return code
	}

	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		fmt.Fprintf(stderr, "error: create database directory: %v\n", err)
		return 2
	}
	// Written to a temp file and renamed, exactly as Pull does: a seed pull
	// that dies halfway must not leave a truncated file where dbcmd.Update
	// will find and read it next.
	tmp := dbPath + ".tmp"
	if err := unpackWithRetry(img, tmp, stderr); err != nil {
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

// verifyPulled checks the signature on the artifact at target (manifest
// digest d) against TrustedKeys and says on stderr what it found. It returns
// the id of the key that verified, or "" with unverified set when
// allowUnsigned excused an ABSENT signature; a non-zero code means the pull
// stops. The three failures are told apart because each calls for a
// different action: not signed (copy the tag, or opt out -- the hint names
// the way out the caller has, which for a --seed input is none), a present
// signature no trusted key verifies (never installed, flag or no flag:
// that is the tampering the signature exists to catch, or a key this
// binary was not built with), and a transport failure (retry, fix auth --
// reported with the registry's own error, never as "not signed", or an
// operator would reach for --allow-unsigned to get past a 403).
func verifyPulled(ctx context.Context, target name.Reference, d v1.Hash, allowUnsigned bool, refusal, hint string, stderr io.Writer) (keyID string, unverified bool, code int) {
	keyID, err := trust.Verify(ctx, target.Context(), d, TrustedKeys(),
		remote.WithContext(ctx), remote.WithAuthFromKeychain(authn.DefaultKeychain))
	switch {
	case err == nil:
		return keyID, false, 0
	case errors.Is(err, trust.ErrNotSigned):
		if allowUnsigned {
			fmt.Fprintf(stderr, "WARNING: installing %s@%s UNVERIFIED (--allow-unsigned): no %s in the repository\n",
				target, d, trust.SigTag(d))
			return "", true, 0
		}
		fmt.Fprintf(stderr, "error: %s@%s is not signed (no %s in the repository) — %s\n", target, d, trust.SigTag(d), refusal)
		fmt.Fprintf(stderr, "  %s\n", hint)
		return "", false, 2
	case errors.Is(err, trust.ErrNoKeyVerifies):
		var ids []string
		for _, k := range TrustedKeys() {
			ids = append(ids, k.ID)
		}
		fmt.Fprintf(stderr, "error: the signature on %s@%s does not verify under any key this assay trusts (%s) — %s\n",
			target, d, strings.Join(ids, ", "), refusal)
		fmt.Fprintf(stderr, "  %v\n", err)
		fmt.Fprintln(stderr, "  a signature that is present and wrong is never installed; if the publisher rotated its key, upgrade assay")
		return "", false, 2
	default:
		fmt.Fprintf(stderr, "error: fetch signature for %s@%s: %v\n", target, d, err)
		return "", false, 2
	}
}

// TrustedKeys is the set of signing keys a pull verifies against (D137):
// trust.TrustedKeys, the keys embedded in this binary. A variable so a test
// can register the key that signed its in-process registry's artifacts --
// the embedded keys cannot sign anything in a test, and a pull that could
// not be tested against a signed artifact would be held by nothing. It is
// never consulted for anything but verification, and nothing in production
// assigns it.
var TrustedKeys = trust.TrustedKeys

// setArtifactFn is store.SetArtifactAt by default, and the seam Pull writes
// the record through, so a test can make the write fail: nothing else can --
// img.Digest() is served from the manifest already fetched, and nothing holds
// the temp file open -- and the branch that fails the pull on it would
// otherwise be held by no test (renameFn's reasoning, one step earlier).
var setArtifactFn = store.SetArtifactAt

// removeLegacySidecar is what remains of the sidecar path (D120 before D127):
// it removes a pre-D127 record beside dbPath, which nothing reads but which
// must not survive to be mistaken for current.
func removeLegacySidecar(dbPath string, stderr io.Writer) {
	if err := store.RemoveLegacyArtifactRecord(dbPath); err != nil {
		fmt.Fprintf(stderr, "warning: remove the previous pull's sidecar record: %v\n", err)
	}
}

// transferAttempts is how many times a pull downloads the database layer
// before giving up on an interrupted transfer (D140).
const transferAttempts = 3

// unpackWithRetry is dbartifact.Unpack, attempted up to transferAttempts
// times while the failure is an interrupted transfer (D140).
//
// go-containerregistry already retries each REQUEST three times on a 5xx,
// a 429 or a dropped connection; what it cannot retry is a response body
// cut after the request succeeded, which is how a 60 MB layer download
// fails on a flaky link or a registry restarting mid-stream. Each attempt
// re-requests the layer from the start and rewrites tmp from empty. Any
// other failure -- a layer that is not gzip, a digest that does not match,
// no database layer at all -- is the artifact's, not the link's, and fails
// at once: retrying it would only repeat the same answer three times.
func unpackWithRetry(img v1.Image, tmp string, stderr io.Writer) error {
	var err error
	for n := 1; n <= transferAttempts; n++ {
		_ = os.Remove(tmp)
		if err = dbartifact.Unpack(img, tmp); err == nil {
			return nil
		}
		if !interruptedTransfer(err) {
			return err
		}
		if n < transferAttempts {
			fmt.Fprintf(stderr, "download interrupted (%v); retrying (%d/%d)\n", err, n+1, transferAttempts)
			transferRetryPause(n)
		}
	}
	return fmt.Errorf("after %d attempts: %w", transferAttempts, err)
}

// interruptedTransfer reports whether err is a transfer cut short rather
// than a property of the artifact: the stream ended early, the peer reset
// or closed the connection, or the network timed out.
func interruptedTransfer(err error) bool {
	if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.EPIPE) || errors.Is(err, net.ErrClosed) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// transferRetryPause waits before download attempt n+1 (n is the attempt
// that failed). A variable so tests do not sleep.
var transferRetryPause = func(n int) { time.Sleep(time.Duration(n*n) * 2 * time.Second) }
