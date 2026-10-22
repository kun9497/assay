package dbcmd

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kun9497/assay/internal/dbcmd/trust/trusttest"
	"github.com/kun9497/assay/internal/store"
)

// D137's caller-side tests, written before the verifier had a caller
// (CLAUDE.md: "the helper is covered; nothing calls it"). trust.Verify is
// held by its own package; what these hold is that Pull and PullSeed
// consult it, where in their sequence they do, and what each answer does
// to the exit code, the record, and the files on disk.

// An unsigned artifact is refused BEFORE anything is written: no temp file,
// no lock, the live database untouched. The message names the tag a mirror
// must copy, because "not signed" against a mirror usually means the mirror
// copied the image and not its signature.
func TestPull_RefusesAnUnsignedArtifactBeforeUnpacking(t *testing.T) {
	dst := pushable(t, time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC))
	before, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	ref := publishedUnsignedFrom(t, pushable(t, time.Date(2026, 8, 3, 0, 0, 0, 0, time.UTC)), store.SchemaVersion, nil)
	_, d := hashOf(t, ref)

	var out, errOut bytes.Buffer
	if code := Pull(context.Background(), dst, ref, false, &out, &errOut); code != 2 {
		t.Fatalf("Pull of an unsigned artifact = %d, want 2 (stderr: %s)", code, errOut.String())
	}
	if !strings.Contains(errOut.String(), "is not signed") {
		t.Errorf("stderr does not say the artifact is not signed:\n%s", errOut.String())
	}
	if !strings.Contains(errOut.String(), trusttest.SigTag(d)) {
		t.Errorf("stderr does not name the signature tag %s a mirror must copy:\n%s", trusttest.SigTag(d), errOut.String())
	}
	if !strings.Contains(errOut.String(), "--allow-unsigned") {
		t.Errorf("stderr does not name the explicit way out:\n%s", errOut.String())
	}
	if _, err := os.Stat(dst + ".tmp"); !os.IsNotExist(err) {
		t.Error("an unsigned artifact was unpacked before it was refused (temp file exists)")
	}
	if _, err := os.Stat(dst + ".lock"); !os.IsNotExist(err) {
		t.Error("an unsigned artifact took the writer lock before it was refused (lock file exists)")
	}
	after, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("the live database is gone: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Error("a refused pull modified the live database")
	}
}

// The common case: signed by a trusted key, installed, and the record says
// which key -- so a report's provenance and `db status` can name it.
func TestPull_InstallsASignedArtifactAndRecordsTheKey(t *testing.T) {
	ref := published(t, store.SchemaVersion)
	dst := filepath.Join(t.TempDir(), "vulnerability.db")

	var out, errOut bytes.Buffer
	if code := Pull(context.Background(), dst, ref, false, &out, &errOut); code != 0 {
		t.Fatalf("Pull = %d, want 0 (stderr: %s)", code, errOut.String())
	}
	rec := artifactOf(t, dst)
	if want := testSigningPublicKey().ID; rec.SignedBy != want {
		t.Errorf("record SignedBy = %q, want the verifying key %q", rec.SignedBy, want)
	}
	if rec.Unverified {
		t.Error("record says Unverified on a pull that verified")
	}
	if strings.Contains(errOut.String(), "UNVERIFIED") {
		t.Errorf("a verified pull warned as if unverified:\n%s", errOut.String())
	}
}

// --allow-unsigned excuses an ABSENT signature, never a wrong one: a
// signature that exists and does not verify is evidence of tampering (or of
// a key this binary was not built to trust), and no flag installs that.
func TestPull_WrongKeyIsRefusedEvenWithAllowUnsigned(t *testing.T) {
	ref := publishedUnsignedFrom(t, pushable(t, time.Date(2026, 8, 3, 0, 0, 0, 0, time.UTC)), store.SchemaVersion, nil)
	r, d := hashOf(t, ref)
	trusttest.SignArtifact(t, trusttest.NewKey(t), r, d)
	dst := filepath.Join(t.TempDir(), "vulnerability.db")

	var out, errOut bytes.Buffer
	if code := Pull(context.Background(), dst, ref, true, &out, &errOut); code != 2 {
		t.Fatalf("Pull of a wrongly signed artifact with --allow-unsigned = %d, want 2 (stderr: %s)", code, errOut.String())
	}
	if !strings.Contains(errOut.String(), "does not verify") {
		t.Errorf("stderr does not say the signature does not verify:\n%s", errOut.String())
	}
	if strings.Contains(errOut.String(), "is not signed") {
		t.Errorf("a present, wrong signature was reported as absent:\n%s", errOut.String())
	}
	if _, err := os.Stat(dst); !os.IsNotExist(err) {
		t.Error("a wrongly signed artifact was installed")
	}
}

// The explicit opt-out: installed, warned about on stderr, and recorded as
// unverified so `db status` and every report's provenance say so.
func TestPull_AllowUnsignedInstallsAndMarksTheRecord(t *testing.T) {
	ref := publishedUnsignedFrom(t, pushable(t, time.Date(2026, 8, 3, 0, 0, 0, 0, time.UTC)), store.SchemaVersion, nil)
	dst := filepath.Join(t.TempDir(), "vulnerability.db")

	var out, errOut bytes.Buffer
	if code := Pull(context.Background(), dst, ref, true, &out, &errOut); code != 0 {
		t.Fatalf("Pull --allow-unsigned = %d, want 0 (stderr: %s)", code, errOut.String())
	}
	if !strings.Contains(errOut.String(), "WARNING") || !strings.Contains(errOut.String(), "UNVERIFIED") {
		t.Errorf("stderr does not warn that the install is unverified:\n%s", errOut.String())
	}
	rec := artifactOf(t, dst)
	if !rec.Unverified || rec.SignedBy != "" {
		t.Errorf("record = %+v, want Unverified with no SignedBy", rec)
	}
	var status, statusErr bytes.Buffer
	if code := Status(dst, &status, &statusErr); code != 0 {
		t.Fatalf("Status = %d (stderr: %s)", code, statusErr.String())
	}
	if !strings.Contains(status.String(), "signed:     NO") {
		t.Errorf("db status does not say the database is unverified:\n%s", status.String())
	}
}

// A registry that answers the signature fetch with an error is a transport
// failure, not "not signed": the two call for different actions (retry or
// fix auth, versus copy the tag or opt out), and a 403 reported as "not
// signed" would send an operator to --allow-unsigned for a problem the flag
// does not have. The registry serves the artifact and its signature until
// the pull starts, then refuses only the .sig tag.
func TestPull_TransportFailureOnTheSigTagIsNotNotSigned(t *testing.T) {
	var block atomic.Bool
	wrap := func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if block.Load() && strings.Contains(r.URL.Path, ".sig") {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			h.ServeHTTP(w, r)
		})
	}
	ref := publishedFrom(t, pushable(t, time.Date(2026, 8, 3, 0, 0, 0, 0, time.UTC)), store.SchemaVersion, wrap)
	block.Store(true)

	// With the flag too: --allow-unsigned excuses an absent signature, and
	// a 403 is not evidence of absence. A CI job carrying the flag for a
	// mirror must not have an expired token quietly downgrade every pull
	// to unverified.
	for _, allow := range []bool{false, true} {
		dst := filepath.Join(t.TempDir(), "vulnerability.db")
		var out, errOut bytes.Buffer
		if code := Pull(context.Background(), dst, ref, allow, &out, &errOut); code != 2 {
			t.Fatalf("allowUnsigned=%v: Pull with the signature fetch refused = %d, want 2 (stderr: %s)", allow, code, errOut.String())
		}
		if !strings.Contains(errOut.String(), "403") {
			t.Errorf("allowUnsigned=%v: stderr does not carry the registry's status:\n%s", allow, errOut.String())
		}
		if strings.Contains(errOut.String(), "is not signed") || strings.Contains(errOut.String(), "UNVERIFIED") {
			t.Errorf("allowUnsigned=%v: a transport failure was reported as an unsigned artifact:\n%s", allow, errOut.String())
		}
		if _, err := os.Stat(dst); !os.IsNotExist(err) {
			t.Errorf("allowUnsigned=%v: a pull whose signature could not be fetched installed a database", allow)
		}
	}
}

// A mirror that answers the missing .sig tag with a 404 its own way (no
// MANIFEST_UNKNOWN code: Harbor, a proxy) is a mirror without the
// signature, so the documented way out works there too.
func TestPull_AllowUnsignedWorksOnAMirrorWhose404CarriesNoSpecCode(t *testing.T) {
	var block atomic.Bool
	wrap := func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if block.Load() && strings.Contains(r.URL.Path, ".sig") {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"errors":[{"code":"NOT_FOUND","message":"artifact not found"}]}`))
				return
			}
			h.ServeHTTP(w, r)
		})
	}
	ref := publishedUnsignedFrom(t, pushable(t, time.Date(2026, 8, 3, 0, 0, 0, 0, time.UTC)), store.SchemaVersion, wrap)
	block.Store(true)
	dst := filepath.Join(t.TempDir(), "vulnerability.db")

	var out, errOut bytes.Buffer
	if code := Pull(context.Background(), dst, ref, false, &out, &errOut); code != 2 || !strings.Contains(errOut.String(), "is not signed") {
		t.Fatalf("without the flag: Pull = %d, want 2 with 'is not signed' (stderr: %s)", code, errOut.String())
	}
	out.Reset()
	errOut.Reset()
	if code := Pull(context.Background(), dst, ref, true, &out, &errOut); code != 0 {
		t.Fatalf("with --allow-unsigned: Pull = %d, want 0 (stderr: %s)", code, errOut.String())
	}
	if rec := artifactOf(t, dst); !rec.Unverified {
		t.Errorf("record = %+v, want Unverified", rec)
	}
}

// A flag left in a script after an outage does not mark a signed artifact
// unverified: the record says what was found, not what was permitted.
func TestPull_AllowUnsignedOnASignedArtifactRecordsTheKey(t *testing.T) {
	ref := published(t, store.SchemaVersion)
	dst := filepath.Join(t.TempDir(), "vulnerability.db")

	var out, errOut bytes.Buffer
	if code := Pull(context.Background(), dst, ref, true, &out, &errOut); code != 0 {
		t.Fatalf("Pull --allow-unsigned of a signed artifact = %d, want 0 (stderr: %s)", code, errOut.String())
	}
	rec := artifactOf(t, dst)
	if rec.SignedBy != testSigningPublicKey().ID || rec.Unverified {
		t.Errorf("record = %+v, want SignedBy %s and not Unverified", rec, testSigningPublicKey().ID)
	}
	if strings.Contains(errOut.String(), "UNVERIFIED") {
		t.Errorf("a verified pull warned as unverified:\n%s", errOut.String())
	}
}

// A --seed input is verified exactly as a pull is, and there is no flag to
// opt out: the nightly builder is the one caller, and a builder seeded from
// an unsigned database would publish -- and sign -- whatever it was fed.
func TestPullSeed_RefusesAnUnsignedSeed(t *testing.T) {
	host := registryHost(t)
	curRef := fmt.Sprintf("%s/assay-db:v%d", host, store.SchemaVersion)
	var out, errOut bytes.Buffer
	if code := Push(context.Background(), bounded(t, time.Time{}, 5), curRef, false, &out, &errOut); code != 0 {
		t.Fatalf("seeding the registry failed: %d (%s)", code, errOut.String())
	}
	_, d := hashOf(t, curRef)

	dst := filepath.Join(t.TempDir(), "seed.db")
	out.Reset()
	errOut.Reset()
	if code := PullSeed(context.Background(), dst, curRef, &out, &errOut); code != 2 {
		t.Fatalf("PullSeed of an unsigned seed = %d, want 2 (stderr: %s)", code, errOut.String())
	}
	if !strings.Contains(errOut.String(), "is not signed") || !strings.Contains(errOut.String(), trusttest.SigTag(d)) {
		t.Errorf("stderr does not say the seed is unsigned and name its signature tag:\n%s", errOut.String())
	}
	if strings.Contains(errOut.String(), "--allow-unsigned") {
		t.Errorf("stderr offers a flag db build --seed does not have:\n%s", errOut.String())
	}
	for _, p := range []string{dst, dst + ".tmp"} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("%s exists after a refused seed pull", p)
		}
	}
}

func TestPullSeed_AcceptsASignedSeed(t *testing.T) {
	host := registryHost(t)
	curRef := fmt.Sprintf("%s/assay-db:v%d", host, store.SchemaVersion)
	seed(t, curRef, time.Time{}, 5)

	dst := filepath.Join(t.TempDir(), "seed.db")
	var out, errOut bytes.Buffer
	if code := PullSeed(context.Background(), dst, curRef, &out, &errOut); code != 0 {
		t.Fatalf("PullSeed of a signed seed = %d, want 0 (stderr: %s)", code, errOut.String())
	}
	db, err := store.Open(dst)
	if err != nil {
		t.Fatalf("the pulled seed does not open: %v", err)
	}
	db.Close()
}
