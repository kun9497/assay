package dbcmd

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/provider"
	"github.com/kun9497/assay/internal/store"
)

// D120/D127: `db update` records what it pulled IN the database it installs,
// so a scan reads the record and the database it names in one open; `db build`
// writes a fresh Meta, so a built database is never named as a pulled one. The
// pre-D127 sidecar is removed wherever it is found and read by nothing.

// artifactOf opens the database at path and returns its Meta.Artifact.
func artifactOf(t *testing.T, path string) *store.ArtifactRecord {
	t.Helper()
	db, err := store.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer db.Close()
	m, err := db.Meta()
	if err != nil {
		t.Fatal(err)
	}
	return m.Artifact
}

func digestOf(t *testing.T, ref string) (name.Reference, string) {
	t.Helper()
	r, err := name.ParseReference(ref)
	if err != nil {
		t.Fatal(err)
	}
	img, err := remote.Image(r)
	if err != nil {
		t.Fatal(err)
	}
	d, err := img.Digest()
	if err != nil {
		t.Fatal(err)
	}
	return r, d.String()
}

func TestPull_RecordsTheArtifactInTheDatabaseItInstalled(t *testing.T) {
	ref := published(t, store.SchemaVersion)
	dst := filepath.Join(t.TempDir(), "vulnerability.db")
	// A previous, pre-D127 pull's sidecar: never read again, and not left
	// behind to be mistaken for current.
	legacy := store.LegacyArtifactRecordPath(dst)
	if err := os.WriteFile(legacy, []byte(`{"reference":"old","digest":"sha256:old"}`), 0o644); err != nil {
		t.Fatal(err)
	}

	before := time.Now().UTC().Add(-time.Second)
	var out, errOut bytes.Buffer
	if code := Pull(context.Background(), dst, ref, &out, &errOut); code != 0 {
		t.Fatalf("Pull = %d, want 0 (stderr: %s)", code, errOut.String())
	}
	rec := artifactOf(t, dst)
	if rec == nil {
		t.Fatal("the installed database carries no artifact record")
	}
	r, want := digestOf(t, ref)
	if rec.Digest != want {
		t.Errorf("record digest = %s, want the manifest digest %s", rec.Digest, want)
	}
	if rec.Reference != r.String() {
		t.Errorf("record reference = %q, want %q", rec.Reference, r.String())
	}
	if rec.PulledAt.Before(before) {
		t.Errorf("record pulledAt = %v, want this pull's time", rec.PulledAt)
	}
	if _, err := os.Stat(legacy); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the legacy sidecar survived the pull (stat err = %v)", err)
	}
}

// The record is written into the temp database BEFORE the install rename, not
// into the live one after it: the install-failure message tells the user to
// move the temp file into place by hand, and that file must already name its
// own artifact. This is the window the sidecar left open (external review #7):
// a database installed without its record, or with the previous pull's.
func TestPull_TheTempDatabaseCarriesItsRecordBeforeInstall(t *testing.T) {
	ref := published(t, store.SchemaVersion)
	dst := filepath.Join(t.TempDir(), "vulnerability.db")
	saved := renameFn
	renameFn = func(_, _ string) error { return errors.New("forced: database busy") }
	t.Cleanup(func() { renameFn = saved })

	var out, errOut bytes.Buffer
	if code := Pull(context.Background(), dst, ref, &out, &errOut); code != 2 {
		t.Fatalf("Pull = %d, want 2 when the install rename fails (stderr: %s)", code, errOut.String())
	}
	if _, err := os.Stat(dst); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a database was installed although the rename failed (stat err = %v)", err)
	}
	tmp := dst + ".tmp"
	rec := artifactOf(t, tmp)
	if rec == nil {
		t.Fatalf("the complete database left at %s carries no artifact record; moved into place by hand it would name no artifact, or the previous pull's", tmp)
	}
	if _, want := digestOf(t, ref); rec.Digest != want {
		t.Errorf("temp database's record digest = %s, want %s", rec.Digest, want)
	}
}

// A pull refused for its schema installs nothing, so the database in place
// keeps naming the artifact it actually came from.
func TestPull_ARefusedPullLeavesTheInstalledRecordAlone(t *testing.T) {
	dst := filepath.Join(t.TempDir(), "vulnerability.db")
	var out, errOut bytes.Buffer
	first := published(t, store.SchemaVersion)
	if code := Pull(context.Background(), dst, first, &out, &errOut); code != 0 {
		t.Fatalf("first Pull = %d, want 0 (stderr: %s)", code, errOut.String())
	}
	_, want := digestOf(t, first)

	refused := published(t, store.SchemaVersion+1)
	if code := Pull(context.Background(), dst, refused, &out, &errOut); code != 2 {
		t.Fatalf("refused Pull = %d, want 2", code)
	}
	if rec := artifactOf(t, dst); rec == nil || rec.Digest != want {
		t.Errorf("record after a refused pull = %+v, want the first pull's %s", rec, want)
	}
}

func TestUpdate_ABuiltDatabaseNamesNoArtifact(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vulnerability.db")
	// The database being replaced was pulled: its record, and a legacy
	// sidecar beside it, must both be gone once the build has replaced it.
	if code := Pull(context.Background(), path, published(t, store.SchemaVersion), &bytes.Buffer{}, &bytes.Buffer{}); code != 0 {
		t.Fatalf("Pull = %d, want 0", code)
	}
	if artifactOf(t, path) == nil {
		t.Fatal("precondition: the pulled database names its artifact")
	}
	legacy := store.LegacyArtifactRecordPath(path)
	if err := os.WriteFile(legacy, []byte(`{"reference":"r","digest":"sha256:pulled"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	p := fakeProvider{name: "osv", covers: []string{"Go"}, advs: []advisory.Advisory{{
		ID: "GHSA-x", Database: "GHSA", Source: "osv", Kind: advisory.KindVulnerability,
		Affected: []advisory.Affected{{Ecosystem: "Go", Name: "github.com/a/b"}},
	}}}
	var out, errOut bytes.Buffer
	if code := Update(context.Background(), path, "", "", false, []provider.Provider{p}, nil, nil, nil, &out, &errOut); code != 0 {
		t.Fatalf("Update = %d, want 0 (stderr: %s)", code, errOut.String())
	}
	if rec := artifactOf(t, path); rec != nil {
		t.Errorf("a built database names an artifact: %+v", rec)
	}
	if _, err := os.Stat(legacy); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("legacy sidecar survived db build (stat err = %v): a built database would be named as the pulled one", err)
	}
}
