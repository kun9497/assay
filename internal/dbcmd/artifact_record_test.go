package dbcmd

import (
	"bytes"
	"context"
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

// D120: `db update` records what it pulled beside the database, so a scan can
// name the artifact; `db build` removes the record, so a built database is
// never named as a pulled one.

func TestPull_RecordsTheArtifactItInstalled(t *testing.T) {
	ref := published(t, store.SchemaVersion)
	dst := filepath.Join(t.TempDir(), "vulnerability.db")
	// A previous pull's record, which this pull must replace.
	if err := store.WriteArtifactRecord(dst, store.ArtifactRecord{Reference: "old", Digest: "sha256:old"}); err != nil {
		t.Fatal(err)
	}

	before := time.Now().UTC().Add(-time.Second)
	var out, errOut bytes.Buffer
	if code := Pull(context.Background(), dst, ref, &out, &errOut); code != 0 {
		t.Fatalf("Pull = %d, want 0 (stderr: %s)", code, errOut.String())
	}
	rec, ok, err := store.ReadArtifactRecord(dst)
	if err != nil || !ok {
		t.Fatalf("no artifact record after a pull: ok=%v err=%v", ok, err)
	}
	r, err := name.ParseReference(ref)
	if err != nil {
		t.Fatal(err)
	}
	img, err := remote.Image(r)
	if err != nil {
		t.Fatal(err)
	}
	want, err := img.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if rec.Digest != want.String() {
		t.Errorf("record digest = %s, want the manifest digest %s", rec.Digest, want)
	}
	if rec.Reference != r.String() {
		t.Errorf("record reference = %q, want %q", rec.Reference, r.String())
	}
	if rec.PulledAt.Before(before) {
		t.Errorf("record pulledAt = %v, want this pull's time", rec.PulledAt)
	}
}

// A pull refused for its schema installs nothing, so it must leave the
// existing record — which still names the database in place — alone.
func TestPull_ARefusedPullLeavesTheRecordAlone(t *testing.T) {
	ref := published(t, store.SchemaVersion+1)
	dst := filepath.Join(t.TempDir(), "vulnerability.db")
	old := store.ArtifactRecord{Reference: "old", Digest: "sha256:old"}
	if err := store.WriteArtifactRecord(dst, old); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := Pull(context.Background(), dst, ref, &out, &errOut); code != 2 {
		t.Fatalf("Pull = %d, want 2", code)
	}
	if rec, ok, _ := store.ReadArtifactRecord(dst); !ok || rec.Digest != old.Digest {
		t.Errorf("record after a refused pull = %+v (ok=%v), want the old one", rec, ok)
	}
}

func TestUpdate_RemovesAPulledDatabasesArtifactRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vulnerability.db")
	if err := store.WriteArtifactRecord(path, store.ArtifactRecord{Reference: "r", Digest: "sha256:pulled"}); err != nil {
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
	if _, err := os.Stat(store.ArtifactRecordPath(path)); !os.IsNotExist(err) {
		t.Errorf("artifact record survived db build (stat err = %v): a built database would be named as the pulled one", err)
	}
}
