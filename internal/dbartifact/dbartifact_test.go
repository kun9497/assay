package dbartifact

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

func TestPackUnpack_RoundTripsTheExactBytes(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "vulnerability.db")
	// Deliberately not valid bolt: Pack must move bytes, not interpret
	// them. A Pack that understood the format could not round-trip a
	// database written by a newer schema.
	want := []byte("bolt-ish bytes \x00\x01\x02 and some repetition to compress")
	if err := os.WriteFile(src, want, 0o644); err != nil {
		t.Fatal(err)
	}

	m := Meta{
		SchemaVersion: 6,
		BuiltAt:       time.Date(2026, 8, 4, 6, 0, 0, 0, time.UTC),
		DataAsOf:      time.Date(2026, 8, 3, 0, 0, 0, 0, time.UTC),
	}
	img, err := Pack(src, m)
	if err != nil {
		t.Fatal(err)
	}

	dst := filepath.Join(dir, "out.db")
	if err := Unpack(img, dst); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Errorf("round trip changed the bytes:\n got %q\nwant %q", got, want)
	}
}

// The metadata must be readable from the MANIFEST, without pulling the
// layer: a schema mismatch is the common case for an out-of-date client,
// and discovering it after a 60 MB download is the wrong order.
func TestMetaOf_ReadsAnnotationsWithoutTheLayer(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "vulnerability.db")
	if err := os.WriteFile(src, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	want := Meta{
		SchemaVersion: 6,
		BuiltAt:       time.Date(2026, 8, 4, 6, 0, 0, 0, time.UTC),
		DataAsOf:      time.Date(2026, 8, 3, 0, 0, 0, 0, time.UTC),
	}
	img, err := Pack(src, want)
	if err != nil {
		t.Fatal(err)
	}

	got, err := MetaOf(img)
	if err != nil {
		t.Fatal(err)
	}
	if got.SchemaVersion != want.SchemaVersion {
		t.Errorf("SchemaVersion = %d, want %d", got.SchemaVersion, want.SchemaVersion)
	}
	if !got.BuiltAt.Equal(want.BuiltAt) {
		t.Errorf("BuiltAt = %v, want %v", got.BuiltAt, want.BuiltAt)
	}
	// D12: freshness is the upstream timestamp, and it has to survive the
	// round trip separately from BuiltAt. A pulled database that reported
	// its pull time as its freshness would call a stale mirror current.
	if !got.DataAsOf.Equal(want.DataAsOf) {
		t.Errorf("DataAsOf = %v, want %v", got.DataAsOf, want.DataAsOf)
	}

	// And the annotations are on the manifest itself, reachable without
	// touching layer bytes.
	mf, err := img.Manifest()
	if err != nil {
		t.Fatal(err)
	}
	if mf.Annotations[AnnotationSchema] != strconv.Itoa(want.SchemaVersion) {
		t.Errorf("manifest annotations = %v, want %s to be %d",
			mf.Annotations, AnnotationSchema, want.SchemaVersion)
	}
}

// An image that is not one of ours must be refused by name rather than
// producing a corrupt database file. The failure mode this prevents is a
// scan running happily against garbage.
func TestUnpack_RejectsAnImageThatIsNotADatabase(t *testing.T) {
	img, err := mutate.Append(empty.Image, mutate.Addendum{
		Layer:     static.NewLayer([]byte("not a database"), types.OCILayer),
		MediaType: types.OCILayer,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = Unpack(img, filepath.Join(t.TempDir(), "out.db"))
	if err == nil {
		t.Fatal("Unpack accepted an image with no assay layer")
	}
	if !strings.Contains(err.Error(), MediaTypeLayer) {
		t.Errorf("error %q does not name the media type it wanted", err)
	}
}

// The source annotation is what GHCR reads to link a package to a repository,
// and that linkage is what lets the scheduled publish use GITHUB_TOKEN at all.
// Its absence cost two silent daily failures before anyone looked, so it is
// asserted on the manifest rather than assumed from the map literal.
func TestPack_CarriesTheSourceAnnotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vulnerability.db")
	if err := os.WriteFile(path, []byte("bolt-ish bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	img, err := Pack(path, Meta{SchemaVersion: 7})
	if err != nil {
		t.Fatal(err)
	}
	mf, err := img.Manifest()
	if err != nil {
		t.Fatal(err)
	}
	got, ok := mf.Annotations[AnnotationSource]
	if !ok {
		t.Fatalf("manifest carries no %s; GHCR cannot link the package and a workflow token cannot touch it", AnnotationSource)
	}
	// Derived from go.mod rather than compared against SourceRepo, which would
	// be circular — editing the constant would move both sides and the test
	// would stay green while the package linked to the wrong repository, which
	// is worse than no link because it looks correct on the package page.
	// Reading the module path also makes a repo rename fail here rather than
	// silently in a scheduled job.
	mod, err := os.ReadFile(filepath.Join("..", "..", "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	// Split on fields rather than on lines: a newline written into this file by
	// a generator script is the hazard CLAUDE.md records, and it bit this very
	// test once — the literal collapsed into a real newline, the file stopped
	// compiling, and four mutations reported "caught" when they had only broken
	// the build. Fields needs no escape at all.
	var modPath string
	fields := strings.Fields(string(mod))
	for i, f := range fields {
		if f == "module" && i+1 < len(fields) {
			modPath = fields[i+1]
			break
		}
	}
	if modPath == "" {
		t.Fatal("no module line in go.mod; this test cannot check what it claims to")
	}
	if want := "https://" + modPath; got != want {
		t.Errorf("%s = %q, want %q (derived from go.mod's module path)", AnnotationSource, got, want)
	}
	// The key must be the OCI standard one. A dev.assay.* spelling would be
	// carried faithfully and read by nobody.
	if AnnotationSource != "org.opencontainers.image.source" {
		t.Errorf("AnnotationSource = %q, want the OCI standard key", AnnotationSource)
	}
}
