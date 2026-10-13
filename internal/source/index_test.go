package source

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

// D119 review fixes: what the index walk does with a platform-less entry it
// cannot read, and the single-image check's normalisation, ladder and
// descriptor fallback. The callers are held in internal/scancmd's
// platform_test.go; these reach the branches directly.

// A platform-less entry whose image or config cannot be read is skipped, as it
// was before D119. The walk now reads the whole tree before choosing, so
// returning the error let one broken entry sink an index that holds the exact
// match.
func TestImageFromIndex_UnreadablePlatformlessEntryIsSkipped(t *testing.T) {
	bad := strings.Repeat("d", 64)
	readErr := errors.New("blob sha256:dddd not found")
	for _, tc := range []struct {
		name string
		idx  fakeIndex
	}{
		{"Image fails", fakeIndex{imageErrs: map[string]error{bad: readErr}}},
		{"ConfigFile fails", fakeIndex{images: map[string]v1.Image{bad: configImage{err: readErr}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			idx := tc.idx
			idx.platforms = []string{"linux/amd64", "linux/riscv64"}
			idx.noPlatform = []string{bad}
			_, choice, err := imageFromIndex(idx, "layout", v1.Hash{}, plat("linux/riscv64"), true)
			if err != nil {
				t.Fatalf("imageFromIndex: %v — one unreadable entry refused an index holding the exact match", err)
			}
			if choice.Platform != "linux/riscv64" || choice.Match != MatchExact {
				t.Errorf("choice = %+v, want linux/riscv64 exact", choice)
			}
		})
	}
}

// ...but a registry's 401 or 403 is not an unreadable entry. Skipping it
// turns a refusal into "has no image", naming the wrong problem (D118).
func TestImageFromIndex_PlatformlessRefusalIsReturned(t *testing.T) {
	bad := strings.Repeat("e", 64)
	for _, tc := range []struct {
		name   string
		status int
		build  func(error) fakeIndex
	}{
		{"Image 401", http.StatusUnauthorized, func(e error) fakeIndex {
			return fakeIndex{imageErrs: map[string]error{bad: e}}
		}},
		{"ConfigFile 403", http.StatusForbidden, func(e error) fakeIndex {
			return fakeIndex{images: map[string]v1.Image{bad: configImage{err: e}}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			te := &transport.Error{StatusCode: tc.status}
			// Wrapped, as go-containerregistry's own callers may wrap it: the
			// test is errors.As, not a type switch on the top error.
			idx := tc.build(fmt.Errorf("fetch child: %w", te))
			idx.platforms = []string{"linux/riscv64"}
			idx.noPlatform = []string{bad}
			_, _, err := imageFromIndex(idx, "registry", v1.Hash{}, plat("linux/riscv64"), true)
			if !errors.Is(err, te) {
				t.Fatalf("err = %v, want the %d refusal returned", err, tc.status)
			}
		})
	}
}

// An index whose only entries are unreadable names the read failure, not a
// platform miss: "contains no image for any platform" would be untrue.
func TestImageFromIndex_NothingReadableNamesTheReadError(t *testing.T) {
	bad := strings.Repeat("f", 64)
	readErr := errors.New("blob not found")
	idx := fakeIndex{noPlatform: []string{bad}, imageErrs: map[string]error{bad: readErr}}
	_, _, err := imageFromIndex(idx, "layout", v1.Hash{}, plat("linux/riscv64"), true)
	if !errors.Is(err, readErr) {
		t.Fatalf("err = %v, want the read error", err)
	}
	var pe *platformError
	if errors.As(err, &pe) {
		t.Errorf("err %q is a platform miss; nothing was readable to miss", err)
	}
	if !strings.Contains(err.Error(), "entry sha256:"+bad+": ") {
		t.Errorf("err %q does not name the entry", err)
	}
}

// A miss with entries skipped says so, so "it offers X" is not read as the
// whole index.
func TestImageFromIndex_MissNotesSkippedEntries(t *testing.T) {
	bad := strings.Repeat("a", 64)
	idx := fakeIndex{
		platforms:  []string{"linux/amd64"},
		noPlatform: []string{bad},
		imageErrs:  map[string]error{bad: errors.New("blob not found")},
	}
	_, _, err := imageFromIndex(idx, "layout", v1.Hash{}, plat("linux/riscv64"), true)
	want := "layout has no linux/riscv64 image; it offers linux/amd64 (entry sha256:" + bad +
		" could not be read: blob not found)"
	if err == nil || err.Error() != want {
		t.Errorf("err = %v\nwant %s", err, want)
	}
}

// The layout the review reproduced: a linux/amd64 image with a platform on its
// descriptor, plus a platform-less entry whose config blob is not JSON. Both
// with --platform and on the host default, the good entry is scanned.
func TestOpen_LayoutWithAnUnreadableEntrySelectsTheGoodOne(t *testing.T) {
	setHostPlatform(t, "linux/amd64")
	dir := filepath.Join(t.TempDir(), "layout")
	lp, err := layout.Write(dir, empty.Index)
	if err != nil {
		t.Fatal(err)
	}
	good := platformImage(t, plat("linux/amd64"))
	if err := lp.AppendImage(good, layout.WithPlatform(plat("linux/amd64"))); err != nil {
		t.Fatal(err)
	}
	goodDigest, err := good.Digest()
	if err != nil {
		t.Fatal(err)
	}

	cfg := []byte("not json at all")
	cfgHash := writeBlob(t, lp, cfg)
	manifest := []byte(fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,"config":{"mediaType":%q,"digest":%q,"size":%d},"layers":[]}`,
		types.OCIManifestSchema1, types.OCIConfigJSON, cfgHash, len(cfg)))
	mHash := writeBlob(t, lp, manifest)
	if err := lp.AppendDescriptor(v1.Descriptor{
		MediaType: types.OCIManifestSchema1, Digest: mHash, Size: int64(len(manifest)),
	}); err != nil {
		t.Fatal(err)
	}

	for _, p := range []string{"linux/amd64", ""} {
		img, err := Open(context.Background(), "oci-dir:"+dir, p)
		if err != nil {
			t.Fatalf("--platform %q: Open: %v", p, err)
		}
		if img.Platform.ManifestDigest != goodDigest.String() || img.Platform.Match != MatchExact {
			t.Errorf("--platform %q: chose %+v, want %s exact", p, img.Platform, goodDigest)
		}
	}
}

// checkSingle's own branches: the candidate is normalised before comparing,
// the compatibility ladder applies to a single image as to an index, and a
// config naming no platform falls back to the descriptor's.
func TestCheckSingle(t *testing.T) {
	arm64 := &v1.Platform{OS: "linux", Architecture: "arm64"}
	for _, tc := range []struct {
		name     string
		cfg      configImage
		desc     *v1.Platform
		want     string
		explicit bool
		// wantPlat and wantMatch are the choice; wantErr, when set, is the
		// refusal instead.
		wantPlat, wantMatch, wantErr string
	}{
		{name: "arm64/v8 config is arm64", cfg: configImage{os: "linux", arch: "arm64", variant: "v8"},
			want: "linux/arm64", explicit: true, wantPlat: "linux/arm64", wantMatch: MatchExact},
		{name: "aarch64 config is arm64", cfg: configImage{os: "linux", arch: "aarch64"},
			want: "linux/arm64", explicit: true, wantPlat: "linux/arm64", wantMatch: MatchExact},
		{name: "x86_64 config is amd64", cfg: configImage{os: "linux", arch: "x86_64"},
			want: "linux/amd64", explicit: true, wantPlat: "linux/amd64", wantMatch: MatchExact},
		{name: "arm/v6 image for an arm/v7 request is compatible", cfg: configImage{os: "linux", arch: "arm", variant: "v6"},
			want: "linux/arm/v7", explicit: true, wantPlat: "linux/arm/v6", wantMatch: MatchCompatible},
		{name: "the ladder never climbs", cfg: configImage{os: "linux", arch: "arm", variant: "v7"},
			want: "linux/arm/v6", explicit: true, wantErr: "x is a single linux/arm/v7 image; --platform asked for linux/arm/v6"},
		{name: "empty config falls back to the descriptor: match", cfg: configImage{}, desc: arm64,
			want: "linux/arm64", explicit: true, wantPlat: "linux/arm64", wantMatch: MatchExact},
		{name: "empty config falls back to the descriptor: refusal", cfg: configImage{}, desc: arm64,
			want: "linux/amd64", explicit: true, wantErr: "x is a single linux/arm64 image; --platform asked for linux/amd64"},
		{name: "empty config falls back to the descriptor: mismatch on default", cfg: configImage{}, desc: arm64,
			want: "linux/amd64", wantPlat: "linux/arm64", wantMatch: MatchMismatch},
		{name: "empty config and no descriptor is unchecked", cfg: configImage{},
			want: "linux/amd64", explicit: true, wantPlat: "", wantMatch: MatchUnchecked},
	} {
		t.Run(tc.name, func(t *testing.T) {
			choice, err := checkSingle(tc.cfg, tc.desc, "x", v1.Hash{}, normalizePlatform(plat(tc.want)), tc.explicit)
			if tc.wantErr != "" {
				if err == nil || err.Error() != tc.wantErr {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("checkSingle: %v", err)
			}
			if choice.Platform != tc.wantPlat || choice.Match != tc.wantMatch {
				t.Errorf("choice = {Platform %q, Match %q}, want {%q, %q}",
					choice.Platform, choice.Match, tc.wantPlat, tc.wantMatch)
			}
		})
	}
}

func plat(s string) v1.Platform {
	parts := strings.Split(s, "/")
	p := v1.Platform{OS: parts[0], Architecture: parts[1]}
	if len(parts) == 3 {
		p.Variant = parts[2]
	}
	return p
}

// setHostPlatform points HostPlatform at p for one test.
func setHostPlatform(t *testing.T, p string) {
	t.Helper()
	orig := HostPlatform
	HostPlatform = func() v1.Platform { return plat(p) }
	t.Cleanup(func() { HostPlatform = orig })
}

// platformImage is a random one-layer image whose config says p.
func platformImage(t *testing.T, p v1.Platform) v1.Image {
	t.Helper()
	img, err := random.Image(64, 1)
	if err != nil {
		t.Fatal(err)
	}
	cf, err := img.ConfigFile()
	if err != nil {
		t.Fatal(err)
	}
	cf = cf.DeepCopy()
	cf.OS, cf.Architecture, cf.Variant = p.OS, p.Architecture, p.Variant
	if img, err = mutate.ConfigFile(img, cf); err != nil {
		t.Fatal(err)
	}
	return img
}

func writeBlob(t *testing.T, lp layout.Path, b []byte) v1.Hash {
	t.Helper()
	h, _, err := v1.SHA256(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	if err := lp.WriteBlob(h, io.NopCloser(bytes.NewReader(b))); err != nil {
		t.Fatal(err)
	}
	return h
}
