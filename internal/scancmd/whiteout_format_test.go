package scancmd

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

// Release review of v0.18.0 (2026-11-12): one image, one verdict, whatever
// archive delivers it. PR #295 had keyed the same-layer whiteout order on the
// layer's media type (OCI: the layer's own entry survives its whiteout;
// Docker: the whiteout after the entry removes it), and go-containerregistry's
// tarball reader reports every docker-archive layer as a Docker layer whatever
// the image's manifest said -- so an OCI-typed image (buildkit's default)
// read exit 0 through `oci-dir:` and exit 2 through `docker-archive:` of the
// identical bytes. The rule is one for every layer, and it is the OCI image
// spec's (v0.18.1, after the independent review of 2026-11-12): a whiteout
// hides lower layers only, so this layer's own entry before the marker
// stands -- what syft, grype, trivy, umoci and go-containerregistry's
// extract do, while the runtimes' production paths (moby overlay2,
// containerd's overlay applier) refuse to apply such a layer at all. Goes
// red when the walk consults the media type again on either path, or deletes
// the layer's own entry again.
func TestRun_OneImageOneVerdictWhateverArchiveDeliversIt(t *testing.T) {
	isolateCredentials(t)
	db := layerDigestDB(t)
	for _, tc := range []struct {
		name  string
		upper []p4Entry
		code  int
		want  string // on stderr for exit 2, in stdout for exit 1
	}{
		{
			// The upper layer writes a patched database, then whiteouts it:
			// the layer's own database stands and the base layer's
			// vulnerable copy beneath stays hidden -- one package, clean.
			name:  "database then its whiteout in one layer",
			upper: []p4Entry{{name: apkDBPath, body: p4ApkPatched}, {name: "lib/apk/db/.wh.installed"}},
			code:  0, want: "1 component(s) seen, 1 evaluated, 0 finding(s)",
		},
		{
			// The whiteout alone: the base layer's database is hidden and
			// nothing replaces it, so there is no database to judge.
			name:  "whiteout alone in the upper layer",
			upper: []p4Entry{{name: "lib/apk/db/.wh.installed"}},
			code:  2, want: "no supported package database",
		},
		{
			// Control: the whiteout before the entry is overwritten by it.
			name:  "whiteout then database in one layer",
			upper: []p4Entry{{name: "lib/apk/db/.wh.installed"}, {name: apkDBPath, body: p4ApkVulnerable}},
			code:  1, want: "busybox-binsh (busybox)  1.36.1-r05",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := p4Tar(t, p4Entry{name: osReleasePath, body: osReleaseAlpine319}, p4Entry{name: apkDBPath, body: p4ApkVulnerable})
			upper := p4Tar(t, tc.upper...)
			img, err := mutate.AppendLayers(empty.Image,
				static.NewLayer(base, types.OCIUncompressedLayer),
				static.NewLayer(upper, types.OCIUncompressedLayer))
			if err != nil {
				t.Fatal(err)
			}
			cf, err := img.ConfigFile()
			if err != nil {
				t.Fatal(err)
			}
			cf.OS, cf.Architecture = "linux", runtime.GOARCH
			if img, err = mutate.ConfigFile(img, cf); err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			tarPath := filepath.Join(dir, "image.tar")
			ref, err := name.ParseReference("scancmd-whiteout:latest")
			if err != nil {
				t.Fatal(err)
			}
			if err := tarball.WriteToFile(tarPath, ref, img); err != nil {
				t.Fatal(err)
			}
			layoutDir := filepath.Join(dir, "layout")
			lp, err := layout.Write(layoutDir, empty.Index)
			if err != nil {
				t.Fatal(err)
			}
			if err := lp.AppendImage(img); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(filepath.Join(layoutDir, "index.json")); err != nil {
				t.Fatal(err)
			}
			codes := map[string]int{}
			for _, target := range []string{"docker-archive:" + tarPath, "oci-dir:" + layoutDir} {
				out, errOut, code := scanFailOnLow(t, db, target)
				codes[target] = code
				where := out
				if tc.code == 2 {
					where = errOut
				}
				if code != tc.code || !strings.Contains(where, tc.want) {
					t.Errorf("%s: Run = %d, want %d with %q\nstdout: %s\nstderr: %s", target, code, tc.code, tc.want, out, errOut)
				}
			}
			if codes["docker-archive:"+tarPath] != codes["oci-dir:"+layoutDir] {
				t.Errorf("one image, two verdicts: %v", codes)
			}
		})
	}
}
