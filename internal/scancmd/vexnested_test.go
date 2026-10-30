package scancmd

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/mutate"

	"github.com/kun9497/assay/internal/report"
)

// nestedVEXIndex is an outer index holding two inner indexes: one listing the
// image this host scans, and a sibling listing an image for another
// platform. It returns the outer index and the digests a statement can name.
// With described false the inner descriptors carry no platform, as
// layout.Write leaves them, so the image is judged by its config instead.
func nestedVEXIndex(t *testing.T, described bool) (outer v1.ImageIndex, digests map[string]string) {
	t.Helper()
	img := vexRegistryImage(t, map[string]string{osReleasePath: osReleaseAlpine319, apkDBPath: apkThreePackages})
	cf, err := img.ConfigFile()
	if err != nil {
		t.Fatal(err)
	}
	p := v1.Platform{OS: cf.OS, Architecture: cf.Architecture}
	setHost(t, p.OS+"/"+p.Architecture)

	other, err := mutate.ConfigFile(img, func() *v1.ConfigFile {
		c := cf.DeepCopy()
		c.Architecture = "riscv64"
		return c
	}())
	if err != nil {
		t.Fatal(err)
	}
	op := v1.Platform{OS: "linux", Architecture: "riscv64"}

	desc := func(p *v1.Platform) v1.Descriptor {
		if !described {
			return v1.Descriptor{}
		}
		return v1.Descriptor{Platform: p}
	}
	inner := mutate.AppendManifests(empty.Index, mutate.IndexAddendum{Add: img, Descriptor: desc(&p)})
	sibling := mutate.AppendManifests(empty.Index, mutate.IndexAddendum{Add: other, Descriptor: desc(&op)})
	outer = mutate.AppendManifests(empty.Index, mutate.IndexAddendum{Add: inner}, mutate.IndexAddendum{Add: sibling})
	return outer, map[string]string{
		"outer":          digestOf(t, outer),
		"inner":          digestOf(t, inner),
		"manifest":       digestOf(t, img),
		"sibling":        digestOf(t, sibling),
		"other platform": digestOf(t, other),
		"unrelated":      "sha256:" + string(bytes.Repeat([]byte("f"), 64)),
	}
}

// QA 2026-10-30: a VEX statement naming the index a nested image was pulled
// through applied only when it named the manifest or the index that listed
// it. The outer index -- the digest `docker buildx imagetools` prints, and
// the one a registry reference by digest names -- was dropped while the
// tree was walked, so the statement was skipped and the finding stood. The
// controls hold scope where D121 put it: a sibling index, an image for
// another platform and an unrelated digest are not this image.
func TestRun_QA1030_VEXNamingAnOuterIndexAppliesToTheImageItLists(t *testing.T) {
	want := map[string]bool{
		"outer": true, "inner": true, "manifest": true,
		"sibling": false, "other platform": false, "unrelated": false,
	}
	check := func(t *testing.T, target, named, digest string) {
		t.Helper()
		db := vexDB(t, "Alpine:v3.19", vexAdv{"ALPINE-2031-0002", "CVE-2031-9002", "openssl", "3.1.4-r99"})
		vexPath := writeVEX(t, stmt("CVE-2031-9002", product("pkg:oci/alpine@"+digest, libssl3PURL)))
		var out, errOut bytes.Buffer
		code := Run(context.Background(), db, target, Options{Output: "json", FailOnUnknown: true, VEXFiles: []string{vexPath}}, &out, &errOut)
		var doc report.Document
		if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
			t.Fatalf("decode: %v\nstderr: %s", err, errOut.String())
		}
		applied := code == 0 && len(doc.Suppressed) == 1 && len(doc.Findings) == 0
		kept := code == 1 && len(doc.Suppressed) == 0 && len(doc.Findings) == 1
		if want[named] && !applied {
			t.Errorf("statement naming the %s (%s): exit %d, %d finding(s), %d suppressed; want it applied\nstderr: %s",
				named, digest, code, len(doc.Findings), len(doc.Suppressed), errOut.String())
		}
		if !want[named] && !kept {
			t.Errorf("statement naming the %s (%s): exit %d, %d finding(s), %d suppressed; want the finding kept",
				named, digest, code, len(doc.Findings), len(doc.Suppressed))
		}
	}

	t.Run("oci-dir", func(t *testing.T) {
		outer, digests := nestedVEXIndex(t, false)
		dir := filepath.Join(t.TempDir(), "layout")
		lp, err := layout.Write(dir, empty.Index)
		if err != nil {
			t.Fatal(err)
		}
		if err := lp.AppendIndex(outer); err != nil {
			t.Fatal(err)
		}
		for named, digest := range digests {
			t.Run(named, func(t *testing.T) { check(t, "oci-dir:"+dir, named, digest) })
		}
	})
	t.Run("registry", func(t *testing.T) {
		isolateCredentials(t)
		ar := openRegistry(t)
		outer, digests := nestedVEXIndex(t, true)
		pushIndex(t, ar.host, "nested:current", outer)
		for _, target := range []string{ar.host + "/nested@" + digests["outer"], ar.host + "/nested:current"} {
			for named, digest := range digests {
				t.Run(target[len(ar.host):]+"/"+named, func(t *testing.T) { check(t, target, named, digest) })
			}
		}
	})
}
