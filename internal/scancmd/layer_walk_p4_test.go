package scancmd

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"

	"github.com/kun9497/assay/internal/severity"
	"github.com/kun9497/assay/internal/source"
)

// Audit 2026-10-22 P4, re-verified 2026-11-02: two ways the layer walk read a
// different filesystem from the one the container runs on, both silent.
//
// (A) A path written twice inside one layer tar is left on disk as its LAST
// entry by every extractor (docker's and containerd's untar, GNU tar), and the
// walk kept the FIRST.
//
// (B) A symlink chain was cut at seven links (eight passes, the final file
// costing one) where Linux follows forty, and a chain still pending at the cut
// -- or a cycle -- came back as an absent file: an image with no distro, or no
// package database, and nothing saying resolution stopped.

// p4Entry is one tar entry, in order. link makes it a symlink, or a hardlink
// with hard.
type p4Entry struct {
	name, body, link string
	hard             bool
}

func p4Tar(t *testing.T, es ...p4Entry) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range es {
		h := &tar.Header{Name: e.name, Mode: 0o644, Size: int64(len(e.body)), Typeflag: tar.TypeReg}
		if e.link != "" {
			kind := byte(tar.TypeSymlink)
			if e.hard {
				kind = tar.TypeLink
			}
			h = &tar.Header{Name: e.name, Mode: 0o777, Typeflag: kind, Linkname: e.link}
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if e.link == "" {
			if _, err := tw.Write([]byte(e.body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// p4Archive writes raw as the one layer of a docker-archive and returns the
// target, so Run reads it through the real image loader and walk.
func p4Archive(t *testing.T, raw []byte) string {
	t.Helper()
	layer, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(raw)), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	img, err := mutate.AppendLayers(empty.Image, layer)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := name.ParseReference("scancmd-p4:latest")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "image.tar")
	if err := tarball.WriteToFile(path, ref, img); err != nil {
		t.Fatal(err)
	}
	return "docker-archive:" + path
}

// p4Chain returns n symlinks leading from start to final: start -> c/1 ->
// ... -> c/(n-1) -> final, n links in all. Absolute targets, so a link's
// directory does not enter into it.
func p4Chain(start, final string, n int) []p4Entry {
	var es []p4Entry
	from := start
	for i := 1; i < n; i++ {
		to := fmt.Sprintf("chain/hop%02d", i)
		es = append(es, p4Entry{name: from, link: "/" + to})
		from = to
	}
	return append(es, p4Entry{name: from, link: "/" + final})
}

const (
	// Either side of d111DB's 1.36.1-r10 fix: r05 is one finding, r15 none.
	p4ApkVulnerable = "P:busybox-binsh\nV:1.36.1-r05\nA:x86_64\no:busybox\n\n"
	p4ApkPatched    = "P:busybox-binsh\nV:1.36.1-r15\nA:x86_64\no:busybox\n\n"
)

// (A), through Run: the apk database written twice in one layer is read as
// the copy written second. Both orders, so the test holds "last entry wins"
// rather than "the patched copy wins".
func TestRun_P4_DuplicateEntryInOneLayerReadsTheLastOne(t *testing.T) {
	db := layerDigestDB(t)
	low := severity.Low
	for _, tc := range []struct {
		name          string
		first, second string
		want          int
	}{
		{"vulnerable then patched", p4ApkVulnerable, p4ApkPatched, 0},
		{"patched then vulnerable", p4ApkPatched, p4ApkVulnerable, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target := p4Archive(t, p4Tar(t,
				p4Entry{name: osReleasePath, body: osReleaseAlpine319},
				p4Entry{name: apkDBPath, body: tc.first},
				p4Entry{name: apkDBPath, body: tc.second},
			))
			var out, errOut bytes.Buffer
			code := Run(context.Background(), db, target, Options{FailOn: &low}, &out, &errOut)
			if code != tc.want {
				t.Fatalf("Run = %d, want %d: the database written second is what the container has\nstdout: %s\nstderr: %s",
					code, tc.want, out.String(), errOut.String())
			}
			if found := strings.Contains(out.String(), "ALPINE-2024-0001"); found != (tc.want == 1) {
				t.Errorf("finding ALPINE-2024-0001 reported = %v, want %v:\n%s", found, tc.want == 1, out.String())
			}
		})
	}
}

// (A) for FilesUnder's caller: a distroless status.d stanza written twice in
// one layer is cataloged at the second version.
func TestCatalogFromImage_P4_DuplicateStatusDStanzaReadsTheLastOne(t *testing.T) {
	stanza := func(v string) string {
		return "Package: libc6\nStatus: install ok installed\nVersion: " + v + "\nSource: glibc\n\n"
	}
	raw := p4Tar(t,
		p4Entry{name: osReleasePath, body: osReleaseDebian12},
		p4Entry{name: dpkgStatusDir + "/libc6", body: stanza("2.36-9+deb12u1")},
		p4Entry{name: dpkgStatusDir + "/libc6", body: stanza("2.36-9+deb12u7")},
	)
	img := &source.Image{Layers: []source.Layer{{DiffID: "sha256:one",
		Open: func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(raw)), nil }}}}
	target, _, _, err := catalogFromImage(context.Background(), "test-image", img)
	if err != nil {
		t.Fatalf("catalogFromImage: %v", err)
	}
	if len(target.Packages) != 1 || target.Packages[0].Version != "2.36-9+deb12u7" {
		t.Fatalf("packages = %+v, want libc6 at the second stanza's 2.36-9+deb12u7", target.Packages)
	}
}

// (A)'s other in-layer rules, each held at the cataloger that consumes the
// walk rather than only in source's own tests (the mutation round found each
// of these green here until a row was added for it).
func TestCatalogFromImage_P4_InLayerOrderDecidesTheInventory(t *testing.T) {
	stanza := func(pkg, v string) string {
		return "Package: " + pkg + "\nStatus: install ok installed\nVersion: " + v + "\n\n"
	}
	libc6 := dpkgStatusDir + "/libc6"
	zlib := p4Entry{name: dpkgStatusDir + "/zlib1g", body: stanza("zlib1g", "1:1.2.13.dfsg-1")}
	for _, tc := range []struct {
		name    string
		layers  [][]p4Entry // base first
		want    map[string]string
		skipped int // stats.SkippedNoVersion
		noDB    bool
	}{
		{
			// A whiteout after the layer's own database removes it, and the
			// base layer's copy beneath stays hidden -- on every delivery
			// path alike (TestRun_OneImageOneVerdictWhateverArchiveDeliversIt).
			name: "apk database whited out later in its own layer",
			layers: [][]p4Entry{
				{{name: osReleasePath, body: osReleaseAlpine319}, {name: apkDBPath, body: p4ApkVulnerable}},
				{{name: apkDBPath, body: p4ApkPatched}, {name: "lib/apk/db/.wh.installed"}},
			},
			noDB: true,
		},
		{
			name: "whiteout above the database without a replacement",
			layers: [][]p4Entry{
				{{name: osReleasePath, body: osReleaseAlpine319}, {name: apkDBPath, body: p4ApkVulnerable}},
				{{name: "lib/apk/db/.wh.installed"}},
			},
			noDB: true,
		},
		{
			// The hardlink holds the database as it was when the link entry
			// was reached; the rewrite after it changes only tmp/pkgdb.
			name: "apk database hardlinked, target rewritten after the link",
			layers: [][]p4Entry{{
				{name: osReleasePath, body: osReleaseAlpine319},
				{name: "tmp/pkgdb", body: p4ApkVulnerable},
				{name: apkDBPath, link: "tmp/pkgdb", hard: true},
				{name: "tmp/pkgdb", body: p4ApkPatched},
			}},
			want: map[string]string{"busybox-binsh": "1.36.1-r05"},
		},
		{
			// A whiteout of the target after the link does not reach the
			// inode the link already holds.
			name: "apk database hardlinked, target whited out after the link",
			layers: [][]p4Entry{
				{{name: osReleasePath, body: osReleaseAlpine319}, {name: "tmp/pkgdb", body: p4ApkVulnerable}},
				{{name: apkDBPath, link: "tmp/pkgdb", hard: true}, {name: "tmp/.wh.pkgdb"}},
			},
			want: map[string]string{"busybox-binsh": "1.36.1-r05"},
		},
		{
			name: "status.d stanza whited out later in its own layer",
			layers: [][]p4Entry{
				{{name: osReleasePath, body: osReleaseDebian12}, {name: libc6, body: stanza("libc6", "2.36-9")}},
				{{name: libc6, body: stanza("libc6", "2.36-9+deb12u7")}, {name: dpkgStatusDir + "/.wh.libc6"}, zlib},
			},
			want: map[string]string{"zlib1g": "1:1.2.13.dfsg-1"},
		},
		{
			// The image ends with a link there, which is a stanza not read:
			// counted, not cataloged at the replaced file's version.
			name: "status.d stanza replaced by a symlink in its own layer",
			layers: [][]p4Entry{{
				{name: osReleasePath, body: osReleaseDebian12},
				{name: libc6, body: stanza("libc6", "2.36-9")},
				{name: libc6, link: "elsewhere"},
				zlib,
			}},
			want:    map[string]string{"zlib1g": "1:1.2.13.dfsg-1"},
			skipped: 1,
		},
		{
			// An entry beneath the stanza's name makes it a directory.
			name: "status.d stanza turned into a directory later in its own layer",
			layers: [][]p4Entry{{
				{name: osReleasePath, body: osReleaseDebian12},
				{name: libc6, body: stanza("libc6", "2.36-9")},
				{name: libc6 + "/x", body: "x"},
				zlib,
			}},
			want: map[string]string{"zlib1g": "1:1.2.13.dfsg-1"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var ls []source.Layer
			for i, es := range tc.layers {
				raw := p4Tar(t, es...)
				ls = append(ls, source.Layer{DiffID: fmt.Sprintf("sha256:l%d", i),
					Open: func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(raw)), nil }})
			}
			target, stats, _, err := catalogFromImage(context.Background(), "test-image", &source.Image{Layers: ls})
			if tc.noDB {
				if err == nil || !strings.Contains(err.Error(), "no supported package database found") {
					t.Fatalf("err = %v, packages %+v; want no database: the layer removed its own", err, target.Packages)
				}
				return
			}
			if err != nil {
				t.Fatalf("catalogFromImage: %v", err)
			}
			got := map[string]string{}
			for _, p := range target.Packages {
				got[p.Name] = p.Version
			}
			if fmt.Sprint(got) != fmt.Sprint(tc.want) {
				t.Errorf("packages = %v, want %v", got, tc.want)
			}
			if stats.SkippedNoVersion != tc.skipped {
				t.Errorf("SkippedNoVersion = %d, want %d", stats.SkippedNoVersion, tc.skipped)
			}
		})
	}
}

// p4Doc is the slice of the JSON report (B) reads.
type p4Doc struct {
	Unread []struct {
		Path   string `json:"path"`
		Reason string `json:"reason"`
	} `json:"unread"`
	Summary struct {
		TargetIncomplete int `json:"targetIncomplete"`
		UnreadManifests  int `json:"unreadManifests"`
	} `json:"summary"`
}

func p4Scan(t *testing.T, db, target string, opts Options) (p4Doc, string, string, int) {
	t.Helper()
	opts.Output = "json"
	var out, errOut bytes.Buffer
	code := Run(context.Background(), db, target, opts, &out, &errOut)
	var doc p4Doc
	if out.Len() > 0 {
		if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
			t.Fatalf("stdout is not one JSON document: %v\n%s", err, out.String())
		}
	}
	return doc, out.String(), errOut.String(), code
}

// wantUnresolved asserts the report names exactly path as not read, with a
// reason containing why (the link limit, or a cycle), and counts it as the
// target's incompleteness.
func wantUnresolved(t *testing.T, doc p4Doc, stdout, path, why string) {
	t.Helper()
	if len(doc.Unread) != 1 || doc.Unread[0].Path != path {
		t.Fatalf("unread = %+v, want exactly %s: a chain cut off is not an absent file\n%s", doc.Unread, path, stdout)
	}
	if !strings.Contains(doc.Unread[0].Reason, why) {
		t.Errorf("unread reason = %q, want it to say %q", doc.Unread[0].Reason, why)
	}
	if doc.Summary.TargetIncomplete < 1 || doc.Summary.UnreadManifests != 1 {
		t.Errorf("summary = %+v, want the unresolved path counted (targetIncomplete >= 1, unreadManifests 1)", doc.Summary)
	}
}

// (B), through Run: etc/os-release behind 40 links is read (Linux's
// MAXSYMLINKS), behind 41 it is reported unresolved rather than absent, and a
// cycle is reported the same way (ELOOP).
func TestRun_P4_OSReleaseSymlinkChainLimit(t *testing.T) {
	db := layerDigestDB(t)
	const realOSRelease = "usr/lib/os-release"
	image := func(links ...p4Entry) string {
		es := append([]p4Entry{
			{name: realOSRelease, body: osReleaseAlpine319},
			{name: apkDBPath, body: p4ApkPatched},
		}, links...)
		return p4Archive(t, p4Tar(t, es...))
	}

	t.Run("40 links resolve", func(t *testing.T) {
		doc, out, errOut, code := p4Scan(t, db, image(p4Chain(osReleasePath, realOSRelease, 40)...),
			Options{FailOnIncomplete: true})
		if code != 0 {
			t.Fatalf("Run = %d, want 0: forty links is what Linux follows\nstdout: %s\nstderr: %s", code, out, errOut)
		}
		if len(doc.Unread) != 0 {
			t.Errorf("unread = %+v, want none", doc.Unread)
		}
	})

	for _, tc := range []struct {
		name  string
		links []p4Entry
		why   string
	}{
		{"41 links", p4Chain(osReleasePath, realOSRelease, 41), "40 symbolic links"},
		// A cycle is told apart from the limit, and ended at its first
		// repeated lookup rather than after forty-one passes over the image.
		{"a 2-cycle", []p4Entry{{name: osReleasePath, link: "/etc/os-release.loop"}, {name: "etc/os-release.loop", link: "/" + osReleasePath}}, "symbolic link cycle"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc, out, errOut, code := p4Scan(t, db, image(tc.links...), Options{FailOnIncomplete: true})
			if code != 2 {
				t.Fatalf("Run = %d, want 2\nstdout: %s\nstderr: %s", code, out, errOut)
			}
			wantUnresolved(t, doc, out, osReleasePath, tc.why)
			if want := "not read: " + osReleasePath + " ("; !strings.Contains(errOut, want) {
				t.Errorf("stderr lacks %q:\n%s", want, errOut)
			}
		})
	}
}

// (B), the gate itself: an unresolved chain at a path the scan did not end up
// needing still leaves the scan incomplete -- the chain might have led to the
// image's real database. Disclosed always; exit 2 only when asked, under the
// broad flag and under =target (a malformed image is the target's to fix).
func TestRun_P4_UnresolvedChainIsIncompletenessNotAbsence(t *testing.T) {
	db := layerDigestDB(t)
	es := append([]p4Entry{
		{name: osReleasePath, body: osReleaseAlpine319},
		{name: apkDBPath, body: p4ApkPatched},
		{name: "var/lib/dpkg/real-status", body: "Package: x\n"},
	}, p4Chain(dpkgDBPath, "var/lib/dpkg/real-status", 41)...)
	target := p4Archive(t, p4Tar(t, es...))

	doc, out, errOut, code := p4Scan(t, db, target, Options{})
	if code != 0 {
		t.Fatalf("no gate: Run = %d, want 0\nstdout: %s\nstderr: %s", code, out, errOut)
	}
	wantUnresolved(t, doc, out, dpkgDBPath, "40 symbolic links")

	for _, opts := range []Options{{FailOnIncomplete: true}, {FailOnIncompleteTarget: true}} {
		if _, out, errOut, code := p4Scan(t, db, target, opts); code != 2 {
			t.Errorf("%+v: Run = %d, want 2\nstdout: %s\nstderr: %s", opts, code, out, errOut)
		}
	}
}

// (B) where the cut-off chain was the only package database: the scan still
// fails, and now says which path it could not resolve instead of only "no
// supported package database found".
func TestRun_P4_UnresolvedDatabaseIsNamedInTheError(t *testing.T) {
	db := layerDigestDB(t)
	es := append([]p4Entry{
		{name: osReleasePath, body: osReleaseAlpine319},
		{name: "lib/apk/db/real-installed", body: p4ApkPatched},
	}, p4Chain(apkDBPath, "lib/apk/db/real-installed", 41)...)
	_, out, errOut, code := p4Scan(t, db, p4Archive(t, p4Tar(t, es...)), Options{})
	if code != 2 {
		t.Fatalf("Run = %d, want 2\nstdout: %s\nstderr: %s", code, out, errOut)
	}
	if want := "not resolved: " + apkDBPath + " ("; !strings.Contains(errOut, want) {
		t.Errorf("stderr lacks %q:\n%s", want, errOut)
	}
}
