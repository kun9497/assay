package scancmd

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/store"
)

// D160: an image scan reads two fixed locations for application packages --
// installed package.json files under the global node_modules roots and Go
// binaries directly in the standard bin directories -- and says so per
// ecosystem in inventoryScope.applicationScope. Caller first (CLAUDE.md):
// every test here drives Run through a docker-archive image, and deleting
// the probe call in catalogFromImage turns each of them red.

// probeEntry is one tar entry with its own mode, for executables.
type probeEntry struct {
	name string
	body []byte
	mode int64
}

// writeProbeImage is writeImageTar for entries that need a mode: the probe
// selects executables on the execute bit, which the string map cannot carry.
func writeProbeImage(t *testing.T, path string, entries []probeEntry) {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		mode := e.mode
		if mode == 0 {
			mode = 0o644
		}
		if err := tw.WriteHeader(&tar.Header{Name: e.name, Mode: mode, Size: int64(len(e.body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(e.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	raw := buf.Bytes()
	layer, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(raw)), nil })
	if err != nil {
		t.Fatalf("LayerFromOpener: %v", err)
	}
	img, err := mutate.AppendLayers(empty.Image, layer)
	if err != nil {
		t.Fatalf("AppendLayers: %v", err)
	}
	ref, err := name.ParseReference("scancmd-probe-test:latest")
	if err != nil {
		t.Fatal(err)
	}
	if err := tarball.WriteToFile(path, ref, img); err != nil {
		t.Fatalf("WriteToFile: %v", err)
	}
}

// probeDB holds one npm advisory (minimatch below 3.0.5) and one Go advisory
// (go.etcd.io/bbolt below 1.6.0, the module buildBBoltBinary links), beside
// the osv provider declaring Alpine, npm and Go, so both probes' packages are
// evaluated against something real rather than passing on an empty bucket.
func probeDB(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vulnerability.db")
	w, err := store.Create(path)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	for _, a := range []advisory.Advisory{
		{ID: "GHSA-probe-npm-0001", Kind: advisory.KindVulnerability, Database: "GHSA", Upstream: []string{"CVE-2026-90001"},
			Severity: []advisory.Severity{{Type: "CVSS_V3", Score: vecCritical}},
			Affected: []advisory.Affected{{Ecosystem: "npm", Name: "minimatch",
				Ranges: []advisory.Range{{Type: advisory.RangeSemver, Events: []advisory.Event{{Introduced: "0"}, {Fixed: "3.0.5"}}}}}}},
		{ID: "GO-2026-90002", Kind: advisory.KindVulnerability, Database: "GO", Upstream: []string{"CVE-2026-90002"},
			Severity: []advisory.Severity{{Type: "CVSS_V3", Score: vecCritical}},
			Affected: []advisory.Affected{{Ecosystem: "Go", Name: "go.etcd.io/bbolt",
				Ranges: []advisory.Range{{Type: advisory.RangeSemver, Events: []advisory.Event{{Introduced: "0"}, {Fixed: "1.6.0"}}}}}}},
	} {
		if err := w.Put(a); err != nil {
			t.Fatalf("Put: %v", err)
		}
	}
	if err := w.SetMeta(store.Meta{Providers: map[string]store.Provenance{"osv": {Ecosystems: []string{"Alpine:v3.19", "npm", "Go"}}}}); err != nil {
		t.Fatalf("SetMeta: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return path
}

// buildLinuxBBoltBinary is buildBBoltBinary cross-compiled for linux/amd64:
// the probe sniffs for ELF, and a binary built for this test host would be
// PE on Windows or Mach-O on macOS -- which is also the shape the probe is
// for, since images hold Linux binaries whatever builds them.
func buildLinuxBBoltBinary(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go is not on PATH; this test needs a toolchain to build its fixture")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"),
		[]byte("module example.test/probed\n\ngo 1.26\n\nrequire go.etcd.io/bbolt v1.5.0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"),
		[]byte("package main\n\nimport _ \"go.etcd.io/bbolt\"\n\nfunc main() {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "tool")
	cmd := exec.Command("go", "build", "-buildvcs=false", "-o", bin, ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOFLAGS=-mod=mod", "GOPROXY=off", "GOSUMDB=off", "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0")
	out, err := cmd.CombinedOutput()
	if err != nil {
		if strings.Contains(string(out), "module lookup disabled by GOPROXY=off") {
			t.Skipf("go build failed (%v); fixture needs a module not in the local cache:\n%s", err, out)
		}
		t.Fatalf("go build failed (%v):\n%s", err, out)
	}
	return bin
}

type probeDoc struct {
	SchemaVersion int `json:"schemaVersion"`
	Summary       struct {
		Components   int `json:"components"`
		Evaluated    int `json:"evaluated"`
		NotEvaluated int `json:"notEvaluated"`
		Findings     int `json:"findings"`
	} `json:"summary"`
	Findings []struct {
		Package struct {
			Name      string `json:"name"`
			Version   string `json:"version"`
			Ecosystem string `json:"ecosystem"`
			PURL      string `json:"purl"`
			Locations []struct {
				Path        string `json:"path"`
				LayerDigest string `json:"layerDigest"`
			} `json:"locations"`
		} `json:"package"`
		Advisory struct{ ID string } `json:"advisory"`
	} `json:"findings"`
	InventoryScope *struct {
		OSPackages          string `json:"osPackages"`
		Bitnami             string `json:"bitnami"`
		ApplicationPackages string `json:"applicationPackages"`
		ApplicationScope    []struct {
			Ecosystem string   `json:"ecosystem"`
			State     string   `json:"state"`
			Roots     []string `json:"roots"`
		} `json:"applicationScope"`
	} `json:"inventoryScope"`
}

func decodeProbe(t *testing.T, out string) probeDoc {
	t.Helper()
	var doc probeDoc
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("stdout is not one JSON document: %v\n%s", err, out)
	}
	return doc
}

func alpineEntries() []probeEntry {
	return []probeEntry{{name: osReleasePath, body: []byte(osReleaseAlpine319)}, {name: apkDBPath, body: []byte(apkOneRecord)}}
}

func (d probeDoc) scopeOf(eco string) (state string, roots []string, ok bool) {
	if d.InventoryScope == nil {
		return "", nil, false
	}
	for _, a := range d.InventoryScope.ApplicationScope {
		if a.Ecosystem == eco {
			return a.State, a.Roots, true
		}
	}
	return "", nil, false
}

// The npm probe: a global tree with a nested dependency. The nested copy is
// the package the advisory names; a package.json inside a package (esm/) and
// a tree outside the roots (app/node_modules) are not packages.
func TestRun_D160_NpmTreeUnderTheGlobalRootIsRead(t *testing.T) {
	tarPath := filepath.Join(t.TempDir(), "image.tar")
	writeProbeImage(t, tarPath, append(alpineEntries(),
		probeEntry{name: "usr/lib/node_modules/npm/package.json", body: []byte(`{"name":"npm","version":"8.19.4"}`)},
		probeEntry{name: "usr/lib/node_modules/npm/node_modules/minimatch/package.json", body: []byte(`{"name":"minimatch","version":"3.0.4"}`)},
		probeEntry{name: "usr/lib/node_modules/npm/esm/package.json", body: []byte(`{"type":"module"}`)},
		probeEntry{name: "app/node_modules/minimatch/package.json", body: []byte(`{"name":"minimatch","version":"3.0.4"}`)},
	))
	var out, errOut bytes.Buffer
	code := Run(context.Background(), probeDB(t), "docker-archive:"+tarPath, Options{Output: "json"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("Run = %d, want 0 (no gate)\nstderr: %s", code, errOut.String())
	}
	doc := decodeProbe(t, out.String())
	// The apk package plus two npm packages; esm/ and app/ contribute nothing.
	if doc.Summary.Components != 3 || doc.Summary.Evaluated != 3 {
		t.Errorf("summary = %+v, want 3 components, 3 evaluated (busybox, npm, minimatch)", doc.Summary)
	}
	if len(doc.Findings) != 1 {
		t.Fatalf("findings = %d, want 1 (minimatch 3.0.4 < 3.0.5)\n%s", len(doc.Findings), out.String())
	}
	f := doc.Findings[0]
	if f.Package.Name != "minimatch" || f.Package.Ecosystem != "npm" || f.Package.PURL != "pkg:npm/minimatch@3.0.4" {
		t.Errorf("finding package = %+v, want npm minimatch 3.0.4 with its purl", f.Package)
	}
	if len(f.Package.Locations) != 1 || f.Package.Locations[0].Path != "usr/lib/node_modules/npm/node_modules/minimatch/package.json" || f.Package.Locations[0].LayerDigest == "" {
		t.Errorf("finding locations = %+v, want the nested path with its layer", f.Package.Locations)
	}
	if s := doc.InventoryScope; s == nil || s.ApplicationPackages != "partial" {
		t.Fatalf("inventoryScope = %+v, want applicationPackages partial", s)
	}
	if state, roots, ok := doc.scopeOf("npm"); !ok || state != "read" || len(roots) != 3 || roots[0] != "usr/lib/node_modules" {
		t.Errorf("applicationScope npm = %q %v (present %v), want read with the three roots", state, roots, ok)
	}
	if state, roots, ok := doc.scopeOf("Go"); !ok || state != "none" || len(roots) != 7 {
		t.Errorf("applicationScope Go = %q %v (present %v), want none with the seven bin directories", state, roots, ok)
	}
	for _, eco := range []string{"PyPI", "Maven"} {
		if state, _, ok := doc.scopeOf(eco); !ok || state != "not-read" {
			t.Errorf("applicationScope %s = %q (present %v), want not-read", eco, state, ok)
		}
	}
	if doc.SchemaVersion != 18 {
		t.Errorf("schemaVersion = %d, want 18", doc.SchemaVersion)
	}
}

// The Go probe: a real Go binary in usr/bin is read and its linked module
// found; the same binary under /opt is not (outside the fixed directories),
// and a shell script with the execute bit in usr/bin is declined at the sniff.
func TestRun_D160_GoBinaryInABinDirectoryIsRead(t *testing.T) {
	bin := buildLinuxBBoltBinary(t)
	data, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	script := []byte("#!/bin/sh\n" + strings.Repeat("echo not-a-go-binary\n", 100))
	tarPath := filepath.Join(t.TempDir(), "image.tar")
	writeProbeImage(t, tarPath, append(alpineEntries(),
		probeEntry{name: "usr/bin/tool", body: data, mode: 0o755},
		probeEntry{name: "opt/tool/bin/tool", body: data, mode: 0o755},
		probeEntry{name: "usr/bin/wrapper.sh", body: script, mode: 0o755},
		// The same bytes without the execute bit are data, not a program,
		// and a binary one directory down is outside the probe.
		probeEntry{name: "usr/bin/tool.bak", body: data, mode: 0o644},
		probeEntry{name: "usr/bin/plugins/tool", body: data, mode: 0o755},
	))
	var out, errOut bytes.Buffer
	code := Run(context.Background(), probeDB(t), "docker-archive:"+tarPath, Options{Output: "json"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("Run = %d, want 0 (no gate)\nstderr: %s", code, errOut.String())
	}
	doc := decodeProbe(t, out.String())
	var bbolt []string
	for _, f := range doc.Findings {
		if f.Package.Name == "go.etcd.io/bbolt" {
			for _, l := range f.Package.Locations {
				bbolt = append(bbolt, l.Path)
			}
		}
	}
	if len(bbolt) != 1 || bbolt[0] != "usr/bin/tool" {
		t.Errorf("bbolt finding locations = %v, want exactly usr/bin/tool (the /opt copy, the 0644 copy and the "+
			"plugins/ copy are outside the probe)\n%s", bbolt, out.String())
	}
	if state, _, ok := doc.scopeOf("Go"); !ok || state != "read" {
		t.Errorf("applicationScope Go = %q (present %v), want read", state, ok)
	}
	if state, _, ok := doc.scopeOf("npm"); !ok || state != "none" {
		t.Errorf("applicationScope npm = %q (present %v), want none: no tree under the roots", state, ok)
	}
}

// An installed package.json that names no version is a component whose
// version is unknown (D36): counted in notEvaluated, never a package.
func TestRun_D160_PackageJSONWithoutAVersionIsACountedSkip(t *testing.T) {
	tarPath := filepath.Join(t.TempDir(), "image.tar")
	writeProbeImage(t, tarPath, append(alpineEntries(),
		probeEntry{name: "usr/local/lib/node_modules/corepack/package.json", body: []byte(`{"name":"corepack"}`)},
	))
	var out, errOut bytes.Buffer
	code := Run(context.Background(), probeDB(t), "docker-archive:"+tarPath, Options{Output: "json"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("Run = %d, want 0\nstderr: %s", code, errOut.String())
	}
	doc := decodeProbe(t, out.String())
	if doc.Summary.Components != 2 || doc.Summary.Evaluated != 1 || doc.Summary.NotEvaluated != 1 {
		t.Errorf("summary = %+v, want 2 components, 1 evaluated, 1 not evaluated", doc.Summary)
	}
	for _, f := range doc.Findings {
		if f.Package.Name == "corepack" {
			t.Errorf("a version-less package.json became a finding: %+v", f.Package)
		}
	}
}

// D141's disclosure says what the probes read and what they still do not,
// on stderr and in SARIF, from the same scope record.
func TestRun_D160_DisclosureNamesWhatWasReadAndWhatWasNot(t *testing.T) {
	tarPath := filepath.Join(t.TempDir(), "image.tar")
	writeProbeImage(t, tarPath, alpineEntries())
	var out, errOut bytes.Buffer
	if code := Run(context.Background(), probeDB(t), "docker-archive:"+tarPath, Options{}, &out, &errOut); code != 0 {
		t.Fatalf("Run = %d\nstderr: %s", code, errOut.String())
	}
	for _, want := range []string{
		"note: an image scan reads OS packages (and Bitnami markers) plus npm packages under usr/lib/node_modules, usr/local/lib/node_modules and opt/app-root/src/node_modules and Go binaries under usr/bin",
		"Python packages and Java packages, node_modules elsewhere and Go binaries elsewhere -- were not checked",
		"(D70, D160)",
	} {
		if !strings.Contains(errOut.String(), want) {
			t.Errorf("stderr lacks %q:\n%s", want, errOut.String())
		}
	}
	var sarif bytes.Buffer
	if code := Run(context.Background(), probeDB(t), "docker-archive:"+tarPath, Options{Output: "sarif"}, &sarif, io.Discard); code != 0 {
		t.Fatalf("Run(sarif) = %d", code)
	}
	if s := sarif.String(); !strings.Contains(s, "plus npm packages under usr/lib/node_modules") || !strings.Contains(s, "the other application packages -- Python packages and Java packages") {
		t.Errorf("SARIF inventory-scope result does not carry the probed scope:\n%s", s)
	}
}

// The one pass's two hooks, directly: the branches a docker-archive fixture
// cannot show one at a time (a sniff that accepted everything would still
// yield the same findings, since ParseBytes rejects a script -- what it would
// cost is the script's bytes).
func TestProbeHooks(t *testing.T) {
	reg := func(mode int64, size int64) *tar.Header {
		return &tar.Header{Typeflag: tar.TypeReg, Mode: mode, Size: size}
	}
	for _, tc := range []struct {
		name string
		h    *tar.Header
		want bool
	}{
		{"usr/bin/tool", reg(0o755, 4096), true},
		{"usr/local/sbin/tool", reg(0o700, 4096), true},
		{"usr/bin/tool", reg(0o644, 4096), false},         // no execute bit
		{"usr/bin/tool", reg(0o755, 512), false},          // below the floor
		{"usr/bin/plugins/tool", reg(0o755, 4096), false}, // not a direct child
		{"opt/bin/tool", reg(0o755, 4096), false},         // not a bin directory
		{"usr/bin/link", &tar.Header{Typeflag: tar.TypeSymlink, Mode: 0o777}, false},
		{"usr/lib/node_modules/x/package.json", reg(0o644, 40), true},
		{"usr/lib/node_modules/x/node_modules/y/package.json", reg(0o644, 40), true},
		{"app/node_modules/x/package.json", reg(0o644, 40), false}, // outside the roots
		{"usr/lib/node_modules/x/README.md", reg(0o644, 40), false},
	} {
		if got := probeCandidate(tc.name, tc.h); got != tc.want {
			t.Errorf("probeCandidate(%q, mode %o, size %d, type %c) = %v, want %v", tc.name, tc.h.Mode, tc.h.Size, tc.h.Typeflag, got, tc.want)
		}
	}
	if !probeSniff("usr/lib/node_modules/x/package.json", []byte("{\"n")) {
		t.Error("a package.json was declined at the sniff")
	}
	if !probeSniff("usr/bin/tool", []byte{0x7f, 'E', 'L', 'F'}) || probeSniff("usr/bin/tool", []byte("#!/b")) || probeSniff("usr/bin/tool", []byte{0x7f, 'E', 'L'}) {
		t.Error("the executable sniff is not exactly the four-byte ELF magic")
	}
}
