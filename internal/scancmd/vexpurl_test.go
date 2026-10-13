package scancmd

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/report"
	"github.com/kun9497/assay/internal/store"
)

// D121's caller tests. Every one goes through Run against a real image — a
// docker-archive: tarball or an in-memory registry — because the purl an
// image's OS package now carries is assigned in catalogFromImage, and a
// statement's image scope is decided from what Run knows about the target.
// The vex package's own tests hold the matching rules; these hold that Run
// reaches them.

// apkThreePackages: busybox and busybox-binsh share the origin busybox, and
// libssl3's origin is openssl. busybox is a binary named like its source,
// which is the case where an unmarked source statement could be misread.
const apkThreePackages = `P:busybox
V:1.36.1-r15
A:x86_64
o:busybox

P:busybox-binsh
V:1.36.1-r15
A:x86_64
o:busybox

P:libssl3
V:3.1.4-r5
A:x86_64
o:openssl

`

// libssl3PURL is syft v1.50.0's purl for libssl3 on alpine:3.19.9, spelled
// as the measured syft output spells it — the string a statement written
// against a syft SBOM of the image carries.
const libssl3PURL = "pkg:apk/alpine/libssl3@3.1.4-r5?arch=x86_64&distro=alpine-3.19.9&upstream=openssl"

// vexAdv is one advisory for vexDB: an ID that differs from its CVE alias
// (so a statement naming the CVE matches through the alias, never on a
// substring of the ID), on the source name pkg.
type vexAdv struct {
	id, cve, pkg, fixed string
}

// vexDB builds a database covering eco with advs in it.
func vexDB(t *testing.T, eco string, advs ...vexAdv) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vulnerability.db")
	w, err := store.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range advs {
		if err := w.Put(advisory.Advisory{
			ID: a.id, Kind: advisory.KindVulnerability, Aliases: []string{a.cve}, Database: "TEST",
			Affected: []advisory.Affected{{
				Ecosystem: eco, Name: a.pkg,
				Ranges: []advisory.Range{{
					Type:   advisory.RangeEcosystem,
					Events: []advisory.Event{{Introduced: "0"}, {Fixed: a.fixed}},
				}},
			}},
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.SetMeta(store.Meta{
		Providers: map[string]store.Provenance{"osv": {Ecosystems: []string{eco}}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func alpineVEXDB(t *testing.T) string {
	return vexDB(t, "Alpine:v3.19",
		vexAdv{"ALPINE-2031-0001", "CVE-2031-9001", "busybox", "1.36.1-r99"},
		vexAdv{"ALPINE-2031-0002", "CVE-2031-9002", "openssl", "3.1.4-r99"})
}

// writeVEX writes an OpenVEX v0.2.0 document holding statements (raw JSON
// objects) and returns its path.
func writeVEX(t *testing.T, statements ...string) string {
	t.Helper()
	doc := `{"@context":"https://openvex.dev/ns/v0.2.0","@id":"https://example.com/vex/d121",` +
		`"author":"D121 Test","timestamp":"2026-10-13T00:00:00Z","version":1,"statements":[` +
		strings.Join(statements, ",") + `]}`
	p := filepath.Join(t.TempDir(), "vex.json")
	if err := os.WriteFile(p, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// stmt is one not_affected statement about cve naming products (raw JSON).
func stmt(cve string, products ...string) string {
	return `{"vulnerability":{"name":"` + cve + `"},"products":[` + strings.Join(products, ",") +
		`],"status":"not_affected","justification":"inline_mitigations_already_exist"}`
}

// product renders one product: an @id and optional subcomponent @ids.
func product(id string, subs ...string) string {
	s := `{"@id":"` + id + `"`
	if len(subs) > 0 {
		var parts []string
		for _, sub := range subs {
			parts = append(parts, `{"@id":"`+sub+`"}`)
		}
		s += `,"subcomponents":[` + strings.Join(parts, ",") + `]`
	}
	return s + "}"
}

// scanVEXJSON runs a JSON scan of target with the given --vex documents and
// decodes the report.
func scanVEXJSON(t *testing.T, db, target string, vexFiles ...string) (report.Document, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := Run(context.Background(), db, target, Options{Output: "json", VEXFiles: vexFiles}, &out, &errOut)
	if code == 2 {
		t.Fatalf("Run = 2\nstderr: %s", errOut.String())
	}
	var doc report.Document
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, out.String())
	}
	return doc, errOut.String()
}

// pair is one finding as (package name, CVE alias), the unit these tests
// assert on: asserting the pair, never either half, so a test cannot pass on
// the column it was not testing.
type pair struct{ pkg, cve string }

func pairsOf(recs []report.FindingRecord) map[pair]bool {
	out := map[pair]bool{}
	for _, r := range recs {
		for _, a := range r.Advisory.Aliases {
			out[pair{r.Package.Name, a}] = true
		}
	}
	return out
}

func suppressedPairs(doc report.Document) map[pair]bool {
	var recs []report.FindingRecord
	for _, s := range doc.Suppressed {
		recs = append(recs, s.FindingRecord)
	}
	return pairsOf(recs)
}

// alpineArchive writes an Alpine 3.19.9 docker-archive with apkdb and
// returns its target string.
func alpineArchive(t *testing.T, apkdb string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "image.tar")
	writeImageTar(t, p, map[string]string{osReleasePath: osReleaseAlpine319, apkDBPath: apkdb})
	return "docker-archive:" + p
}

// (1) The headline. A statement about an image's OS package, in syft's
// spelling, suppresses that package's finding — before D121 the package had
// no purl and the statement silently matched nothing. Goes red when the
// assignOSPURLs call in catalogFromImage is deleted.
func TestRun_VEXSuppressesAnImageOSPackageBySyftPURL(t *testing.T) {
	db := alpineVEXDB(t)
	target := alpineArchive(t, apkThreePackages)

	doc, _ := scanVEXJSON(t, db, target)
	var got string
	for _, f := range doc.Findings {
		if f.Package.Name == "libssl3" {
			got = f.Package.PURL
		}
	}
	if got != libssl3PURL {
		t.Errorf("libssl3 purl in JSON = %q, want syft's %q", got, libssl3PURL)
	}

	vexPath := writeVEX(t, stmt("CVE-2031-9002", product(libssl3PURL)))
	doc, stderr := scanVEXJSON(t, db, target, vexPath)
	sup := suppressedPairs(doc)
	if !sup[pair{"libssl3", "CVE-2031-9002"}] || len(doc.Suppressed) != 1 {
		t.Fatalf("suppressed = %v, want exactly libssl3/CVE-2031-9002\nstderr: %s", sup, stderr)
	}
}

// (3) A statement naming a source package's name without arch=src/source is
// a statement about the binary of that name only. busybox is both the
// source and a binary here; busybox-binsh, built from it, keeps its finding.
func TestRun_VEXUnmarkedSourceNameIsTheBinaryOnly(t *testing.T) {
	db := alpineVEXDB(t)
	target := alpineArchive(t, apkThreePackages)
	vexPath := writeVEX(t, stmt("CVE-2031-9001", product("pkg:apk/alpine/busybox@1.36.1-r15")))

	doc, stderr := scanVEXJSON(t, db, target, vexPath)
	sup, kept := suppressedPairs(doc), pairsOf(doc.Findings)
	if !sup[pair{"busybox", "CVE-2031-9001"}] {
		t.Errorf("busybox/CVE-2031-9001 not suppressed; suppressed = %v\nstderr: %s", sup, stderr)
	}
	if !kept[pair{"busybox-binsh", "CVE-2031-9001"}] || sup[pair{"busybox-binsh", "CVE-2031-9001"}] {
		t.Errorf("busybox-binsh/CVE-2031-9001 must stay a finding: kept = %v, suppressed = %v", kept, sup)
	}
}

// vexRegistryImage is an image whose config names this host's platform, so
// the registry path selects it, holding files.
func vexRegistryImage(t *testing.T, files map[string]string) v1.Image {
	t.Helper()
	raw := buildTar(t, files)
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
	cf, err := img.ConfigFile()
	if err != nil {
		t.Fatal(err)
	}
	cf = cf.DeepCopy()
	cf.OS, cf.Architecture = "linux", runtime.GOARCH
	if img, err = mutate.ConfigFile(img, cf); err != nil {
		t.Fatal(err)
	}
	return img
}

// (2) and (6). A Docker Hardened Images-shaped statement: the package listed
// under the image AND again as a bare, version-less top-level product. The
// same image content is pushed under two names; the statement applies to
// the one it names and to nothing else, the bare duplicate included. The
// summary line is asserted whole, as a line.
func TestRun_VEXImageScopedStatementAppliesOnlyToThatImage(t *testing.T) {
	isolateCredentials(t)
	ar := openRegistry(t)
	db := alpineVEXDB(t)
	img := vexRegistryImage(t, map[string]string{osReleasePath: osReleaseAlpine319, apkDBPath: apkThreePackages})
	dhi := pushImage(t, ar.host, "dhi/python:3.13", img)
	stock := pushImage(t, ar.host, "library/alpine:3.19", img)

	dhiProduct := "pkg:docker/dhi/python@3.13?repository_url=" + ar.host
	vexPath := writeVEX(t, stmt("CVE-2031-9002",
		product(dhiProduct, libssl3PURL),
		product("pkg:apk/alpine/libssl3")))

	doc, stderr := scanVEXJSON(t, db, stock, vexPath)
	if len(doc.Suppressed) != 0 {
		t.Errorf("a statement scoped to %s suppressed %v on %s", dhi, suppressedPairs(doc), stock)
	}
	if !pairsOf(doc.Findings)[pair{"libssl3", "CVE-2031-9002"}] {
		t.Errorf("libssl3/CVE-2031-9002 missing from findings on %s", stock)
	}
	const wantOther = "vex: 1 of 1 statement(s) matched no finding (1 name an image that is not this target, " +
		"0 skipped); 0 finding(s) carry no purl to match against\n"
	if !hasLine(stderr, "\n"+wantOther) {
		t.Errorf("stderr lacks the summary line %q\nstderr: %s", wantOther, stderr)
	}

	doc, stderr = scanVEXJSON(t, db, dhi, vexPath)
	if sup := suppressedPairs(doc); !sup[pair{"libssl3", "CVE-2031-9002"}] || len(doc.Suppressed) != 1 {
		t.Errorf("on %s, suppressed = %v, want exactly libssl3/CVE-2031-9002\nstderr: %s", dhi, sup, stderr)
	}
	const wantSame = "vex: 0 of 1 statement(s) matched no finding (0 name an image that is not this target, " +
		"0 skipped); 0 finding(s) carry no purl to match against\n"
	if !hasLine(stderr, "\n"+wantSame) {
		t.Errorf("stderr lacks the summary line %q\nstderr: %s", wantSame, stderr)
	}
}

// (2), the other two identities. A digest names the image whatever it was
// loaded through, so a docker-archive: scan matches its own manifest digest
// and no other; a tag-scoped statement cannot match an archive, which has
// no repository to compare.
func TestRun_VEXImageScopeByDigestAndNotByNameOnAnArchive(t *testing.T) {
	db := alpineVEXDB(t)
	target := alpineArchive(t, apkThreePackages)

	// Learn the archive's manifest digest the way a reader would: from the
	// D119 image record the scan itself reports.
	doc, _ := scanVEXJSON(t, db, target)
	if doc.Image == nil || doc.Image.ManifestDigest == "" {
		t.Fatal("JSON has no image manifest digest")
	}
	digest := doc.Image.ManifestDigest

	byDigest := writeVEX(t, stmt("CVE-2031-9002", product("pkg:oci/whatever@"+digest, libssl3PURL)))
	doc, stderr := scanVEXJSON(t, db, target, byDigest)
	if !suppressedPairs(doc)[pair{"libssl3", "CVE-2031-9002"}] {
		t.Errorf("a statement scoped to this archive's digest did not apply\nstderr: %s", stderr)
	}

	otherDigest := writeVEX(t, stmt("CVE-2031-9002", product(
		"pkg:oci/whatever@sha256:0000000000000000000000000000000000000000000000000000000000000000", libssl3PURL)))
	if doc, _ := scanVEXJSON(t, db, target, otherDigest); len(doc.Suppressed) != 0 {
		t.Errorf("a statement scoped to another digest applied: %v", suppressedPairs(doc))
	}

	byTag := writeVEX(t, stmt("CVE-2031-9002", product("pkg:docker/library/alpine@3.19", libssl3PURL)))
	if doc, _ := scanVEXJSON(t, db, target, byTag); len(doc.Suppressed) != 0 {
		t.Errorf("a tag-scoped statement applied to an archive, which has no name: %v", suppressedPairs(doc))
	}
}

// An image-scoped statement in a scan that is not of an image is skipped:
// the scan cannot know it is that image. The SBOM carries the package purl
// verbatim, so only the scope can be what stops it.
func TestRun_VEXImageScopedStatementSkippedOnAnSBOM(t *testing.T) {
	db := alpineVEXDB(t)
	sbom := writeAlpineSBOM(t, libssl3PURL)
	vexPath := writeVEX(t, stmt("CVE-2031-9002", product("pkg:oci/whatever@sha256:abc", libssl3PURL)))
	doc, stderr := scanVEXJSON(t, db, sbom, vexPath)
	if len(doc.Suppressed) != 0 {
		t.Errorf("an image-scoped statement applied to an SBOM scan: %v", suppressedPairs(doc))
	}
	if !strings.Contains(stderr, "(1 name an image that is not this target, ") {
		t.Errorf("stderr does not count the out-of-scope statement\nstderr: %s", stderr)
	}
}

// writeAlpineSBOM is a CycloneDX document holding one Alpine 3.19 apk
// component with the given purl.
func writeAlpineSBOM(t *testing.T, purl string) string {
	t.Helper()
	doc := `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[` +
		`{"type":"operating-system","name":"alpine","version":"3.19.9"},` +
		`{"type":"library","name":"libssl3","version":"3.1.4-r5","purl":"` + purl + `",` +
		`"properties":[{"name":"syft:metadata:originPackage","value":"openssl"}]}]}`
	p := filepath.Join(t.TempDir(), "sbom.cdx.json")
	if err := os.WriteFile(p, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// (7) An SBOM's purl is the producer's and reaches the report verbatim —
// D121 only fills a purl where none exists, and the image path is the only
// one that does. The purl here is deliberately not syft's spelling of this
// package (an extra qualifier, a different distro point release).
func TestRun_SBOMPurlIsReportedVerbatim(t *testing.T) {
	db := alpineVEXDB(t)
	const odd = "pkg:apk/alpine/libssl3@3.1.4-r5?arch=x86_64&distro=alpine-3.19.1&package-id=feedface"
	doc, stderr := scanVEXJSON(t, db, writeAlpineSBOM(t, odd))
	if len(doc.Findings) != 1 {
		t.Fatalf("findings = %d, want 1\nstderr: %s", len(doc.Findings), stderr)
	}
	if got := doc.Findings[0].Package.PURL; got != odd {
		t.Errorf("purl = %q, want the SBOM's own %q verbatim", got, odd)
	}
}

const osReleaseDebian12Bookworm = `PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
NAME="Debian GNU/Linux"
VERSION_ID="12"
VERSION="12 (bookworm)"
VERSION_CODENAME=bookworm
ID=debian
`

// dpkgOpensslAndGlibc: openssl (a binary named like its source), libssl3
// built from it, and libc6 from glibc.
const dpkgOpensslAndGlibc = `Package: openssl
Status: install ok installed
Architecture: amd64
Version: 3.0.17-1~deb12u2

Package: libssl3
Status: install ok installed
Architecture: amd64
Source: openssl
Version: 3.0.17-1~deb12u2

Package: libc6
Status: install ok installed
Architecture: amd64
Source: glibc
Version: 2.36-9+deb12u10
`

// (4) A source statement marked arch=source applies to every binary built
// from that source at that version — openssl and libssl3 — and to nothing
// else, even a finding under the same CVE on a package from another source.
func TestRun_VEXMarkedSourceStatementCoversItsBinariesOnly(t *testing.T) {
	db := vexDB(t, "Debian:12",
		vexAdv{"DEBIAN-2031-0101", "CVE-2031-9101", "openssl", "3.0.99-1"},
		vexAdv{"DEBIAN-2031-0102", "CVE-2031-9101", "glibc", "2.36-99"})
	p := filepath.Join(t.TempDir(), "image.tar")
	writeImageTar(t, p, map[string]string{osReleasePath: osReleaseDebian12Bookworm, dpkgDBPath: dpkgOpensslAndGlibc})
	target := "docker-archive:" + p

	vexPath := writeVEX(t, stmt("CVE-2031-9101",
		product("pkg:deb/debian/openssl@3.0.17-1~deb12u2?arch=source")))
	doc, stderr := scanVEXJSON(t, db, target, vexPath)
	sup, kept := suppressedPairs(doc), pairsOf(doc.Findings)
	for _, want := range []pair{{"openssl", "CVE-2031-9101"}, {"libssl3", "CVE-2031-9101"}} {
		if !sup[want] {
			t.Errorf("%v not suppressed by the source statement; suppressed = %v\nstderr: %s", want, sup, stderr)
		}
	}
	if !kept[pair{"libc6", "CVE-2031-9101"}] || len(doc.Suppressed) != 2 {
		t.Errorf("libc6/CVE-2031-9101 must stay a finding and only two be suppressed: kept = %v, suppressed = %v",
			kept, sup)
	}
	for _, s := range doc.Suppressed {
		if !strings.Contains(s.Reason, "(via source package openssl)") {
			t.Errorf("reason %q does not say the binary was exonerated through its source", s.Reason)
		}
	}

	// The same statement at another source version applies to nothing.
	stale := writeVEX(t, stmt("CVE-2031-9101",
		product("pkg:deb/debian/openssl@3.0.11-1~deb12u1?arch=source")))
	if doc, _ := scanVEXJSON(t, db, target, stale); len(doc.Suppressed) != 0 {
		t.Errorf("a source statement at another version applied: %v", suppressedPairs(doc))
	}
}

const osReleaseUbuntu2204 = `PRETTY_NAME="Ubuntu 22.04.5 LTS"
NAME="Ubuntu"
VERSION_ID="22.04"
VERSION="22.04.5 LTS (Jammy Jellyfish)"
VERSION_CODENAME=jammy
ID=ubuntu
ID_LIKE=debian
UBUNTU_CODENAME=jammy
`

const dpkgUbuntuLibssl3 = `Package: libssl3
Status: install ok installed
Architecture: amd64
Source: openssl
Version: 3.0.2-0ubuntu1.18
`

// (5) Canonical's OpenVEX shape: a source statement with distro=<codename>.
// It applies on a jammy image; the same statement for noble does not.
func TestRun_VEXUbuntuCodenameDistro(t *testing.T) {
	db := vexDB(t, "Ubuntu:22.04:LTS", vexAdv{"UBUNTU-2031-0201", "CVE-2031-9201", "openssl", "3.0.2-0ubuntu1.99"})
	p := filepath.Join(t.TempDir(), "image.tar")
	writeImageTar(t, p, map[string]string{osReleasePath: osReleaseUbuntu2204, dpkgDBPath: dpkgUbuntuLibssl3})
	target := "docker-archive:" + p

	jammy := writeVEX(t, stmt("CVE-2031-9201",
		product("pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1.18?arch=source&distro=jammy")))
	doc, stderr := scanVEXJSON(t, db, target, jammy)
	if !suppressedPairs(doc)[pair{"libssl3", "CVE-2031-9201"}] {
		t.Errorf("distro=jammy statement did not apply on a jammy image\nstderr: %s", stderr)
	}

	noble := writeVEX(t, stmt("CVE-2031-9201",
		product("pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1.18?arch=source&distro=noble")))
	if doc, _ := scanVEXJSON(t, db, target, noble); len(doc.Suppressed) != 0 {
		t.Errorf("distro=noble statement applied on a jammy image: %v", suppressedPairs(doc))
	}
}

const osReleaseChainguard = `ID=chainguard
NAME="Chainguard"
PRETTY_NAME="Chainguard"
`

// (6) The other half of the summary line. Chainguard has no measured purl
// namespace, so its packages get no purl; a finding on one is counted as
// having nothing for a statement to match, rather than passing unremarked.
func TestRun_VEXSummaryCountsFindingsWithoutAPURL(t *testing.T) {
	db := vexDB(t, "Chainguard", vexAdv{"CGA-2031-0301", "CVE-2031-9301", "busybox", "1.36.1-r99"})
	p := filepath.Join(t.TempDir(), "image.tar")
	writeImageTar(t, p, map[string]string{osReleasePath: osReleaseChainguard, apkDBPath: apkThreePackages})
	vexPath := writeVEX(t, stmt("CVE-2031-9301", product("pkg:apk/chainguard/busybox")))

	doc, stderr := scanVEXJSON(t, db, "docker-archive:"+p, vexPath)
	if len(doc.Suppressed) != 0 {
		t.Errorf("suppressed %v with no purl to match", suppressedPairs(doc))
	}
	const want = "vex: 1 of 1 statement(s) matched no finding (0 name an image that is not this target, " +
		"0 skipped); 2 finding(s) carry no purl to match against\n"
	if !hasLine(stderr, "\n"+want) {
		t.Errorf("stderr lacks the summary line %q\nstderr: %s", want, stderr)
	}
}

// No --vex, no summary line: its presence means VEX was applied.
func TestRun_NoVEXNoSummaryLine(t *testing.T) {
	db := alpineVEXDB(t)
	_, stderr := scanVEXJSON(t, db, alpineArchive(t, apkThreePackages))
	if strings.Contains(stderr, "vex: ") {
		t.Errorf("a scan with no --vex printed a VEX summary\nstderr: %s", stderr)
	}
}
