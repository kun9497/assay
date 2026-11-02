package scancmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/kun9497/assay/internal/report"
)

// QA 2026-11-02, finding #1. An SBOM's deb purl carries the source version in
// its upstream qualifier ("util-linux@2.38.1-5+deb12u2", as syft and
// OSPackagePURL both write it) and an rpm purl carries the SRPM file name.
// Both readers kept the source NAME and dropped the version, so the matcher's
// source-version branch (D41) never ran on SBOM input: the binary's own
// version, epoch included, was compared with a source-keyed fix. The image
// path judged the same package correctly; the air-gapped SBOM path returned
// exit 0, no findings, no skips.

// sbomDeb is one Debian 12 binary with an upstream qualifier, in both
// formats. The CycloneDX document also carries syft's properties so the
// cataloger has a second place to read a source version from.
func sbomDeb(format, name, version, upstream string) string {
	purl := fmt.Sprintf("pkg:deb/debian/%s@%s?arch=amd64&distro=debian-12&upstream=%s", name, version, upstream)
	switch format {
	case "cyclonedx":
		return fmt.Sprintf(`{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[
 {"type":"library","name":%q,"version":"1:2.38.1-5+deb12u3","purl":%q}]}`, name, purl)
	case "spdx":
		return fmt.Sprintf(`{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","packages":[
 {"SPDXID":"SPDXRef-p","name":%q,"externalRefs":[{"referenceType":"purl","referenceLocator":%q}]}]}`, name, purl)
	}
	panic("unknown format " + format)
}

func writeSBOM(t *testing.T, format, doc string) string {
	t.Helper()
	ext := ".cdx.json"
	if format == "spdx" {
		ext = ".spdx.json"
	}
	path := filepath.Join(t.TempDir(), "doc"+ext)
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func runSBOMJSON(t *testing.T, db, sbom string) (int, report.Document, string) {
	t.Helper()
	var out, stderr bytes.Buffer
	code := Run(context.Background(), db, sbom, Options{Output: "json", FailOnUnknown: true, FailOnIncomplete: true}, &out, &stderr)
	var doc report.Document
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("decode: %v stderr=%s", err, stderr.String())
	}
	return code, doc, stderr.String()
}

// The dpkg shape of TestRun_DebianSameNameBinaryIsJudgedOnItsSourceVersion,
// as an SBOM: bsdutils 1:2.38.1-5+deb12u3 built from util-linux
// 2.38.1-5+deb12u2, which is below the fix. The binary's epoch sorts it
// above the fix, so a reader that drops the source version returns clean.
// The same document with the source AT the fix is clean, so the test cannot
// be passed by matching unconditionally.
func TestRun_SBOMDebBinaryIsJudgedOnItsSourceVersion(t *testing.T) {
	db := vexDB(t, "Debian:12", vexAdv{"DEBIAN-2031-1", "CVE-2031-9001", "util-linux", "2.38.1-5+deb12u3"})
	for _, format := range []string{"cyclonedx", "spdx"} {
		t.Run(format, func(t *testing.T) {
			for _, name := range []string{"bsdutils", "util-linux"} {
				sbom := writeSBOM(t, format, sbomDeb(format, name, "1%3A2.38.1-5%2Bdeb12u3", "util-linux%402.38.1-5%2Bdeb12u2"))
				code, doc, stderr := runSBOMJSON(t, db, sbom)
				if code != 1 || len(doc.Findings) != 1 || len(doc.Skipped) != 0 {
					t.Fatalf("%s: exit=%d findings=%d skips=%d, want 1/1/0: source util-linux 2.38.1-5+deb12u2 is below the fix (stderr=%s)",
						name, code, len(doc.Findings), len(doc.Skipped), stderr)
				}
				f := doc.Findings[0]
				if f.Package.Name != name || f.MatchedName != "util-linux" {
					t.Errorf("%s: finding on %q via %q, want %q via util-linux", name, f.Package.Name, f.MatchedName, name)
				}
				if f.Package.Source == nil || f.Package.Source.Version != "2.38.1-5+deb12u2" {
					t.Errorf("%s: report source = %+v, want version 2.38.1-5+deb12u2 shown", name, f.Package.Source)
				}
			}

			fixed := writeSBOM(t, format, sbomDeb(format, "bsdutils", "1%3A2.38.1-5%2Bdeb12u3", "util-linux%402.38.1-5%2Bdeb12u3"))
			if code, doc, stderr := runSBOMJSON(t, db, fixed); code != 0 || len(doc.Findings) != 0 {
				t.Errorf("source at the fix: exit=%d findings=%d, want clean (stderr=%s)", code, len(doc.Findings), stderr)
			}
		})
	}
}

// sbomRPM is a set of rpm purls in both formats; each entry is
// "name|version|epoch|srpm" (epoch "" for none).
func sbomRPM(format, distro, ns string, pkgs [][4]string) string {
	var purls []string
	for _, p := range pkgs {
		purl := fmt.Sprintf("pkg:rpm/%s/%s@%s?arch=x86_64&distro=%s&upstream=%s", ns, p[0], p[1], distro, p[3])
		if p[2] != "" {
			purl += "&epoch=" + p[2]
		}
		purls = append(purls, purl)
	}
	switch format {
	case "cyclonedx":
		var comps string
		for i, p := range pkgs {
			if i > 0 {
				comps += ","
			}
			comps += fmt.Sprintf(`{"type":"library","name":%q,"version":%q,"purl":%q}`, p[0], p[1], purls[i])
		}
		return `{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[` + comps + `]}`
	case "spdx":
		var ps string
		for i, p := range pkgs {
			if i > 0 {
				ps += ","
			}
			ps += fmt.Sprintf(`{"SPDXID":"SPDXRef-%d","name":%q,"externalRefs":[{"referenceType":"purl","referenceLocator":%q}]}`, i, p[0], purls[i])
		}
		return `{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","packages":[` + ps + `]}`
	}
	panic("unknown format " + format)
}

// The mod_ssl shape (D152's synthetic false negative, D153's image shape),
// as a syft-style SBOM with the upstream qualifier: mod_ssl 1:2.4.62-1.fc40
// built from httpd 2.4.62-1.fc40, httpd installed beside it, fix at
// 2.4.63-1.fc40. Judged on its own version the epoch hides the fix; judged
// on the SRPM's version with the main package's epoch (D153's rule, now run
// on SBOM input too) it is found through httpd.
func TestRun_SBOMRPMSubpackageIsJudgedOnTheSRPMEVR(t *testing.T) {
	db := vexDB(t, "Fedora:40", vexAdv{"FEDORA-2031-1", "CVE-2031-9002", "httpd", "2.4.63-1.fc40"})
	for _, format := range []string{"cyclonedx", "spdx"} {
		t.Run(format, func(t *testing.T) {
			sbom := writeSBOM(t, format, sbomRPM(format, "fedora-40", "fedora", [][4]string{
				{"httpd", "2.4.62-1.fc40", "", "httpd-2.4.62-1.fc40.src.rpm"},
				{"mod_ssl", "2.4.62-1.fc40", "1", "httpd-2.4.62-1.fc40.src.rpm"},
			}))
			code, doc, stderr := runSBOMJSON(t, db, sbom)
			viaSource := false
			for _, f := range doc.Findings {
				if f.Package.Name == "mod_ssl" && f.MatchedName == "httpd" {
					viaSource = true
					if f.Package.Source == nil || f.Package.Source.Version != "2.4.62-1.fc40" {
						t.Errorf("mod_ssl report source = %+v, want httpd 2.4.62-1.fc40 (no epoch: httpd carries none)", f.Package.Source)
					}
				}
			}
			if code != 1 || !viaSource || len(doc.Skipped) != 0 {
				t.Errorf("exit=%d, mod_ssl via httpd=%v, skips=%d, findings=%d; want exit 1 and mod_ssl reached through httpd (stderr=%s)",
					code, viaSource, len(doc.Skipped), len(doc.Findings), stderr)
			}
		})
	}
}

// The other direction of the same rule: perl-B 1.80-484.el9 at epoch 0 is
// built from perl, whose main package carries epoch 4. The fix is
// 4:5.32.1-481.el9. The SRPM's version-release alone (5.32.1-484.el9) sorts
// below every perl fix, a permanent false positive; with the main package's
// epoch it is 4:5.32.1-484.el9 and clean. This is the shape that rules out
// "name and version from the SRPM, no epoch" for the SBOM path.
func TestRun_SBOMRPMSubpackageTakesTheMainPackageEpoch(t *testing.T) {
	db := vexDB(t, "Red Hat:9", vexAdv{"RHSA-2031:1", "CVE-2031-9003", "perl", "4:5.32.1-481.el9"})
	for _, format := range []string{"cyclonedx", "spdx"} {
		t.Run(format, func(t *testing.T) {
			sbom := writeSBOM(t, format, sbomRPM(format, "rhel-9.4", "redhat", [][4]string{
				{"perl", "5.32.1-484.el9", "4", "perl-5.32.1-484.el9.src.rpm"},
				{"perl-B", "1.80-484.el9", "", "perl-5.32.1-484.el9.src.rpm"},
			}))
			code, doc, stderr := runSBOMJSON(t, db, sbom)
			if code != 0 || len(doc.Findings) != 0 || len(doc.Skipped) != 0 {
				t.Errorf("exit=%d findings=%d skips=%d, want clean: perl-B is judged as perl 4:5.32.1-484.el9 (stderr=%s)",
					code, len(doc.Findings), len(doc.Skipped), stderr)
			}
		})
	}
}

// With nothing else from the SRPM in the document, D153's step 4 keeps the
// binary's own epoch, and mod_ssl's 1 still hides the httpd fix. This is the
// residual D153 recorded for an image ("Gives up"), reached the same way on
// an SBOM; it is pinned so a change to it is a decision and not a drift.
// The source purl of an SPDX GENERATES edge states the epoch and does not
// have this gap (TestRun_SPDXSourceRelationshipDoesNotBorrowTheBinaryEpoch).
func TestRun_SBOMLoneRPMSubpackageKeepsItsOwnEpoch(t *testing.T) {
	db := vexDB(t, "Fedora:40", vexAdv{"FEDORA-2031-1", "CVE-2031-9002", "httpd", "2.4.63-1.fc40"})
	sbom := writeSBOM(t, "cyclonedx", sbomRPM("cyclonedx", "fedora-40", "fedora", [][4]string{
		{"mod_ssl", "2.4.62-1.fc40", "1", "httpd-2.4.62-1.fc40.src.rpm"},
	}))
	code, doc, _ := runSBOMJSON(t, db, sbom)
	if code != 0 || len(doc.Findings) != 0 {
		t.Errorf("exit=%d findings=%d; the lone subpackage keeps its own epoch (D153 step 4) and is not found", code, len(doc.Findings))
	}
	if len(doc.Skipped) != 0 {
		t.Errorf("skips=%d, want 0", len(doc.Skipped))
	}
}

// A source statement (D121) names the SOURCE version. With Source.Version
// read from the purl, vex compares it against that and not against the
// binary's own version, so the statement written against the source applies
// and one written at the binary's version does not.
func TestRun_SBOMDebSourceStatementAppliesAtTheSourceVersion(t *testing.T) {
	db := vexDB(t, "Debian:12", vexAdv{"DEBIAN-2031-1", "CVE-2031-9001", "util-linux", "2.38.1-5+deb12u3"})
	sbom := writeSBOM(t, "cyclonedx", sbomDeb("cyclonedx", "bsdutils", "1%3A2.38.1-5%2Bdeb12u3", "util-linux%402.38.1-5%2Bdeb12u2"))

	atSource := writeVEX(t, stmt("CVE-2031-9001", product("pkg:deb/debian/util-linux@2.38.1-5+deb12u2?arch=source")))
	doc, stderr := scanVEXJSON(t, db, sbom, atSource)
	if len(doc.Suppressed) != 1 || len(doc.Findings) != 0 {
		t.Errorf("source statement: suppressed=%d findings=%d, want 1/0 (stderr=%s)", len(doc.Suppressed), len(doc.Findings), stderr)
	}

	atBinary := writeVEX(t, stmt("CVE-2031-9001", product("pkg:deb/debian/util-linux@1:2.38.1-5+deb12u3?arch=source")))
	doc, stderr = scanVEXJSON(t, db, sbom, atBinary)
	if len(doc.Suppressed) != 0 || len(doc.Findings) != 1 {
		t.Errorf("statement at the binary's version: suppressed=%d findings=%d, want 0/1 (stderr=%s)", len(doc.Suppressed), len(doc.Findings), stderr)
	}
}
