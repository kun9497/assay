package scancmd

import (
	"fmt"
	"strings"
	"testing"
)

// QA 2026-11-20. Trivy writes an OS package's source in its own properties
// (aquasecurity:trivy:SrcName / SrcVersion / SrcRelease / SrcEpoch) and never
// in the purl's upstream qualifier, which was the only spelling the SBOM
// readers knew. A Trivy document's libssl3 was keyed to its release, looked up
// under the binary name alone, judged clean and counted as evaluated: on
// Trivy's own Debian 10.2 golden 70 of 99 Debian findings were missing, with
// exit 0 under every incompleteness gate.

// trivyProps renders Trivy's source properties; an empty value is a property
// Trivy would not have written.
func trivyProps(srcName, srcVersion, srcRelease, srcEpoch string) string {
	var props []string
	for _, p := range [][2]string{
		{"aquasecurity:trivy:PkgType", "debian"},
		{"aquasecurity:trivy:SrcEpoch", srcEpoch},
		{"aquasecurity:trivy:SrcName", srcName},
		{"aquasecurity:trivy:SrcRelease", srcRelease},
		{"aquasecurity:trivy:SrcVersion", srcVersion},
	} {
		if p[1] != "" {
			props = append(props, fmt.Sprintf(`{"name":%q,"value":%q}`, p[0], p[1]))
		}
	}
	return strings.Join(props, ",")
}

// trivyBOM is one OS package under an operating-system component, the shape
// Trivy emits: the release is on the OS component, the purl has no upstream.
func trivyBOM(osName, osVersion, purl, name, version, props string) string {
	return fmt.Sprintf(`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,
 "metadata":{"tools":{"components":[{"type":"application","group":"aquasecurity","name":"trivy","version":"dev"}]}},
 "components":[
  {"type":"operating-system","name":%q,"version":%q},
  {"type":"library","name":%q,"version":%q,"purl":%q,"properties":[%s]}]}`,
		osName, osVersion, name, version, purl, props)
}

// libssl3 is built from openssl and Debian's advisory names openssl. The
// source below the fix must be found; the same document with the source AT
// the fix must be clean, so reading the name while dropping the version (or
// matching unconditionally) cannot pass both rows.
func TestRun_TrivySBOMDebIsJudgedThroughItsSourcePackage(t *testing.T) {
	db := vexDB(t, "Debian:12", vexAdv{"DEBIAN-2031-7", "CVE-2031-9007", "openssl", "3.0.13-1~deb12u1"})
	const purl = "pkg:deb/debian/libssl3@3.0.11-1~deb12u2?arch=amd64&distro=debian-12.4"

	below := writeSBOM(t, "cyclonedx", trivyBOM("debian", "12.4", purl, "libssl3", "3.0.11-1~deb12u2",
		trivyProps("openssl", "3.0.11", "1~deb12u2", "")))
	code, doc, stderr := runSBOMJSON(t, db, below)
	if code != 1 || len(doc.Findings) != 1 || len(doc.Skipped) != 0 {
		t.Fatalf("source below the fix: exit=%d findings=%d skips=%d, want 1/1/0 (stderr=%s)",
			code, len(doc.Findings), len(doc.Skipped), stderr)
	}
	if got := doc.Findings[0].Package.Name; got != "libssl3" {
		t.Errorf("finding is on %q, want the installed binary libssl3", got)
	}

	at := writeSBOM(t, "cyclonedx", trivyBOM("debian", "12.4", purl, "libssl3", "3.0.11-1~deb12u2",
		trivyProps("openssl", "3.0.13", "1~deb12u1", "")))
	code, doc, stderr = runSBOMJSON(t, db, at)
	if code != 0 || len(doc.Findings) != 0 || len(doc.Skipped) != 0 {
		t.Fatalf("source at the fix: exit=%d findings=%d skips=%d, want 0/0/0 (stderr=%s)",
			code, len(doc.Findings), len(doc.Skipped), stderr)
	}
}

// The epoch is a property of its own. login 1:4.5-1.1 is built from shadow
// 1:4.5-1.1, which sorts ABOVE an epoch-less fix of 4.6-1; with SrcEpoch
// dropped the source reads 4.5-1.1 and the package is reported. The second
// row is the same package against a fix its epoch does not clear.
func TestRun_TrivySBOMDebSourceCarriesItsEpoch(t *testing.T) {
	const purl = "pkg:deb/debian/login@4.5-1.1?arch=amd64&distro=debian-10.2&epoch=1"
	sbom := writeSBOM(t, "cyclonedx", trivyBOM("debian", "10.2", purl, "login", "1:4.5-1.1",
		trivyProps("shadow", "4.5", "1.1", "1")))

	db := vexDB(t, "Debian:10", vexAdv{"DEBIAN-2031-8", "CVE-2031-9008", "shadow", "4.6-1"})
	code, doc, stderr := runSBOMJSON(t, db, sbom)
	if code != 0 || len(doc.Findings) != 0 || len(doc.Skipped) != 0 {
		t.Fatalf("epoch-less fix: exit=%d findings=%d skips=%d, want 0/0/0: shadow 1:4.5-1.1 is above 4.6-1 (stderr=%s)",
			code, len(doc.Findings), len(doc.Skipped), stderr)
	}

	db = vexDB(t, "Debian:10", vexAdv{"DEBIAN-2031-9", "CVE-2031-9009", "shadow", "1:4.5-2"})
	code, doc, stderr = runSBOMJSON(t, db, sbom)
	if code != 1 || len(doc.Findings) != 1 {
		t.Fatalf("fix under the same epoch: exit=%d findings=%d, want 1/1 (stderr=%s)", code, len(doc.Findings), stderr)
	}
}

// Alpine advisories are source-keyed too; an apk source carries no version
// because the binary's own is the source's.
func TestRun_TrivySBOMApkIsJudgedThroughItsOriginPackage(t *testing.T) {
	db := vexDB(t, "Alpine:v3.19", vexAdv{"ALPINE-2031-7", "CVE-2031-9017", "openssl", "3.1.4-r5"})
	const purl = "pkg:apk/alpine/libssl3@3.1.4-r2?arch=x86_64&distro=3.19.0"
	sbom := writeSBOM(t, "cyclonedx", trivyBOM("alpine", "3.19.0", purl, "libssl3", "3.1.4-r2",
		trivyProps("openssl", "3.1.4-r2", "", "")))
	code, doc, stderr := runSBOMJSON(t, db, sbom)
	if code != 1 || len(doc.Findings) != 1 || len(doc.Skipped) != 0 {
		t.Fatalf("exit=%d findings=%d skips=%d, want 1/1/0 (stderr=%s)", code, len(doc.Findings), len(doc.Skipped), stderr)
	}
}

// A document carrying both spellings keeps the purl's: the upstream qualifier
// is the statement SPDX readers see too, and the two agree when a producer
// writes both. Here they are made to disagree so the precedence is visible.
func TestRun_TrivySourcePropertyDoesNotOverrideThePurl(t *testing.T) {
	db := vexDB(t, "Debian:12", vexAdv{"DEBIAN-2031-7", "CVE-2031-9007", "openssl", "3.0.13-1~deb12u1"})
	const purl = "pkg:deb/debian/libssl3@3.0.11-1~deb12u2?arch=amd64&distro=debian-12.4&upstream=openssl"
	sbom := writeSBOM(t, "cyclonedx", trivyBOM("debian", "12.4", purl, "libssl3", "3.0.11-1~deb12u2",
		trivyProps("not-openssl", "9.9", "9", "")))
	code, doc, stderr := runSBOMJSON(t, db, sbom)
	if code != 1 || len(doc.Findings) != 1 {
		t.Fatalf("exit=%d findings=%d, want 1/1: the purl names openssl (stderr=%s)", code, len(doc.Findings), stderr)
	}
}
