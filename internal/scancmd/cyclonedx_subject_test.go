package scancmd

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/report"
)

// QA 2026-11-04 (reproduced from the 2026-11-02 handoff), end to end. The
// CycloneDX reader walked bom.components only, so a package written as the
// document's subject -- metadata.component, the slot CycloneDX reserves for
// the thing the SBOM is about, which for a library SBOM IS the library -- or
// as one of the subject's own nested components was never cataloged: not
// scanned, not counted, in no skip bucket, exit 0 under `--fail-on low
// --fail-on-incomplete`. The caller's tests: through Run, with the advisory
// on the subject, every shape below yields the finding and exit 1, and the
// same package written in both places is one package and one finding.
//
// The cases are shaped after the live reproduction (lodash 4.17.20 /
// CVE-2021-23337 against the public v9 artifact) with a fake store so the
// suite needs no database.

const (
	cdxStart   = `{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,`
	cdxSubject = `{"type":"library","name":"cdxsubject","version":"1.0.0","purl":"pkg:golang/example.com/cdxsubject@1.0.0"}`
	cdxClean   = `{"type":"library","name":"cdxclean","version":"1.0.0","purl":"pkg:golang/example.com/cdxclean@1.0.0"}`
)

func runCycloneDXSubject(t *testing.T, body string) (int, report.Document, string) {
	t.Helper()
	dbPath := buildMatrixDB(t, []matrixAdv{
		{id: "GHSA-cdx-subject", pkg: "cdxsubject", fixed: "2.0.0", vectors: []string{vecCritical}},
	})
	path := filepath.Join(t.TempDir(), "subject.cdx.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	code := Run(context.Background(), dbPath, path,
		Options{Output: "json", FailOn: &bandLow, FailOnIncomplete: true}, &out, &errOut)
	var doc report.Document
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("decode report: %v\nstdout: %s\nstderr: %s", err, out.String(), errOut.String())
	}
	return code, doc, out.String()
}

func findingIDs(doc report.Document) []string {
	var ids []string
	for _, f := range doc.Findings {
		ids = append(ids, f.Advisory.ID)
	}
	return ids
}

// (a) The subject is the vulnerable library itself; (b) it is a child of a
// purl-less container subject; (c) it sits beside a clean top-level
// component, which stays evaluated. Each must reach the matcher.
func TestRun_CycloneDXSubjectIsScanned(t *testing.T) {
	for _, tc := range []struct {
		name           string
		body           string
		wantComponents int
	}{
		{"subject-only", cdxStart + `"metadata":{"component":` + cdxSubject + `}}`, 1},
		{"subject-child", cdxStart + `"metadata":{"component":{"type":"container","name":"demo","components":[` + cdxSubject + `]}}}`, 1},
		{"subject-beside-clean-component", cdxStart + `"metadata":{"component":` + cdxSubject + `},"components":[` + cdxClean + `]}`, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, doc, out := runCycloneDXSubject(t, tc.body)
			if code != 1 {
				t.Fatalf("Run = %d, want 1: the subject package must be scanned, not dropped as a document root\nstdout: %s", code, out)
			}
			if ids := findingIDs(doc); len(ids) != 1 || ids[0] != "GHSA-cdx-subject" {
				t.Errorf("findings = %v, want exactly [GHSA-cdx-subject]", ids)
			}
			if doc.Summary.Components != tc.wantComponents || doc.Summary.Evaluated != tc.wantComponents {
				t.Errorf("summary components/evaluated = %d/%d, want %d/%d",
					doc.Summary.Components, doc.Summary.Evaluated, tc.wantComponents, tc.wantComponents)
			}
			if doc.Summary.TargetIncomplete != 0 || doc.Summary.NotEvaluated != 0 {
				t.Errorf("summary = %+v, want nothing incomplete", doc.Summary)
			}
		})
	}
}

// (d) The same package written as the subject AND in components -- the
// shape a generator takes when it lists the root package in its own
// inventory -- is one package: one evaluated, one finding, never two.
func TestRun_CycloneDXSubjectDuplicatedInComponentsIsOnePackage(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"same-purl", cdxStart + `"metadata":{"component":` + cdxSubject + `},"components":[` + cdxSubject + `]}`},
		// The purl differs only in a qualifier the identity does not
		// include; name, version and type still say it is one package.
		{"same-name-version-type", cdxStart + `"metadata":{"component":` + cdxSubject + `},"components":[` +
			`{"type":"library","name":"cdxsubject","version":"1.0.0","purl":"pkg:golang/example.com/cdxsubject@1.0.0?package-id=abc"}]}`},
		// Nested under the subject and listed at the top level.
		{"subject-child-and-component", cdxStart + `"metadata":{"component":{"type":"container","name":"demo","components":[` + cdxSubject + `]}},"components":[` + cdxSubject + `]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, doc, out := runCycloneDXSubject(t, tc.body)
			if code != 1 {
				t.Fatalf("Run = %d, want 1\nstdout: %s", code, out)
			}
			if ids := findingIDs(doc); len(ids) != 1 {
				t.Errorf("findings = %v, want the one finding once (the package is listed twice, not present twice)", ids)
			}
			if doc.Summary.Components != 1 || doc.Summary.Evaluated != 1 {
				t.Errorf("summary components/evaluated = %d/%d, want 1/1 (one package, not two)",
					doc.Summary.Components, doc.Summary.Evaluated)
			}
		})
	}
}

// (e) The subject at the fixed version is still evaluated -- counted, exit 0
// because the advisory no longer applies, not because the package was
// skipped. The two outcomes look alike from the exit code alone, which is
// why the summary is held as well.
func TestRun_CycloneDXSubjectAtFixedVersionIsEvaluatedClean(t *testing.T) {
	body := cdxStart + `"metadata":{"component":{"type":"library","name":"cdxsubject","version":"2.0.0","purl":"pkg:golang/example.com/cdxsubject@2.0.0"}}}`
	code, doc, out := runCycloneDXSubject(t, body)
	if code != 0 {
		t.Fatalf("Run = %d, want 0\nstdout: %s", code, out)
	}
	if ids := findingIDs(doc); len(ids) != 0 {
		t.Errorf("findings = %v, want none at the fixed version", ids)
	}
	if doc.Summary.Components != 1 || doc.Summary.Evaluated != 1 {
		t.Errorf("summary components/evaluated = %d/%d, want 1/1: clean because evaluated, not because dropped",
			doc.Summary.Components, doc.Summary.Evaluated)
	}
}

// (f) A subject that is the document's own root -- syft's purl-less
// container, Red Hat's pkg:oci image, a product named without a version --
// is not a package and stays uncounted, as before: the inventory beside it
// is exactly what is scanned, and a strict gate does not trip on the root.
func TestRun_CycloneDXSubjectPseudoRootStaysUncounted(t *testing.T) {
	for _, tc := range []struct{ name, subject string }{
		{"no-purl-container", `{"type":"container","name":"mirror.gcr.io/library/alpine:3.19","version":"sha256:b58899f069c47216f6002a6850143dc6fae0d35eb8b0df9300bbe6327b9c2171"}`},
		{"oci-purl", `{"type":"container","name":"demo","purl":"pkg:oci/demo@sha256:0000000000000000000000000000000000000000000000000000000000000000"}`},
		{"purl-without-version", `{"type":"application","name":"product","purl":"pkg:golang/example.com/product"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := cdxStart + `"metadata":{"component":` + tc.subject + `},"components":[` + cdxClean + `]}`
			code, doc, out := runCycloneDXSubject(t, body)
			if code != 0 {
				t.Fatalf("Run = %d, want 0: a root subject is neither a finding nor an incompleteness\nstdout: %s", code, out)
			}
			if doc.Summary.Components != 1 || doc.Summary.Evaluated != 1 || doc.Summary.NotEvaluated != 0 {
				t.Errorf("summary = %+v, want components/evaluated 1/1 and nothing skipped (the root is not counted)", doc.Summary)
			}
			if strings.Contains(out, "product") || strings.Contains(out, "pkg:oci") {
				t.Errorf("stdout names the root subject as a package:\n%s", out)
			}
		})
	}
}

// (g) A distro package as the subject, or under it, is keyed by the
// document's operating-system component exactly as its top-level twin is.
// The subject walk catalogs into a scratch inventory; a scratch that forgot
// the document's distro keyed a deb purl with no distro qualifier to no
// ecosystem at all -- a coverage skip the matcher reports, which
// --fail-on-incomplete=target does not gate on, so the handoff's exact gate
// exited 0 on a document that names Debian 12 and lists a Debian package.
// With a qualifier naming another release the document still wins (one
// document cannot disagree with itself), so the package is judged against
// Debian 12's fix states, never silently against Debian 11's. The fixture
// advisory carries no severity, so the gate is --fail-on-unknown (D17), as
// the other deb SBOM tests in this package use.
func TestRun_CycloneDXSubjectDistroPackageIsKeyedByTheDocumentDistro(t *testing.T) {
	const debian12 = `{"type":"operating-system","name":"debian","version":"12","properties":[` +
		`{"name":"syft:distro:id","value":"debian"},{"name":"syft:distro:versionID","value":"12"}]}`
	db := vexDB(t, "Debian:12", vexAdv{"DEBIAN-2031-7", "CVE-2031-9007", "bsdutils", "2.38.1-6"})
	for _, purl := range []string{
		"pkg:deb/debian/bsdutils@2.38.1-5?arch=amd64",
		"pkg:deb/debian/bsdutils@2.38.1-5?arch=amd64&distro=debian-11",
	} {
		subject := `{"type":"library","name":"bsdutils","version":"2.38.1-5","purl":"` + purl + `"}`
		for _, tc := range []struct{ name, body string }{
			{"subject", cdxStart + `"metadata":{"component":` + subject + `},"components":[` + debian12 + `]}`},
			{"subject-child", cdxStart + `"metadata":{"component":{"type":"container","name":"demo","components":[` + subject + `]}},"components":[` + debian12 + `]}`},
		} {
			t.Run(tc.name+"/"+purl, func(t *testing.T) {
				path := writeSBOM(t, "cyclonedx", tc.body)
				var out, errOut bytes.Buffer
				code := Run(context.Background(), db, path,
					Options{Output: "json", FailOnUnknown: true, FailOnIncomplete: true, FailOnIncompleteTarget: true}, &out, &errOut)
				var doc report.Document
				if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
					t.Fatalf("decode report: %v\nstdout: %s\nstderr: %s", err, out.String(), errOut.String())
				}
				if code != 1 {
					t.Fatalf("Run = %d, want 1: the subject's deb package must be keyed Debian:12 and matched\nstdout: %s\nstderr: %s", code, out.String(), errOut.String())
				}
				if ids := findingIDs(doc); len(ids) != 1 || ids[0] != "DEBIAN-2031-7" {
					t.Errorf("findings = %v, want exactly [DEBIAN-2031-7]", ids)
				}
				if doc.Summary.Components != 1 || doc.Summary.Evaluated != 1 || doc.Summary.NotEvaluated != 0 {
					t.Errorf("summary = %+v, want components/evaluated 1/1 and nothing skipped", doc.Summary)
				}
			})
		}
	}
}

// (h) A bare purl (no @version) takes its version from the component, so
// two listings of one bare purl at two component versions are two
// packages. Deduping on the purl string alone dropped the subject -- here
// the vulnerable version -- because bom.components carried the same bare
// purl at the fixed version: a silent miss, exit 0.
func TestRun_CycloneDXSubjectBarePURLAtAnotherVersionIsNotDropped(t *testing.T) {
	body := cdxStart + `"metadata":{"component":{"type":"library","name":"cdxsubject","version":"1.0.0","purl":"pkg:golang/example.com/cdxsubject"}},` +
		`"components":[{"type":"library","name":"cdxsubject","version":"2.0.0","purl":"pkg:golang/example.com/cdxsubject"}]}`
	code, doc, out := runCycloneDXSubject(t, body)
	if code != 1 {
		t.Fatalf("Run = %d, want 1: the subject at 1.0.0 is a second package, not a duplicate of the fixed 2.0.0 listing\nstdout: %s", code, out)
	}
	if ids := findingIDs(doc); len(ids) != 1 || ids[0] != "GHSA-cdx-subject" {
		t.Errorf("findings = %v, want exactly [GHSA-cdx-subject]", ids)
	}
	if doc.Summary.Components != 2 || doc.Summary.Evaluated != 2 {
		t.Errorf("summary components/evaluated = %d/%d, want 2/2", doc.Summary.Components, doc.Summary.Evaluated)
	}
}
