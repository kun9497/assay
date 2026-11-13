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

// Main QA of 672fe7a (2026-11-13), through Run: one install listed twice --
// at the top level and under the subject -- with the two purls naming two
// point releases (12.15 and 12.14) under an OS of 12.15. The listings merge
// into one package, and the document contradicts itself about its point
// release, so neither point statement exonerates it and only the shared
// major's does, WHICHEVER position holds which purl: main had suppressed
// CVE-2011-3374 with the 12.15 purl at the top level and kept it the other
// way round; on a fixture database holding one unrated advisory the same two
// shapes written as 12.10/12.11 exited 0 and 1 under --fail-on-unknown.
// Every arch shape of the pair, since the dedupe treats a bare listing and
// an arch-stating one as the same install.
func TestRun_VEXTwoPointReleasesListedForOneInstallInEitherPosition(t *testing.T) {
	db := vexDB(t, "Debian:12", vexAdv{"DEBIAN-2031-0103", "CVE-2031-9103", "sample", "99"})
	want := pair{"example", "CVE-2031-9103"}
	sbom := func(top, topArch, subject, subjectArch string) string {
		purl := func(release, arch string) string {
			q := "distro=" + release + "&upstream=sample%407"
			if arch != "" {
				q = "arch=" + arch + "&" + q
			}
			return "pkg:deb/debian/example@1.0?" + q
		}
		doc := `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[` +
			`{"type":"operating-system","name":"debian","version":"12.15","properties":[` +
			`{"name":"syft:distro:id","value":"debian"},{"name":"syft:distro:versionID","value":"12.15"}]},` +
			`{"type":"library","name":"example","version":"1.0","purl":"` + purl(top, topArch) + `"}],` +
			`"metadata":{"component":{"type":"container","name":"subject","components":[` +
			`{"type":"library","name":"example","version":"1.0","purl":"` + purl(subject, subjectArch) + `"}]}}}`
		p := filepath.Join(t.TempDir(), "dup.cdx.json")
		if err := os.WriteFile(p, []byte(doc), 0o644); err != nil {
			t.Fatal(err)
		}
		return "sbom:" + p
	}
	productFor := func(release string) string {
		return product("pkg:deb/debian/example@1.0?distro=" + release + "&upstream=sample%407")
	}
	for _, pos := range []struct{ top, subject string }{{"debian-12.15", "debian-12.14"}, {"debian-12.14", "debian-12.15"}} {
		for _, arch := range []struct{ top, subject string }{{"amd64", "amd64"}, {"", ""}, {"amd64", ""}, {"", "amd64"}} {
			target := sbom(pos.top, arch.top, pos.subject, arch.subject)
			label := "top " + pos.top + "/" + arch.top + ", subject " + pos.subject + "/" + arch.subject
			t.Run(label+", no VEX", func(t *testing.T) {
				doc, stderr := scanVEXJSON(t, db, target)
				if len(doc.Findings) != 1 || !pairsOf(doc.Findings)[want] || doc.Summary.Components != 1 {
					t.Fatalf("findings %v, components %d; want the one merged package with its finding\nstderr: %s", pairsOf(doc.Findings), doc.Summary.Components, stderr)
				}
			})
			for _, tc := range []struct {
				statement  string
				suppressed bool
			}{{"debian-12.15", false}, {"debian-12.14", false}, {"debian-12", true}} {
				t.Run(label+", statement "+tc.statement, func(t *testing.T) {
					doc, stderr := scanVEXJSON(t, db, target, writeVEX(t, stmt("CVE-2031-9103", productFor(tc.statement))))
					sup, kept := suppressedPairs(doc), pairsOf(doc.Findings)
					if sup[want] != tc.suppressed || kept[want] == tc.suppressed {
						t.Fatalf("suppressed = %v, kept = %v; want suppressed %v\nstderr: %s", sup[want], kept[want], tc.suppressed, stderr)
					}
				})
			}
			// The gate the QA ran: the point statement with --fail-on-unknown
			// exits 1 in both positions, since the unrated finding stands.
			t.Run(label+", --fail-on-unknown with the 12.15 statement exits 1", func(t *testing.T) {
				var out, errOut bytes.Buffer
				code := Run(context.Background(), db, target, Options{Output: "json", FailOnUnknown: true,
					VEXFiles: []string{writeVEX(t, stmt("CVE-2031-9103", productFor("debian-12.15")))}}, &out, &errOut)
				var rep report.Document
				if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
					t.Fatalf("stdout is not one JSON document: %v\n%s", err, errOut.String())
				}
				if code != 1 || len(rep.Suppressed) != 0 || !strings.Contains(errOut.String(), "1 of 1 statement(s) matched no finding") {
					t.Fatalf("Run = %d, suppressed %d; want 1 and none\nstderr: %s", code, len(rep.Suppressed), errOut.String())
				}
			})
		}
	}
}
