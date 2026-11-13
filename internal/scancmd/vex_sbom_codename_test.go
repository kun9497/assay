package scancmd

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/kun9497/assay/internal/report"
)

// Main QA of 67e2cf6 (2026-11-13), through Run: a syft CycloneDX SBOM of an
// Ubuntu image declares the OS with syft:distro:versionCodename=jammy and
// its apt with the numeric distro=ubuntu-22.04 purl. That codename is the
// scan's evidence, as os-release's VERSION_CODENAME is on the image itself,
// so a jammy / JAMMY / ubuntu-jammy statement applies to the SBOM as it does
// to the image (67e2cf6 suppressed two advisories on the image and none on
// its SBOM). A codename that contradicts the OS version, an OS with no
// codename, and an OS declared only in an unrelated branch of the document
// exempt nothing; noble is refused throughout.
func TestRun_VEXUbuntuCodenameFromTheSBOMOperatingSystem(t *testing.T) {
	db := vexDB(t, "Ubuntu:22.04:LTS", vexAdv{"UBUNTU-2031-0106", "CVE-2031-9106", "apt", "2.4.99"})
	want := pair{"apt", "CVE-2031-9106"}
	const apt = `{"type":"library","name":"apt","version":"2.4.14","purl":"pkg:deb/ubuntu/apt@2.4.14?arch=amd64&distro=ubuntu-22.04"}`
	osComponent := func(codename string) string {
		props := `{"name":"syft:distro:id","value":"ubuntu"},{"name":"syft:distro:versionID","value":"22.04"},{"name":"syft:distro:prettyName","value":"Ubuntu 22.04.5 LTS"}`
		if codename != "" {
			props += `,{"name":"syft:distro:versionCodename","value":"` + codename + `"}`
		}
		return `{"type":"operating-system","name":"ubuntu","version":"22.04","properties":[` + props + `]}`
	}
	sbom := func(name, components string) string {
		doc := `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[` + components + `]}`
		p := filepath.Join(t.TempDir(), name+".cdx.json")
		if err := os.WriteFile(p, []byte(doc), 0o644); err != nil {
			t.Fatal(err)
		}
		return "sbom:" + p
	}
	shapes := map[string]string{
		"os jammy":   osComponent("jammy") + "," + apt,
		"os noble":   osComponent("noble") + "," + apt,
		"os without": osComponent("") + "," + apt,
		// The branch is a second Ubuntu package of its own, keyed by its
		// purl (no OS beside it at the top), with the OS among its children.
		"os in a branch":   `{"type":"library","name":"base-files","version":"12ubuntu4.6","purl":"pkg:deb/ubuntu/base-files@12ubuntu4.6?arch=amd64&distro=ubuntu-22.04","components":[` + osComponent("jammy") + `]},` + apt,
		"os after the apt": apt + "," + osComponent("jammy"),
	}
	for _, tc := range []struct {
		shape, statement string
		suppressed       bool
	}{
		{"os jammy", "jammy", true},
		{"os jammy", "JAMMY", true},
		{"os jammy", "ubuntu-jammy", true},
		{"os jammy", "ubuntu-22.04", true},
		{"os jammy", "noble", false},
		{"os after the apt", "JAMMY", true},
		// The OS says 22.04 and noble: the document contradicts itself,
		// and neither codename exempts the 22.04 install.
		{"os noble", "noble", false},
		{"os noble", "jammy", false},
		{"os noble", "ubuntu-22.04", true},
		{"os without", "jammy", false},
		{"os without", "JAMMY", false},
		{"os without", "ubuntu-22.04", true},
		// An OS in another branch names no target (D166); its codename is
		// not this install's evidence.
		{"os in a branch", "JAMMY", false},
		{"os in a branch", "ubuntu-22.04", true},
	} {
		t.Run(tc.shape+", statement "+tc.statement, func(t *testing.T) {
			var out, errOut bytes.Buffer
			code := Run(context.Background(), db, sbom(tc.shape, shapes[tc.shape]), Options{Output: "json", FailOnUnknown: true, FailOnIncompleteTarget: true,
				VEXFiles: []string{writeVEX(t, stmt("CVE-2031-9106", product("pkg:deb/ubuntu/apt@2.4.14?arch=amd64&distro="+tc.statement)))}}, &out, &errOut)
			var doc report.Document
			if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
				t.Fatalf("stdout is not one JSON document: %v\nstderr: %s", err, errOut.String())
			}
			sup, kept := suppressedPairs(doc), pairsOf(doc.Findings)
			wantCode := 1
			if tc.suppressed {
				wantCode = 0
			}
			wantEvaluated := 1
			if tc.shape == "os in a branch" {
				wantEvaluated = 2
			}
			if sup[want] != tc.suppressed || kept[want] == tc.suppressed || code != wantCode || doc.Summary.Evaluated != wantEvaluated {
				t.Fatalf("suppressed = %v, kept = %v, exit %d, evaluated %d; want suppressed %v, exit %d, evaluated %d\nstderr: %s",
					sup[want], kept[want], code, doc.Summary.Evaluated, tc.suppressed, wantCode, wantEvaluated, errOut.String())
			}
		})
	}
}
