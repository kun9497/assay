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

// Main QA of f554fb2 (2026-11-13), through Run, in the shapes the QA built
// from syft's own Ubuntu 22.04 SBOM. A codename statement applies only where
// the package's own operating-system declaration (or, when that states none,
// the document's of the same release) names that codename consistently with
// its version: kinetic beside 22.04, two different codenames on one
// component, a branch declaring noble or both codenames, and a branch
// contradicting the document all exempt nothing, whichever order the
// document lists them in; a branch's own jammy applies with no OS at the top.
func TestRun_VEXUbuntuCodenameBoundaries(t *testing.T) {
	db := vexDB(t, "Ubuntu:22.04:LTS", vexAdv{"UBUNTU-2031-0106", "CVE-2031-9106", "apt", "2.4.99"})
	want := pair{"apt", "CVE-2031-9106"}
	osWith := func(codenames ...string) string {
		props := `{"name":"syft:distro:id","value":"ubuntu"},{"name":"syft:distro:versionID","value":"22.04"},{"name":"syft:distro:prettyName","value":"Ubuntu 22.04.5 LTS"}`
		for _, c := range codenames {
			props += `,{"name":"syft:distro:versionCodename","value":"` + c + `"}`
		}
		return `{"type":"operating-system","name":"ubuntu","version":"22.04","properties":[` + props + `]}`
	}
	const apt = `{"type":"library","name":"apt","version":"2.4.14","purl":"pkg:deb/ubuntu/apt@2.4.14?arch=amd64&distro=ubuntu-22.04"}`
	branch := func(children ...string) string {
		out := `{"type":"library","name":"is-number","version":"7.0.0","purl":"pkg:npm/is-number@7.0.0","components":[`
		for i, c := range children {
			if i > 0 {
				out += ","
			}
			out += c
		}
		return out + `]}`
	}
	shapes := map[string]string{
		"kinetic on 22.04":       osWith("kinetic") + "," + apt,
		"jammy then noble":       osWith("jammy", "noble") + "," + apt,
		"noble then jammy":       osWith("noble", "jammy") + "," + apt,
		"jammy twice":            osWith("jammy", "JAMMY") + "," + apt,
		"top jammy, child noble": osWith("jammy") + "," + branch(osWith("noble"), apt),
		"top jammy, child both":  osWith("jammy") + "," + branch(osWith("jammy"), osWith("noble"), apt),
		"top jammy, child jammy": osWith("jammy") + "," + branch(osWith("jammy"), apt),
		"top jammy, child none":  osWith("jammy") + "," + branch(osWith(), apt),
		"no top, child jammy":    branch(osWith("jammy"), apt),
		"no top, child none":     branch(osWith(), apt),
	}
	for _, tc := range []struct {
		shape, statement string
		suppressed       bool
	}{
		{"kinetic on 22.04", "kinetic", false},
		{"kinetic on 22.04", "KINETIC", false},
		{"kinetic on 22.04", "ubuntu-kinetic", false},
		{"kinetic on 22.04", "ubuntu-22.10", false},
		{"kinetic on 22.04", "jammy", false},
		{"kinetic on 22.04", "ubuntu-22.04", true},
		{"jammy then noble", "JAMMY", false},
		{"noble then jammy", "JAMMY", false},
		{"noble then jammy", "noble", false},
		{"jammy then noble", "ubuntu-22.04", true},
		{"jammy twice", "JAMMY", true},
		{"top jammy, child noble", "JAMMY", false},
		{"top jammy, child both", "JAMMY", false},
		{"top jammy, child jammy", "JAMMY", true},
		{"top jammy, child none", "JAMMY", true},
		{"top jammy, child noble", "ubuntu-22.04", true},
		{"no top, child jammy", "JAMMY", true},
		{"no top, child none", "JAMMY", false},
	} {
		t.Run(tc.shape+", statement "+tc.statement, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "sbom.cdx.json")
			doc := `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[` + shapes[tc.shape] + `]}`
			if err := os.WriteFile(p, []byte(doc), 0o644); err != nil {
				t.Fatal(err)
			}
			var out, errOut bytes.Buffer
			code := Run(context.Background(), db, "sbom:"+p, Options{Output: "json", FailOnUnknown: true, FailOnIncompleteTarget: true,
				VEXFiles: []string{writeVEX(t, stmt("CVE-2031-9106", product("pkg:deb/ubuntu/apt@2.4.14?arch=amd64&distro="+tc.statement)))}}, &out, &errOut)
			var rep report.Document
			if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
				t.Fatalf("stdout is not one JSON document: %v\nstderr: %s", err, errOut.String())
			}
			sup, kept := suppressedPairs(rep), pairsOf(rep.Findings)
			wantCode := 1
			if tc.suppressed {
				wantCode = 0
			}
			if sup[want] != tc.suppressed || kept[want] == tc.suppressed || code != wantCode {
				t.Fatalf("suppressed = %v, kept = %v, exit %d; want suppressed %v, exit %d\nstderr: %s",
					sup[want], kept[want], code, tc.suppressed, wantCode, errOut.String())
			}
		})
	}
}

// The image path holds os-release to the same rule (vexTarget): an image
// whose os-release says VERSION_CODENAME=kinetic beside VERSION_ID 22.04
// gives no codename evidence, so a kinetic statement does not exempt its
// libssl3; the image's own jammy still applies (TestRun_VEXUbuntuCodenameDistro).
func TestRun_VEXUbuntuImageCodenameHeldToItsRelease(t *testing.T) {
	db := vexDB(t, "Ubuntu:22.04:LTS", vexAdv{"UBUNTU-2031-0201", "CVE-2031-9201", "openssl", "3.0.2-0ubuntu1.99"})
	p := filepath.Join(t.TempDir(), "image.tar")
	kinetic := `PRETTY_NAME="Ubuntu 22.04.5 LTS"
NAME="Ubuntu"
VERSION_ID="22.04"
VERSION_CODENAME=kinetic
ID=ubuntu
`
	writeImageTar(t, p, map[string]string{osReleasePath: kinetic, dpkgDBPath: dpkgUbuntuLibssl3})
	for _, st := range []string{"kinetic", "KINETIC"} {
		v := writeVEX(t, stmt("CVE-2031-9201", product("pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1.18?arch=source&distro="+st)))
		if doc, stderr := scanVEXJSON(t, db, "docker-archive:"+p, v); len(doc.Suppressed) != 0 {
			t.Errorf("distro=%s statement applied on a 22.04 image that names kinetic: %v\nstderr: %s", st, suppressedPairs(doc), stderr)
		}
	}
}
