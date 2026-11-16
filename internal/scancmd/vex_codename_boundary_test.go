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

// The shapes the boundary table cannot reach with one list of components:
// an OS of a retired release (22.10) whose codename names another retired
// one, a top level of two releases beside a subject that is the jammy OS,
// and the two listings of one apt -- at the top and under the subject --
// whose own OS declarations say different things about the codename.
func TestRun_VEXUbuntuCodenameAcrossListingsAndRetiredReleases(t *testing.T) {
	osOf := func(version, codename string) string {
		props := `{"name":"syft:distro:id","value":"ubuntu"},{"name":"syft:distro:versionID","value":"` + version + `"}`
		if codename != "" {
			props += `,{"name":"syft:distro:versionCodename","value":"` + codename + `"}`
		}
		return `{"type":"operating-system","name":"ubuntu","version":"` + version + `","properties":[` + props + `]}`
	}
	apt := func(release string) string {
		return `{"type":"library","name":"apt","version":"2.4.14","purl":"pkg:deb/ubuntu/apt@2.4.14?arch=amd64&distro=ubuntu-` + release + `"}`
	}
	subjectOf := func(children string) string {
		return `,"metadata":{"component":{"type":"container","name":"subject","components":[` + children + `]}}`
	}
	for _, tc := range []struct {
		name, key, top, meta, statement string
		suppressed                      bool
	}{
		// 22.10 is kinetic; lunar is 23.04. Without the retired table a
		// codename the tracker table does not know was accepted for a
		// release it does not name.
		{"22.10 OS saying lunar, statement lunar", "Ubuntu:22.10", osOf("22.10", "lunar") + "," + apt("22.10"), "", "lunar", false},
		{"22.10 OS saying kinetic, statement kinetic", "Ubuntu:22.10", osOf("22.10", "kinetic") + "," + apt("22.10"), "", "kinetic", true},
		// Two releases at the top: the apt there answers to neither OS's
		// codename, though the subject is a jammy OS.
		{"top 22.04 and 24.04, subject jammy", "Ubuntu:22.04:LTS", osOf("22.04", "jammy") + "," + osOf("24.04", "noble") + "," + apt("22.04"), `,"metadata":{"component":` + osOf("22.04", "jammy") + `}`, "JAMMY", false},
		// One apt, two listings: the subject's own OS states jammy while the
		// top's states none -- the merged install carries jammy; and a top
		// jammy beside a subject OS contradicting itself carries nothing.
		{"top OS no codename, subject OS jammy", "Ubuntu:22.04:LTS", osOf("22.04", "") + "," + apt("22.04"), subjectOf(osOf("22.04", "jammy") + "," + apt("22.04")), "JAMMY", true},
		{"top OS jammy, subject OS noble on 22.04", "Ubuntu:22.04:LTS", osOf("22.04", "jammy") + "," + apt("22.04"), subjectOf(osOf("22.04", "noble") + "," + apt("22.04")), "JAMMY", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := vexDB(t, tc.key, vexAdv{"UBUNTU-2031-0107", "CVE-2031-9107", "apt", "2.4.99"})
			want := pair{"apt", "CVE-2031-9107"}
			p := filepath.Join(t.TempDir(), "sbom.cdx.json")
			doc := `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[` + tc.top + `]` + tc.meta + `}`
			if err := os.WriteFile(p, []byte(doc), 0o644); err != nil {
				t.Fatal(err)
			}
			var out, errOut bytes.Buffer
			code := Run(context.Background(), db, "sbom:"+p, Options{Output: "json", FailOnUnknown: true,
				VEXFiles: []string{writeVEX(t, stmt("CVE-2031-9107", product("pkg:deb/ubuntu/apt@2.4.14?arch=amd64&distro="+tc.statement)))}}, &out, &errOut)
			var rep report.Document
			if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
				t.Fatalf("stdout is not one JSON document: %v\nstderr: %s", err, errOut.String())
			}
			sup, kept := suppressedPairs(rep), pairsOf(rep.Findings)
			if sup[want] != tc.suppressed || kept[want] == tc.suppressed {
				t.Fatalf("suppressed = %v, kept = %v, exit %d; want suppressed %v\nstderr: %s",
					sup[want], kept[want], code, tc.suppressed, errOut.String())
			}
		})
	}
}

// PR #328 review, through Run: an Ubuntu OS with no version still states its
// codename, as a sibling, as the branch's own OS or alone; a parent OS's
// codename evidence carries to a nearer OS of the same release; and a
// codename this build does not know beside a release it does is refused.
func TestRun_VEXUbuntuCodenameFromVersionlessAndEnclosingOS(t *testing.T) {
	db := vexDB(t, "Ubuntu:22.04:LTS", vexAdv{"UBUNTU-2031-0108", "CVE-2031-9108", "apt", "2.4.99"})
	want := pair{"apt", "CVE-2031-9108"}
	osOf := func(version, codename string, children ...string) string {
		props := `{"name":"syft:distro:id","value":"ubuntu"}`
		if version != "" {
			props += `,{"name":"syft:distro:versionID","value":"` + version + `"}`
		}
		if codename != "" {
			props += `,{"name":"syft:distro:versionCodename","value":"` + codename + `"}`
		}
		out := `{"type":"operating-system","name":"ubuntu","version":"` + version + `","properties":[` + props + `]`
		if len(children) > 0 {
			out += `,"components":[` + strings.Join(children, ",") + `]`
		}
		return out + `}`
	}
	const apt = `{"type":"library","name":"apt","version":"2.4.14","purl":"pkg:deb/ubuntu/apt@2.4.14?arch=amd64&distro=ubuntu-22.04"}`
	branch := func(children ...string) string {
		return `{"type":"library","name":"is-number","version":"7.0.0","purl":"pkg:npm/is-number@7.0.0","components":[` + strings.Join(children, ",") + `]}`
	}
	for _, tc := range []struct {
		name, components, meta, statement string
		suppressed                        bool
	}{
		{"22.04 jammy beside a version-less noble", osOf("22.04", "jammy") + "," + osOf("", "noble") + "," + apt, "", "JAMMY", false},
		{"a version-less noble beside 22.04 jammy", osOf("", "noble") + "," + osOf("22.04", "jammy") + "," + apt, "", "JAMMY", false},
		{"top jammy, branch OS only noble", osOf("22.04", "jammy") + "," + branch(osOf("", "noble"), apt), "", "JAMMY", false},
		{"top jammy, branch OS only kinetic", osOf("22.04", "jammy") + "," + branch(osOf("", "kinetic"), apt), "", "JAMMY", false},
		{"top jammy, branch OS only jammy", osOf("22.04", "jammy") + "," + branch(osOf("", "jammy"), apt), "", "JAMMY", true},
		{"top jammy, subject noble on 22.04 holding an OS that says nothing", osOf("22.04", "jammy"), `,"metadata":{"component":` + osOf("22.04", "noble", osOf("22.04", ""), apt) + `}`, "JAMMY", false},
		{"a codename-only jammy OS", osOf("", "jammy") + "," + apt, "", "JAMMY", true},
		// The branch's own version-less jammy is its evidence when the
		// document's own OS (the subject, 22.04 saying noble) gives none.
		{"branch OS only jammy, subject noble on 22.04", branch(osOf("", "jammy"), apt), `,"metadata":{"component":` + osOf("22.04", "noble") + `}`, "JAMMY", true},
		{"a codename-only noble OS", osOf("", "noble") + "," + apt, "", "JAMMY", false},
		// A retired codename alone names 22.10, not the apt's 22.04
		// (the QA's unversioned-kinetic input).
		{"a codename-only kinetic OS, statement kinetic", osOf("", "kinetic") + "," + apt, "", "kinetic", false},
		{"a codename-only kinetic OS, statement KINETIC", osOf("", "kinetic") + "," + apt, "", "KINETIC", false},
		{"22.04 saying a codename no table knows", osOf("22.04", "tangy") + "," + apt, "", "tangy", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "sbom.cdx.json")
			doc := `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[` + tc.components + `]` + tc.meta + `}`
			if err := os.WriteFile(p, []byte(doc), 0o644); err != nil {
				t.Fatal(err)
			}
			var out, errOut bytes.Buffer
			Run(context.Background(), db, "sbom:"+p, Options{Output: "json", FailOnUnknown: true,
				VEXFiles: []string{writeVEX(t, stmt("CVE-2031-9108", product("pkg:deb/ubuntu/apt@2.4.14?arch=amd64&distro="+tc.statement)))}}, &out, &errOut)
			var rep report.Document
			if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
				t.Fatalf("stdout is not one JSON document: %v\nstderr: %s", err, errOut.String())
			}
			sup, kept := suppressedPairs(rep), pairsOf(rep.Findings)
			if sup[want] != tc.suppressed || kept[want] == tc.suppressed {
				t.Fatalf("suppressed = %v, kept = %v; want suppressed %v\nstderr: %s", sup[want], kept[want], tc.suppressed, errOut.String())
			}
		})
	}
}
