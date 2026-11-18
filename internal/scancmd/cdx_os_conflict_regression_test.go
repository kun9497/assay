package scancmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/report"
)

func scanOSRegression(t *testing.T, db, doc string, vexFiles ...string) (report.Document, int) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "os.cdx.json")
	if err := os.WriteFile(p, []byte(doc), 0600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	rc := Run(context.Background(), db, "sbom:"+p, Options{Output: "json", FailOnUnknown: true, FailOnIncompleteTarget: true, VEXFiles: vexFiles}, &out, &errOut)
	var rep report.Document
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatalf("exit %d: %v: %s", rc, err, errOut.String())
	}
	return rep, rc
}

func TestRun_CDXGenericOSNameCannotEraseCodenameConflict(t *testing.T) {
	db := vexDB(t, "Ubuntu:22.04:LTS", vexAdv{"QA-22", "CVE-2031-9110", "apt", "2.4.99"})
	vf := writeVEX(t, stmt("CVE-2031-9110", product("pkg:deb/ubuntu/apt@2.4.14?arch=amd64&distro=JAMMY")))
	const top = `{"type":"operating-system","name":"ubuntu","version":"22.04","properties":[{"name":"syft:distro:versionCodename","value":"jammy"}]}`
	const apt = `{"type":"library","purl":"pkg:deb/ubuntu/apt@2.4.14?arch=amd64&distro=ubuntu-22.04"}`
	for _, name := range []string{"ubuntu", "linux", "Ubuntu Core"} {
		for _, pair := range [][2]string{{"22.04", "noble"}, {"24.04", "jammy"}} {
			for _, reverse := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/%t", name, pair[0], reverse), func(t *testing.T) {
					branch := fmt.Sprintf(`{"type":"library","purl":"pkg:npm/is-number@7.0.0","components":[{"type":"operating-system","name":%q,"version":%q,"properties":[{"name":"syft:distro:id","value":"ubuntu"},{"name":"syft:distro:versionCodename","value":%q}]}]}`, name, pair[0], pair[1])
					components := top + "," + apt + "," + branch
					if reverse {
						components = branch + "," + apt + "," + top
					}
					rep, rc := scanOSRegression(t, db, `{"bomFormat":"CycloneDX","components":[`+components+`]}`, vf)
					if rc != 1 || rep.Summary.Evaluated != 1 || len(rep.Findings) != 1 || len(rep.Suppressed) != 0 || rep.Summary.TargetIncomplete != 0 || len(rep.Skipped) != 1 || rep.Skipped[0].Package.Name != "is-number" {
						t.Fatalf("exit %d, summary %+v, suppressed %+v, skipped %+v", rc, rep.Summary, rep.Suppressed, rep.Skipped)
					}
				})
			}
		}
	}
	// A generic name alone must not become new positive codename evidence.
	for _, name := range []string{"ubuntu", "linux"} {
		doc := fmt.Sprintf(`{"bomFormat":"CycloneDX","components":[{"type":"operating-system","name":%q,"version":"22.04","properties":[{"name":"syft:distro:id","value":"ubuntu"},{"name":"syft:distro:versionCodename","value":"jammy"}]},%s]}`, name, apt)
		rep, rc := scanOSRegression(t, db, doc, vf)
		wantSuppressed, wantExit := 0, 1
		if name == "ubuntu" {
			wantSuppressed, wantExit = 1, 0
		}
		if rc != wantExit || len(rep.Suppressed) != wantSuppressed || len(rep.Findings) != 1-wantSuppressed || rep.Summary.Evaluated != 1 {
			t.Fatalf("name %q: exit %d, summary %+v", name, rc, rep.Summary)
		}
	}
}

func TestRun_CDXParentOSContradictionCannotKeyItsChild(t *testing.T) {
	db := vexDB(t, "Ubuntu:22.04:LTS", vexAdv{"QA-22", "CVE-2031-9110", "apt", "2.4.99"})
	const apt = `{"type":"library","purl":"pkg:deb/ubuntu/apt@2.4.14?arch=amd64"}`
	for _, tc := range []struct{ name, properties string }{
		{"versions", `{"name":"syft:distro:versionID","value":"22.04"},{"name":"syft:distro:versionID","value":"24.04"}`},
		{"ids", `{"name":"syft:distro:id","value":"ubuntu"},{"name":"syft:distro:id","value":"debian"}`},
		{"name vs id", `{"name":"syft:distro:id","value":"debian"}`},
		{"LTS", `{"name":"syft:distro:prettyName","value":"Ubuntu 22.04 LTS"},{"name":"syft:distro:prettyName","value":"Ubuntu 22.04"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			osName := "ubuntu"
			if tc.name == "ids" {
				osName = "linux"
			}
			var props []json.RawMessage
			if err := json.Unmarshal([]byte("["+tc.properties+"]"), &props); err != nil {
				t.Fatal(err)
			}
			var reason string
			for order := 0; order < 2; order++ {
				if order == 1 {
					for i, j := 0, len(props)-1; i < j; i, j = i+1, j-1 {
						props[i], props[j] = props[j], props[i]
					}
				}
				raw, err := json.Marshal(props)
				if err != nil {
					t.Fatal(err)
				}
				doc := `{"bomFormat":"CycloneDX","metadata":{"component":{"type":"operating-system","name":"` + osName + `","version":"22.04","properties":` + string(raw) + `,"components":[` + apt + `]}}}`
				rep, rc := scanOSRegression(t, db, doc)
				if rc != 2 || rep.Summary.Evaluated != 0 || len(rep.Skipped) != 1 || rep.Summary.TargetIncomplete != 1 || len(rep.Findings) != 0 || rep.Distro != nil {
					t.Fatalf("exit %d, summary %+v, target %+v", rc, rep.Summary, rep.Distro)
				}
				if !strings.Contains(rep.Skipped[0].Reason, "contradicts itself") {
					t.Fatalf("missing conflict explanation: %+v", rep.Skipped)
				}
				if order == 1 && reason != rep.Skipped[0].Reason {
					t.Fatalf("order-dependent conflict: %q vs %q", reason, rep.Skipped[0].Reason)
				}
				reason = rep.Skipped[0].Reason
			}
		})
	}
}

func TestRun_CDXMergedAmbiguityRemainsATargetSkip(t *testing.T) {
	db := vexDB(t, "Ubuntu:22.04:LTS", vexAdv{"QA-22", "CVE-2031-9110", "apt", "2.4.99"})
	const apt = `{"type":"library","purl":"pkg:deb/ubuntu/apt@2.4.14"}`
	doc := `{"bomFormat":"CycloneDX","components":[` + apt + `],"metadata":{"component":{"type":"container","name":"subject","components":[{"type":"operating-system","name":"ubuntu","version":"22.04"},{"type":"operating-system","name":"ubuntu","version":"24.04"},` + apt + `]}}}`
	rep, rc := scanOSRegression(t, db, doc)
	if rc != 2 || rep.Summary.Components != 1 || rep.Summary.TargetIncomplete != 1 || len(rep.Skipped) != 1 {
		t.Fatalf("exit %d, summary %+v", rc, rep.Summary)
	}
}

func TestRun_CDXMixedVendorsCannotUseBinaryVEX(t *testing.T) {
	db := vexDB(t, "Ubuntu:22.04:LTS", vexAdv{"QA-22", "CVE-2031-9110", "apt", "2.4.99"})
	a, b := "pkg:deb/ubuntu/apt@2.4.14?distro=ubuntu-22.04", "pkg:deb/debian/apt@2.4.14?distro=ubuntu-22.04"
	vf := writeVEX(t, stmt("CVE-2031-9110", product(a), product(b)))
	for _, pair := range [][2]string{{a, b}, {b, a}} {
		doc := fmt.Sprintf(`{"bomFormat":"CycloneDX","components":[{"type":"library","purl":%q}],"metadata":{"component":{"type":"library","purl":%q}}}`, pair[0], pair[1])
		rep, rc := scanOSRegression(t, db, doc, vf)
		if rc != 1 || rep.Summary.Evaluated != 1 || len(rep.Findings) != 1 || len(rep.Suppressed) != 0 {
			t.Fatalf("exit %d, summary %+v", rc, rep.Summary)
		}
	}
}

func TestRun_CDXConflictingTopCannotBorrowSubjectDistro(t *testing.T) {
	db := vexDB(t, "Ubuntu:22.04:LTS", vexAdv{"QA-22", "CVE-2031-9110", "apt", "2.4.99"})
	doc := `{"bomFormat":"CycloneDX","components":[{"type":"operating-system","name":"ubuntu","version":"22.04","properties":[{"name":"syft:distro:versionID","value":"24.04"}]},{"type":"library","purl":"pkg:deb/ubuntu/apt@2.4.14"}],"metadata":{"component":{"type":"operating-system","name":"ubuntu","version":"22.04"}}}`
	rep, rc := scanOSRegression(t, db, doc)
	if rc != 2 || rep.Distro != nil || rep.Summary.TargetIncomplete != 1 {
		t.Fatalf("exit %d, distro %+v, summary %+v", rc, rep.Distro, rep.Summary)
	}
}

func TestRun_CDXUncoveredParentCannotMergeWithCoveredInstall(t *testing.T) {
	db := vexDB(t, "Debian:12", vexAdv{"QA-12", "CVE-2031-9110", "apt", "3.0.4"})
	doc := `{"bomFormat":"CycloneDX","components":[{"type":"operating-system","name":"debian","version":"12"},{"type":"library","purl":"pkg:deb/debian/apt@3.0.3"}],"metadata":{"component":{"type":"operating-system","name":"debian","version":"sid","components":[{"type":"library","purl":"pkg:deb/debian/apt@3.0.3"}]}}}`
	rep, rc := scanOSRegression(t, db, doc)
	if rc != 1 || rep.Summary.Components != 2 || rep.Summary.Evaluated != 1 || len(rep.Skipped) != 1 || rep.Summary.TargetIncomplete != 0 {
		t.Fatalf("exit %d, summary %+v", rc, rep.Summary)
	}
}

func TestRun_CDXUnkeyedArchitectureTwinsIgnoreOtherReleaseKeys(t *testing.T) {
	for _, conflict := range []bool{false, true} {
		eco, vendor, version, left, right := "Debian:12", "debian", "3.0.3", "debian-11", "debian-12"
		osInfo, qualifier := "", "distro=debian-sid"
		if conflict {
			eco, vendor, version, left, right = "Ubuntu:22.04:LTS", "ubuntu", "2.4.14", "ubuntu-22.04", "ubuntu-24.04"
			osInfo = `{"type":"operating-system","name":"ubuntu","version":"22.04","properties":[{"name":"syft:distro:versionID","value":"24.04"}]}`
			qualifier = ""
		}
		db := vexDB(t, eco, vexAdv{"QA", "CVE-2031-9110", "apt", "9.9.9"})
		pkg := func(q string) string {
			return fmt.Sprintf(`{"type":"library","purl":"pkg:deb/%s/apt@%s?%s"}`, vendor, version, q)
		}
		top := pkg("distro="+left+"&arch=amd64") + "," + pkg("distro="+right+"&arch=arm64") + "," + pkg(qualifier)
		archQualifier := "arch=amd64"
		if qualifier != "" {
			archQualifier += "&" + qualifier
		}
		subject := pkg(archQualifier)
		if conflict {
			top = osInfo + "," + top
			subject = strings.TrimSuffix(osInfo, "}") + `,"components":[` + subject + `]}`
		}
		rep, rc := scanOSRegression(t, db, `{"bomFormat":"CycloneDX","components":[`+top+`],"metadata":{"component":`+subject+`}}`)
		wantExit, wantTarget := 1, 0
		if conflict {
			wantExit, wantTarget = 2, 1
		}
		if rc != wantExit || rep.Summary.Components != 3 || rep.Summary.TargetIncomplete != wantTarget || rep.Summary.Evaluated != 1 || len(rep.Skipped) != 2 {
			t.Fatalf("conflict %t: exit %d, summary %+v, skips %+v", conflict, rc, rep.Summary, rep.Skipped)
		}
	}
}

func TestRun_CDXSiblingConflictReasonIsOrderIndependent(t *testing.T) {
	db := vexDB(t, "Ubuntu:22.04:LTS", vexAdv{"QA-22", "CVE-2031-9110", "apt", "2.4.99"})
	const first = `{"type":"operating-system","name":"ubuntu","version":"22.04","properties":[{"name":"syft:distro:versionID","value":"24.04"}]}`
	const second = `{"type":"operating-system","name":"ubuntu","version":"22.04","properties":[{"name":"syft:distro:id","value":"debian"}]}`
	var reason string
	for _, pair := range [][2]string{{first, second}, {second, first}} {
		doc := `{"bomFormat":"CycloneDX","components":[` + pair[0] + "," + pair[1] + `,{"type":"library","purl":"pkg:deb/ubuntu/apt@2.4.14"}]}`
		rep, rc := scanOSRegression(t, db, doc)
		if rc != 2 || len(rep.Skipped) != 1 || rep.Summary.TargetIncomplete != 1 {
			t.Fatalf("exit %d, summary %+v", rc, rep.Summary)
		}
		if reason != "" && reason != rep.Skipped[0].Reason {
			t.Fatalf("order-dependent conflict: %q vs %q", reason, rep.Skipped[0].Reason)
		}
		reason = rep.Skipped[0].Reason
	}
}
