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

// Main QA of f554fb2 (2026-11-13), through Run: the same apt listed as
// pkg:deb/ubuntu/apt with the numeric distro and as pkg:deb/debian/apt with
// distro=jammy, the two at the top level and under metadata.component in
// both orders. The debian listing's codename is no evidence about the
// ubuntu package, so the JAMMY statement exempts nothing in either order
// (f554fb2: exit 0 with the ubuntu listing first, 1 the other way round).
func TestRun_VEXUbuntuCodenameIsNotTakenFromAnotherVendor(t *testing.T) {
	db := vexDB(t, "Ubuntu:22.04:LTS", vexAdv{"UBUNTU-2031-0106", "CVE-2031-9106", "apt", "2.4.99"})
	want := pair{"apt", "CVE-2031-9106"}
	listing := func(ref, purl string) string {
		return `{"type":"library","name":"apt","version":"2.4.14","bom-ref":"` + ref + `","purl":"` + purl + `"}`
	}
	const (
		ubuntu = "pkg:deb/ubuntu/apt@2.4.14?arch=amd64&distro=ubuntu-22.04"
		debian = "pkg:deb/debian/apt@2.4.14?arch=amd64&distro=jammy"
	)
	for _, order := range [][2]string{{ubuntu, debian}, {debian, ubuntu}} {
		doc := `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[` + listing("first", order[0]) + `],` +
			`"metadata":{"component":{"type":"container","name":"subject","components":[` + listing("second", order[1]) + `]}}}`
		p := filepath.Join(t.TempDir(), "sbom.cdx.json")
		if err := os.WriteFile(p, []byte(doc), 0o644); err != nil {
			t.Fatal(err)
		}
		var out, errOut bytes.Buffer
		code := Run(context.Background(), db, "sbom:"+p, Options{Output: "json", FailOnUnknown: true, FailOnIncompleteTarget: true,
			VEXFiles: []string{writeVEX(t, stmt("CVE-2031-9106", product("pkg:deb/ubuntu/apt@2.4.14?arch=amd64&distro=JAMMY")))}}, &out, &errOut)
		var rep report.Document
		if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
			t.Fatalf("stdout is not one JSON document: %v\nstderr: %s", err, errOut.String())
		}
		if suppressedPairs(rep)[want] || !pairsOf(rep.Findings)[want] || code != 1 {
			t.Errorf("top %s: suppressed %v, exit %d; want the finding kept, exit 1\nstderr: %s", order[0], suppressedPairs(rep), code, errOut.String())
		}
	}
}

// PR #329 review: the ubuntu listing states no distro= at all (its release
// is the document's OS), so the debian listing's distro=jammy had reached it
// through the copy of qualifiers the kept purl lacks. Refused in both orders.
func TestRun_VEXUbuntuCodenameIsNotCopiedFromAnotherVendor(t *testing.T) {
	db := vexDB(t, "Ubuntu:22.04:LTS", vexAdv{"UBUNTU-2031-0106", "CVE-2031-9106", "apt", "2.4.99"})
	want := pair{"apt", "CVE-2031-9106"}
	const (
		ubuntuOS = `{"type":"operating-system","name":"ubuntu","version":"22.04","properties":[{"name":"syft:distro:id","value":"ubuntu"},{"name":"syft:distro:versionID","value":"22.04"}]}`
		ubuntu   = `{"type":"library","name":"apt","version":"2.4.14","bom-ref":"u","purl":"pkg:deb/ubuntu/apt@2.4.14?arch=amd64"}`
		debian   = `{"type":"library","name":"apt","version":"2.4.14","bom-ref":"d","purl":"pkg:deb/debian/apt@2.4.14?arch=amd64&distro=jammy"}`
	)
	for _, order := range [][2]string{{ubuntu, debian}, {debian, ubuntu}} {
		doc := `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[` + ubuntuOS + `,` + order[0] + `],` +
			`"metadata":{"component":{"type":"container","name":"subject","components":[` + order[1] + `]}}}`
		p := filepath.Join(t.TempDir(), "sbom.cdx.json")
		if err := os.WriteFile(p, []byte(doc), 0o644); err != nil {
			t.Fatal(err)
		}
		var out, errOut bytes.Buffer
		code := Run(context.Background(), db, "sbom:"+p, Options{Output: "json", FailOnUnknown: true,
			VEXFiles: []string{writeVEX(t, stmt("CVE-2031-9106", product("pkg:deb/ubuntu/apt@2.4.14?arch=amd64&distro=JAMMY")))}}, &out, &errOut)
		var rep report.Document
		if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
			t.Fatalf("stdout is not one JSON document: %v\nstderr: %s", err, errOut.String())
		}
		// The finding must still be reported, not merely unsuppressed: a merge
		// that lost the install would pass a suppression-only check (third
		// review of PR #329).
		if suppressedPairs(rep)[want] || !pairsOf(rep.Findings)[want] || code != 1 {
			t.Errorf("top %s: suppressed %v, exit %d; want the finding kept, exit 1\nstderr: %s", order[0], suppressedPairs(rep), code, errOut.String())
		}
	}
}

// Second review of PR #329: the ubuntu listing names another release
// (24.04, or noble) under a document OS of 22.04, so mergePURL replaces its
// distro= -- and had taken the debian listing's jammy as the replacement.
// Refused in both orders.
func TestRun_VEXUbuntuCodenameIsNotReplacedFromAnotherVendor(t *testing.T) {
	db := vexDB(t, "Ubuntu:22.04:LTS", vexAdv{"UBUNTU-2031-0106", "CVE-2031-9106", "apt", "2.4.99"})
	want := pair{"apt", "CVE-2031-9106"}
	const ubuntuOS = `{"type":"operating-system","name":"ubuntu","version":"22.04","properties":[{"name":"syft:distro:id","value":"ubuntu"},{"name":"syft:distro:versionID","value":"22.04"}]}`
	for _, own := range []string{"ubuntu-24.04", "noble"} {
		ubuntu := `{"type":"library","name":"apt","version":"2.4.14","bom-ref":"u","purl":"pkg:deb/ubuntu/apt@2.4.14?arch=amd64&distro=` + own + `"}`
		const debian = `{"type":"library","name":"apt","version":"2.4.14","bom-ref":"d","purl":"pkg:deb/debian/apt@2.4.14?arch=amd64&distro=jammy"}`
		for _, order := range [][2]string{{ubuntu, debian}, {debian, ubuntu}} {
			doc := `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[` + ubuntuOS + `,` + order[0] + `],` +
				`"metadata":{"component":{"type":"container","name":"subject","components":[` + order[1] + `]}}}`
			p := filepath.Join(t.TempDir(), "sbom.cdx.json")
			if err := os.WriteFile(p, []byte(doc), 0o644); err != nil {
				t.Fatal(err)
			}
			var out, errOut bytes.Buffer
			code := Run(context.Background(), db, "sbom:"+p, Options{Output: "json", FailOnUnknown: true,
				VEXFiles: []string{writeVEX(t, stmt("CVE-2031-9106", product("pkg:deb/ubuntu/apt@2.4.14?arch=amd64&distro=JAMMY")))}}, &out, &errOut)
			var rep report.Document
			if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
				t.Fatalf("stdout is not one JSON document: %v\nstderr: %s", err, errOut.String())
			}
			if suppressedPairs(rep)[want] || !pairsOf(rep.Findings)[want] || code != 1 {
				t.Errorf("own distro %s, top %s: suppressed %v, exit %d; want the finding kept, exit 1\nstderr: %s", own, order[0], suppressedPairs(rep), code, errOut.String())
			}
		}
	}
}
