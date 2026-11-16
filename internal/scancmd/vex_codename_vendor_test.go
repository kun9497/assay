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
