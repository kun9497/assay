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

// A package beside conflicting OS evidence remains visibly unjudged even
// when the rest of the SBOM can be evaluated.
func TestRun_CDXConflictingOSNeedsTargetEvidence(t *testing.T) {
	db := vexDB(t, "Ubuntu:24.04:LTS", vexAdv{"QA-24", "CVE-2031-9110", "apt", "2.8.5"})
	const apt = `{"type":"library","name":"apt","purl":"pkg:deb/ubuntu/apt@2.8.4"}`
	const qualified = `{"type":"library","name":"apt","purl":"pkg:deb/ubuntu/apt@2.8.4?distro=ubuntu-24.04"}`
	osInfo := func(v1, v2 string) string {
		return fmt.Sprintf(`{"type":"operating-system","name":"ubuntu","version":"24.04","properties":[{"name":"syft:distro:versionID","value":%q},{"name":"syft:distro:versionID","value":%q}]}`, v1, v2)
	}
	var firstReason string
	for _, tc := range []struct{ name, v1, v2 string }{{"old last", "24.04", "22.04"}, {"new last", "22.04", "24.04"}} {
		t.Run(tc.name, func(t *testing.T) {
			// Duplicate the same binary under a qualified subject. Deduplication
			// must not erase the unresolved installation or poison the valid one.
			doc := `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[` + osInfo(tc.v1, tc.v2) + "," + apt + `],"metadata":{"component":` + qualified + `}}`
			p := filepath.Join(t.TempDir(), "os.cdx.json")
			if err := os.WriteFile(p, []byte(doc), 0600); err != nil {
				t.Fatal(err)
			}
			var stdout, stderr bytes.Buffer
			rc := Run(context.Background(), db, "sbom:"+p, Options{Output: "json", FailOnIncompleteTarget: true}, &stdout, &stderr)
			var rep report.Document
			if err := json.Unmarshal(stdout.Bytes(), &rep); err != nil {
				t.Fatalf("%v: %s", err, stderr.String())
			}
			if rc != 2 || rep.Summary.TargetIncomplete != 1 || rep.Summary.Evaluated != 1 || len(rep.Skipped) != 1 || len(rep.Findings) != 1 {
				t.Fatalf("exit %d, summary %+v, skips %+v", rc, rep.Summary, rep.Skipped)
			}
			reason := rep.Skipped[0].Reason
			if !strings.Contains(reason, "22.04") || !strings.Contains(reason, "24.04") || firstReason != "" && firstReason != reason {
				t.Fatalf("order-dependent or missing contradiction: %q / %q", firstReason, reason)
			}
			firstReason = reason
		})
	}
}

func TestRun_CDXMultipleOSDeclarationsNeedAnIndependentRelease(t *testing.T) {
	db := vexDB(t, "Ubuntu:24.04:LTS", vexAdv{"QA-24", "CVE-2031-9110", "apt", "2.8.5"})
	const os22 = `{"type":"operating-system","name":"ubuntu","version":"22.04"}`
	const os24 = `{"type":"operating-system","name":"ubuntu","version":"24.04"}`
	const sid = `{"type":"operating-system","name":"debian","version":"sid"}`
	const apt = `{"type":"library","purl":"pkg:deb/ubuntu/apt@2.8.4"}`
	const qualified = `{"type":"library","purl":"pkg:deb/ubuntu/apt@2.8.4?distro=ubuntu-24.04"}`
	const language = `{"type":"library","purl":"pkg:npm/is-number@7.0.0"}`
	for _, order := range []string{os22 + "," + os24, os24 + "," + os22} {
		for _, tc := range []struct {
			packages                string
			exit, missing, findings int
		}{
			{apt + "," + qualified, 2, 1, 1},
			{qualified + "," + language, 0, 0, 1},
			{sid + `,{"type":"library","purl":"pkg:deb/debian/dpkg@1?distro=debian-sid"},` + qualified, 0, 0, 1},
			{sid + `,{"type":"library","purl":"pkg:deb/debian/dpkg@1?distro=garbage"},` + qualified, 2, 1, 1},
			{sid + `,{"type":"library","purl":"pkg:deb/debian/dpkg@1?distro=debian-other"},` + qualified, 2, 1, 1},
			{`{"type":"library","name":"is-number","purl":"pkg:npm/is-number@7.0.0","components":[` + os24 + "," + apt + `]}`, 0, 0, 1},
		} {
			p := filepath.Join(t.TempDir(), "scopes.cdx.json")
			doc := `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[` + order + "," + tc.packages + `]}`
			if err := os.WriteFile(p, []byte(doc), 0600); err != nil {
				t.Fatal(err)
			}
			var out, stderr bytes.Buffer
			rc := Run(context.Background(), db, "sbom:"+p, Options{Output: "json", FailOnIncompleteTarget: true}, &out, &stderr)
			var rep report.Document
			if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
				t.Fatal(err)
			}
			if rc != tc.exit || rep.Summary.TargetIncomplete != tc.missing || len(rep.Findings) != tc.findings {
				t.Fatalf("packages %s: exit %d, summary %+v, skips %+v", tc.packages, rc, rep.Summary, rep.Skipped)
			}
		}
	}
}

// Debian sid and Debian 12 are separate installs even when the package
// version and architecture are the same. A missing sid key is a coverage gap.
func TestRun_CDXUncoveredReleaseIsNotAKeyedTwin(t *testing.T) {
	db := vexDB(t, "Debian:12", vexAdv{"QA-12", "CVE-2031-9110", "apt", "3.0.4"})
	const releases = `{"type":"operating-system","name":"debian","version":"sid"},{"type":"operating-system","name":"debian","version":"12"}`
	const sid = `{"type":"library","purl":"pkg:deb/debian/apt@3.0.3?distro=debian-sid"}`
	const twelve = `{"type":"library","purl":"pkg:deb/debian/apt@3.0.3?distro=debian-12"}`
	for _, declarations := range []string{releases + ",", ""} {
		for _, pair := range [][2]string{{sid, twelve}, {twelve, sid}} {
			p := filepath.Join(t.TempDir(), "releases.cdx.json")
			doc := `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[` + declarations + pair[0] + `],"metadata":{"component":` + pair[1] + `}}`
			if err := os.WriteFile(p, []byte(doc), 0600); err != nil {
				t.Fatal(err)
			}
			var out, stderr bytes.Buffer
			rc := Run(context.Background(), db, "sbom:"+p, Options{Output: "json", FailOnIncompleteTarget: true}, &out, &stderr)
			var rep report.Document
			if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
				t.Fatal(err)
			}
			if rc != 0 || rep.Summary.Components != 2 || rep.Summary.Evaluated != 1 || rep.Summary.TargetIncomplete != 0 || len(rep.Skipped) != 1 || len(rep.Findings) != 1 {
				t.Fatalf("exit %d, summary %+v, skips %+v", rc, rep.Summary, rep.Skipped)
			}
		}
	}
}

func TestRun_CDXVEXCannotBorrowAnotherDebVendorsSource(t *testing.T) {
	db := vexDB(t, "Ubuntu:22.04:LTS", vexAdv{"QA-22", "CVE-2031-9110", "apt", "2.4.15"})
	st := writeVEX(t, stmt("CVE-2031-9110", product("pkg:deb/ubuntu/apt@2.4.14?arch=source&distro=ubuntu-22.04")))
	binary := func(ns, qual string) string {
		if ns != "" {
			ns += "/"
		}
		return fmt.Sprintf(`{"type":"library","name":"libapt","purl":"pkg:deb/%slibapt@2.4.14?arch=amd64&distro=ubuntu-22.04%s"}`, ns, qual)
	}
	for _, tc := range []struct {
		bare, source string
		allowed      bool
	}{
		{"ubuntu", "debian", false}, {"ubuntu", "ubuntu", true}, {"", "ubuntu", true}, {"ubuntu", "", false},
	} {
		for _, swap := range []bool{false, true} {
			a, b := binary(tc.bare, ""), binary(tc.source, "&upstream=apt")
			if swap {
				a, b = b, a
			}
			p := filepath.Join(t.TempDir(), "duplicate.cdx.json")
			doc := `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[` + a + `],"metadata":{"component":` + b + `}}`
			if err := os.WriteFile(p, []byte(doc), 0600); err != nil {
				t.Fatal(err)
			}
			rep, _ := scanVEXJSON(t, db, "sbom:"+p, st)
			if rep.Summary.Evaluated != 1 || (len(rep.Suppressed) == 1) != tc.allowed || (len(rep.Findings) == 1) == tc.allowed {
				t.Fatalf("%+v/swap=%t: %+v", tc, swap, rep.Summary)
			}
		}
	}
}
