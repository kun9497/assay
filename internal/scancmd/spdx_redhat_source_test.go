package scancmd

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/store"
)

// 2026-10-22 audit, A3, end to end. A Red Hat advisory is written against
// the SOURCE rpm (D8). Red Hat's own SPDX SBOMs link openssl-libs to the
// openssl source rpm by a GENERATES relationship, not by an upstream
// qualifier, so before the fix a scan of that SBOM reported openssl-libs
// clean where the image scan of the same content found it. The caller's
// test: through Run, an SPDX document shaped like Red Hat's, and a database
// whose only record names `openssl`.
func TestRun_A3_RedHatSPDXBinaryReachesItsSourceAdvisory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vulnerability.db")
	w, err := store.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	const eco = "Red Hat:9"
	if err := w.Put(advisory.Advisory{
		ID: "RHSA-2026:9001", Kind: advisory.KindVulnerability, Database: "RHSA",
		Aliases: []string{"CVE-2026-90010"},
		Affected: []advisory.Affected{{
			Ecosystem: eco,
			Name:      "openssl",
			Ranges: []advisory.Range{{
				Type:   advisory.RangeEcosystem,
				Events: []advisory.Event{{Introduced: "0"}, {Fixed: "1:3.0.7-25.el9_3"}},
			}},
		}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := w.SetMeta(store.Meta{Providers: map[string]store.Provenance{
		"redhat": {Ecosystems: []string{eco}},
	}}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	const doc = `{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","packages":[
	  {"name":"rhel","SPDXID":"SPDXRef-product","externalRefs":[{"referenceCategory":"SECURITY","referenceType":"cpe22Type","referenceLocator":"cpe:/o:redhat:enterprise_linux:9"}]},
	  {"name":"openssl","SPDXID":"SPDXRef-src","externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl",
	    "referenceLocator":"pkg:rpm/redhat/openssl@3.0.7-18.el9_2?arch=src&epoch=1"}]},
	  {"name":"openssl-libs","SPDXID":"SPDXRef-bin","externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl",
	    "referenceLocator":"pkg:rpm/redhat/openssl-libs@3.0.7-18.el9_2?arch=x86_64&epoch=1&repository_id=rhel-9-for-x86_64-baseos-rpms"}]}],
	 "relationships":[
	  {"spdxElementId":"SPDXRef-DOCUMENT","relatedSpdxElement":"SPDXRef-product","relationshipType":"DESCRIBES"},
	  {"spdxElementId":"SPDXRef-src","relatedSpdxElement":"SPDXRef-bin","relationshipType":"GENERATES"}]}`
	sbom := filepath.Join(t.TempDir(), "rhel.spdx.json")
	if err := os.WriteFile(sbom, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}

	var out, errOut bytes.Buffer
	code := Run(context.Background(), path, sbom, Options{Output: "json"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("Run = %d\nstderr: %s", code, errOut.String())
	}
	// Decoded, and the three facts held on ONE finding: the advisory, the
	// installed binary, and the source name it was reached through. Three
	// independent substrings could each come from a different record, and
	// "openssl" alone also matches "openssl-libs" (CLAUDE.md, substring
	// assertions on the wrong column).
	var report struct {
		Findings []struct {
			Package struct {
				Name   string `json:"name"`
				Source *struct {
					Name string `json:"name"`
				} `json:"source"`
			} `json:"package"`
			MatchedName string `json:"matchedName"`
			Advisory    struct {
				ID string `json:"id"`
			} `json:"advisory"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatalf("report is not JSON: %v\n%s", err, out.String())
	}
	for _, f := range report.Findings {
		if f.Advisory.ID == "RHSA-2026:9001" && f.Package.Name == "openssl-libs" && f.MatchedName == "openssl" {
			return
		}
	}
	t.Fatalf("no finding of RHSA-2026:9001 on openssl-libs matched through its source openssl:\n%s", out.String())
}
