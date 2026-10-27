package scancmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/severity"
	"github.com/kun9497/assay/internal/store"
)

// sourceEVRDB writes a database holding one record with the given
// affected entries, each "introduced 0, fixed V".
func sourceEVRDB(t *testing.T, eco, id string, fixed map[string]string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vulnerability.db")
	w, err := store.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	var aff []advisory.Affected
	for _, name := range []string{"nodejs", "npm", "httpd", "mod_ssl"} {
		v, ok := fixed[name]
		if !ok {
			continue
		}
		aff = append(aff, advisory.Affected{Ecosystem: eco, Name: name, Ranges: []advisory.Range{{
			Type: advisory.RangeEcosystem, Events: []advisory.Event{{Introduced: "0"}, {Fixed: v}},
		}}})
	}
	if err := w.Put(advisory.Advisory{
		ID: id, Kind: advisory.KindVulnerability, Database: "RHSA", Affected: aff,
		Severity: []advisory.Severity{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := w.SetMeta(store.Meta{Providers: map[string]store.Provenance{"p": {Ecosystems: []string{eco}}}}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

type evrFinding struct {
	Package struct {
		Name string `json:"name"`
	} `json:"package"`
	MatchedName string `json:"matchedName"`
}

func runSourceEVR(t *testing.T, db, doc string) (int, []evrFinding) {
	t.Helper()
	sbom := filepath.Join(t.TempDir(), "doc.spdx.json")
	if err := os.WriteFile(sbom, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	high := severity.High
	var out, errOut bytes.Buffer
	code := Run(context.Background(), db, sbom, Options{Output: "json", FailOn: &high, FailOnIncompleteTarget: true}, &out, &errOut)
	var r struct {
		Findings []evrFinding `json:"findings"`
	}
	if err := json.Unmarshal(out.Bytes(), &r); err != nil {
		t.Fatalf("decode: %v\nstderr: %s", err, errOut.String())
	}
	return code, r.Findings
}

const npmDoc = `{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","packages":[
 {"SPDXID":"SPDXRef-src","name":"nodejs","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:rpm/redhat/nodejs@` + "%s" + `?arch=src&epoch=1"}]},
 {"SPDXID":"SPDXRef-bin","name":"npm","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:rpm/redhat/npm@` + "%s" + `?arch=x86_64&epoch=1&repository_id=rhel-9-for-x86_64-appstream-rpms"}]}],
 "relationships":[{"spdxElementId":"SPDXRef-src","relatedSpdxElement":"SPDXRef-bin","relationshipType":"GENERATES"}]}`

// 2026-10-27 review, item 1, with Red Hat's real CVE-2023-23920 fixed
// versions: nodejs 1:16.19.1-1.el9_2 and npm 1:8.19.3-1.16.19.1.1.el9_2. An
// SBOM holding exactly those builds is not affected. Before the fix, the
// GENERATES edge gave npm the source NAME only, the lookup under nodejs
// compared npm's 8.19.3 against nodejs's 16.19.1, and a fixed npm was
// reported vulnerable through nodejs.
func TestRun_SPDXSourceRelationshipComparesTheSourceEVR(t *testing.T) {
	db := sourceEVRDB(t, "Red Hat:9", "RHSA-2023:1583", map[string]string{
		"nodejs": "1:16.19.1-1.el9_2", "npm": "1:8.19.3-1.16.19.1.1.el9_2",
	})

	code, f := runSourceEVR(t, db, fmt.Sprintf(npmDoc, "16.19.1-1.el9_2", "8.19.3-1.16.19.1.1.el9_2"))
	if code != 0 || len(f) != 0 {
		t.Errorf("fixed builds: exit %d, findings %+v; want 0 and none", code, f)
	}

	// The source-name lookup still does its job: against a record naming
	// only the source (the shape most Red Hat advisories have), an npm
	// built from a nodejs short of the fix is reached through nodejs, on
	// the source's EVR.
	srcOnly := sourceEVRDB(t, "Red Hat:9", "RHSA-2023:1583", map[string]string{"nodejs": "1:16.19.1-1.el9_2"})
	code, f = runSourceEVR(t, srcOnly, fmt.Sprintf(npmDoc, "16.18.1-3.el9_1", "8.19.2-1.16.18.1.3.el9_1"))
	viaSource := false
	for _, x := range f {
		if x.Package.Name == "npm" && x.MatchedName == "nodejs" {
			viaSource = true
		}
	}
	if code != 1 || !viaSource {
		t.Errorf("pre-fix builds: exit %d, findings %+v; want exit 1 and npm reached through nodejs", code, f)
	}
}

// The other direction, from the review's Fedora probe: mod_ssl carries
// epoch 1 and its source httpd none (as in Fedora's own packaging). Compared
// on the binary's version, 1:2.4.62-1.fc40 sorts above an httpd fix of
// 2.4.63-1.fc40 and the finding vanished -- exit 0, nothing incomplete.
// Compared on the source's EVR, it is found.
func TestRun_SPDXSourceRelationshipDoesNotBorrowTheBinaryEpoch(t *testing.T) {
	db := sourceEVRDB(t, "Fedora:40", "FEDORA-2026-0001", map[string]string{"httpd": "2.4.63-1.fc40"})
	const doc = `{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","packages":[
 {"SPDXID":"SPDXRef-src","name":"httpd","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:rpm/fedora/httpd@2.4.62-1.fc40?arch=src&epoch=0&distro=fedora-40"}]},
 {"SPDXID":"SPDXRef-bin","name":"mod_ssl","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:rpm/fedora/mod_ssl@2.4.62-1.fc40?arch=x86_64&epoch=1&distro=fedora-40"}]}],
 "relationships":[{"spdxElementId":"SPDXRef-bin","relatedSpdxElement":"SPDXRef-src","relationshipType":"GENERATED_FROM"}]}`
	code, f := runSourceEVR(t, db, doc)
	if code != 1 || len(f) != 1 || f[0].Package.Name != "mod_ssl" || f[0].MatchedName != "httpd" {
		t.Errorf("exit %d, findings %+v; want exit 1 and mod_ssl reached through httpd", code, f)
	}
}
