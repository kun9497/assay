package redhat

import (
	"compress/gzip"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/cataloger/spdx"
	"github.com/kun9497/assay/internal/matcher"
	"github.com/kun9497/assay/internal/store"
)

// realSPDXSubpackage is a minimal Red Hat-shaped SPDX document: npm, built
// from nodejs, linked by GENERATES only (no upstream qualifier).
const realSPDXSubpackage = `{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","packages":[
 {"SPDXID":"SPDXRef-src","name":"nodejs","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:rpm/redhat/nodejs@%SRC%?arch=src&epoch=1"}]},
 {"SPDXID":"SPDXRef-bin","name":"npm","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:rpm/redhat/npm@%BIN%?arch=x86_64&epoch=1&repository_id=rhel-9-for-x86_64-appstream-rpms"}]}],
 "relationships":[{"spdxElementId":"SPDXRef-src","relatedSpdxElement":"SPDXRef-bin","relationshipType":"GENERATES"}]}`

// Red Hat's real CSAF VEX document for CVE-2023-23920
// (security.access.redhat.com/data/csaf/v2/vex/2023/cve-2023-23920.json,
// sha256 9f6b64f001ca1d045b6c..., fetched 2026-10-27), converted by this
// provider, against an SPDX npm built from nodejs. It fixes nodejs at
// 1:16.19.1-1.el9_2 and npm at 1:8.19.3-1.16.19.1.1.el9_2. Those builds are
// not affected; before the source EVR was kept, the lookup under nodejs
// compared npm's 8.19.3 with nodejs's fix and reported a Medium finding
// (2026-10-27 review, item 1). The builds before the fix are affected.
func TestRealCSAF_SPDXSubpackageIsJudgedOnItsSourcesEVR(t *testing.T) {
	f, err := os.Open(filepath.Join("testdata", "cve-2023-23920.json.gz"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	var doc document
	if err := json.NewDecoder(zr).Decode(&doc); err != nil {
		t.Fatal(err)
	}
	var st stats
	adv, ok := convert(&doc, &st)
	if !ok {
		t.Fatal("the real document converted to nothing")
	}
	db, err := store.Create(filepath.Join(t.TempDir(), "vulnerability.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Put(adv); err != nil {
		t.Fatal(err)
	}
	if err := db.SetMeta(store.Meta{Providers: map[string]store.Provenance{"redhat": {Ecosystems: []string{"Red Hat:9"}}}}); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name, src, bin string
		want           int
	}{
		{"the fixed builds", "16.19.1-1.el9_2", "8.19.3-1.16.19.1.1.el9_2", 0},
		{"the builds before the fix", "16.18.1-3.el9_1", "8.19.2-1.16.18.1.3.el9_1", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := strings.NewReplacer("%SRC%", tc.src, "%BIN%", tc.bin).Replace(realSPDXSubpackage)
			target, _, err := spdx.Parse(strings.NewReader(in))
			if err != nil {
				t.Fatal(err)
			}
			res, err := matcher.New(db).Match(target)
			if err != nil {
				t.Fatal(err)
			}
			if len(res.Findings) != tc.want || len(res.Skipped) != 0 {
				t.Errorf("findings %+v, skipped %+v; want %d finding(s), no skips", res.Findings, res.Skipped, tc.want)
			}
		})
	}
}
