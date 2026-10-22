package scancmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/report"
	"github.com/kun9497/assay/internal/severity"
	"github.com/kun9497/assay/internal/store"
)

// The 2026-10-22 external review's reproductions, turned from probes of the
// defect into assertions of the intended result and driven through Run --
// so each holds the whole path from catalog to verdict and exit code, not
// the helper that was wrong.

// #1: an npm alias is matched under its registry identity. The lockfile is
// what npm 11.16.0 generated for `"utility-alias": "npm:lodash@4.17.20"`.
func TestRun_NPMAliasIsMatchedAsTheRegistryPackage(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(t.TempDir(), "review.db")
	db, err := store.Create(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Put(advisory.Advisory{ID: "REVIEW-ALIAS-0001", Source: "review", Database: "REVIEW", Kind: advisory.KindVulnerability,
		Severity: []advisory.Severity{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}},
		Affected: []advisory.Affected{{Ecosystem: "npm", Name: "lodash", Ranges: []advisory.Range{{Type: advisory.RangeSemver, Events: []advisory.Event{{Introduced: "0"}, {Fixed: "4.17.21"}}}}}}}); err != nil {
		t.Fatal(err)
	}
	if err := db.SetMeta(store.Meta{BuiltAt: time.Now().UTC(), Providers: map[string]store.Provenance{"review": {Ecosystems: []string{"npm"}, DataAsOf: time.Now().UTC()}}}); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	const generated = `{
  "name": "assay-review-fixture",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": {
      "name": "assay-review-fixture",
      "version": "1.0.0",
      "dependencies": {
        "utility-alias": "npm:lodash@4.17.20"
      }
    },
    "node_modules/utility-alias": {
      "name": "lodash",
      "version": "4.17.20",
      "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz",
      "integrity": "sha512-PlhdFcillOINfeV7Ni6oF1TAEayyZBoZ8bcshTHqOYJYlrqzRK5hagpagky5o4HfCzzd1TRkXPMFq6cKk9rGmA==",
      "license": "MIT"
    }
  }
}`
	threshold := severity.High
	for _, fixture := range []struct{ name, lock string }{
		{"regular", `{"lockfileVersion":3,"packages":{"":{"name":"app","version":"1.0.0"},"node_modules/lodash":{"version":"4.17.20"}}}`},
		{"alias", generated},
		{"v1 alias", `{"lockfileVersion":1,"dependencies":{"utility-alias":{"version":"npm:lodash@4.17.20"}}}`},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(fixture.lock), 0o600); err != nil {
				t.Fatal(err)
			}
			var out, diagnostics bytes.Buffer
			code := Run(context.Background(), dbPath, "dir:"+dir, Options{Output: "json", FailOn: &threshold, FailOnIncomplete: true}, &out, &diagnostics)
			var doc report.Document
			if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
				t.Fatalf("decode: %v; stdout=%s stderr=%s", err, out.String(), diagnostics.String())
			}
			if code != 1 || len(doc.Findings) != 1 {
				t.Fatalf("exit=%d findings=%d, want 1/1: the installed package is lodash 4.17.20 however it is named on disk (stderr=%s)", code, len(doc.Findings), diagnostics.String())
			}
			if doc.Summary.Evaluated != 1 || doc.Summary.NotEvaluated != 0 {
				t.Errorf("summary = %+v, want Evaluated 1 / NotEvaluated 0", doc.Summary)
			}
			if got := doc.Findings[0].Package.PURL; got != "pkg:npm/lodash@4.17.20" {
				t.Errorf("finding PURL = %q, want pkg:npm/lodash@4.17.20", got)
			}
		})
	}
}

// #2: a Go version carrying an Ubuntu or RPM-module marker is judged, not
// skipped as a coverage limitation. The clean sibling pins that the fix did
// not simply stop skipping everything.
func TestRun_LanguageVersionsWithDistroMarkersAreJudged(t *testing.T) {
	dir := t.TempDir()
	db := provDB(t, dir)
	for _, v := range []string{"1.0.0", "1.0.0+fips1", "1.0.0+esm1", "1.0.0-module+el9"} {
		sbom := filepath.Join(dir, "target.json")
		data := fmt.Sprintf(`{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[{"type":"library","name":"%s","version":"%s","purl":"pkg:golang/%s@%s"},{"type":"library","name":"example.com/clean","version":"1.0.0","purl":"pkg:golang/example.com/clean@1.0.0"}]}`, provPkg, v, provPkg, v)
		if err := os.WriteFile(sbom, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
		var out, stderr bytes.Buffer
		threshold := severity.Critical
		code := Run(context.Background(), db, sbom, Options{Output: "json", FailOn: &threshold, FailOnIncompleteTarget: true}, &out, &stderr)
		var doc report.Document
		if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
			t.Fatalf("%s: decode: %v stderr=%s", v, err, stderr.String())
		}
		if code != 1 || len(doc.Findings) != 1 || len(doc.Skipped) != 0 {
			t.Errorf("Go %s: exit=%d findings=%d skips=%+v, want 1/1/none (stderr=%s)", v, code, len(doc.Findings), doc.Skipped, stderr.String())
		}
		if doc.Summary.Evaluated != 2 {
			t.Errorf("Go %s: Evaluated = %d, want 2 (the vulnerable package and its clean sibling)", v, doc.Summary.Evaluated)
		}
	}
}

// #3: through the real dpkg catalog, a binary that shares its source's name
// is judged on the source version dpkg recorded, exactly as a differently
// named binary from the same source is.
func TestRun_DebianSameNameBinaryIsJudgedOnItsSourceVersion(t *testing.T) {
	db := vexDB(t, "Debian:12", vexAdv{"DEBIAN-2031-1", "CVE-2031-9001", "util-linux", "2.38.1-5+deb12u3"})
	for _, name := range []string{"bsdutils", "util-linux"} {
		image := filepath.Join(t.TempDir(), "target.tar")
		status := fmt.Sprintf(`Package: %s
Status: install ok installed
Version: 1:2.38.1-5+deb12u3
Source: util-linux (2.38.1-5+deb12u2)
Architecture: amd64

`, name)
		writeImageTar(t, image, map[string]string{osReleasePath: "ID=debian\nVERSION_ID=\"12\"\n", dpkgDBPath: status})
		var out, stderr bytes.Buffer
		code := Run(context.Background(), db, "docker-archive:"+image, Options{Output: "json", FailOnUnknown: true, FailOnIncomplete: true}, &out, &stderr)
		var doc report.Document
		if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
			t.Fatalf("%s: decode: %v stderr=%s", name, err, stderr.String())
		}
		if code != 1 || len(doc.Findings) != 1 || len(doc.Skipped) != 0 {
			t.Errorf("binary=%s: exit=%d findings=%d skips=%d, want 1/1/0: the source util-linux 2.38.1-5+deb12u2 is below the fix (stderr=%s)", name, code, len(doc.Findings), len(doc.Skipped), stderr.String())
		}
	}
}
