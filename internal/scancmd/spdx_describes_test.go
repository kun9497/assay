package scancmd

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// QA 2026-11-02, finding #6, end to end. An SPDX document's DESCRIBES
// relationship was read as naming a pseudo-package to exclude, with no check
// that the entry it named was one. A document that describes the one real,
// versioned package it inventories -- the shape a hand-written or
// single-package SBOM takes -- scanned as "no components": not cataloged,
// not counted, in no skip bucket, exit 0 under `--fail-on low
// --fail-on-incomplete`. The caller's test: through Run, with the DESCRIBES
// pointing at the only package, the advisory on that package is a finding
// and the verdict is exit 1.
func TestRun_SPDXDescribedRealPackageIsScanned(t *testing.T) {
	dbPath := buildMatrixDB(t, []matrixAdv{
		{id: "GHSA-spdx-described", pkg: "spdxdescribed", fixed: "2.0.0", vectors: []string{vecCritical}},
	})
	const doc = `{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","packages":[
	  {"name":"spdxdescribed","SPDXID":"SPDXRef-Package-spdxdescribed","versionInfo":"1.0.0",
	   "externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl",
	     "referenceLocator":"pkg:golang/example.com/spdxdescribed@1.0.0"}]}],
	  "relationships":[{"spdxElementId":"SPDXRef-DOCUMENT",
	    "relatedSpdxElement":"SPDXRef-Package-spdxdescribed","relationshipType":"DESCRIBES"}]}`
	path := filepath.Join(t.TempDir(), "described.spdx.json")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}

	var out, errOut bytes.Buffer
	code := Run(context.Background(), dbPath, path,
		Options{FailOn: &bandLow, FailOnIncomplete: true}, &out, &errOut)
	if code != 1 {
		t.Fatalf("Run(spdx describing its one real package) = %d, want 1: the described package "+
			"must be scanned, not dropped as a document root\nstdout: %s\nstderr: %s",
			code, out.String(), errOut.String())
	}
	if !strings.Contains(out.String(), "GHSA-spdx-described") {
		t.Errorf("stdout = %q, want the GHSA-spdx-described finding on the described package", out.String())
	}
	if strings.Contains(out.String(), "no components") {
		t.Errorf("stdout = %q, reports an empty document for one that inventories a package", out.String())
	}
}
