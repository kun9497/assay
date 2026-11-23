package scancmd

import (
	"fmt"
	"testing"
)

// QA 2026-11-20. Composer and Cargo lockfiles carry a package's lower-case
// name; GHSA files some of the same packages under capitals
// (KnpLabs/knp-snappy, SurrealDB). The store index and the matcher both key
// on the name as given, so the lockfile's name reached no such advisory and
// the package was judged clean. Held through Run, the store and the matcher,
// in both directions: the capitalised spelling an SBOM may carry must still
// reach a lower-case record.
func TestRun_PackagistAndCratesNamesMatchWhateverTheirCase(t *testing.T) {
	for _, tc := range []struct{ eco, purlType, advisoryName, installedName string }{
		{"Packagist", "composer", "KnpLabs/knp-snappy", "knplabs/knp-snappy"},
		{"Packagist", "composer", "knplabs/knp-snappy", "KnpLabs/knp-snappy"},
		{"crates.io", "cargo", "SurrealDB", "surrealdb"},
		{"crates.io", "cargo", "surrealdb", "SurrealDB"},
	} {
		t.Run(tc.eco+" "+tc.advisoryName+" vs "+tc.installedName, func(t *testing.T) {
			db := vexDB(t, tc.eco, vexAdv{"GHSA-test-case-0001", "CVE-2031-7001", tc.advisoryName, "9.9.9"})
			sbom := writeSBOM(t, "cyclonedx", fmt.Sprintf(`{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[
 {"type":"library","name":%q,"version":"1.7.0","purl":"pkg:%s/%s@1.7.0"}]}`, tc.installedName, tc.purlType, tc.installedName))
			code, doc, stderr := runSBOMJSON(t, db, sbom)
			if code != 1 || len(doc.Findings) != 1 || len(doc.Skipped) != 0 {
				t.Fatalf("exit=%d findings=%d skips=%d, want 1/1/0 (stderr=%s)", code, len(doc.Findings), len(doc.Skipped), stderr)
			}
		})
	}
}
