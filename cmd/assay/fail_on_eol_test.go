package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/kun9497/assay/internal/store"
)

// QA 2026-11-20. Nothing held the flag: parsing it into nothing left the CLI
// suite green.
func TestRun_ScanFailOnEOLReachesRealExitCode(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("ASSAY_DB_DIR", dir)
	w, err := store.Create(filepath.Join(dir, "vulnerability.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := w.SetMeta(store.Meta{
		Providers: map[string]store.Provenance{"osv": {Ecosystems: []string{"npm"}}},
		EOL:       []store.EOLRelease{{DistroID: "debian", Release: "11", EOLFrom: "2000-10-30"}},
	}); err != nil {
		t.Fatal(err)
	}
	w.Close()
	sbom := filepath.Join(dir, "s.cdx.json")
	if err := os.WriteFile(sbom, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","components":[
	 {"type":"operating-system","name":"debian","version":"11","properties":[{"name":"syft:distro:id","value":"debian"},{"name":"syft:distro:versionID","value":"11"}]},
	 {"type":"library","name":"x","version":"1.0.0","purl":"pkg:npm/x@1.0.0"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for want, args := range map[int][]string{0: {"scan", sbom}, 1: {"scan", sbom, "--fail-on-eol"}} {
		var out, errOut bytes.Buffer
		if got := run(args, &out, &errOut); got != want {
			t.Errorf("run(%q) = %d, want %d%s%s", args, got, want, string(rune(10)), errOut.String())
		}
	}
}
