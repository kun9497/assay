package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	bolt "go.etcd.io/bbolt"

	"github.com/kun9497/assay/internal/store"
)

// D173 through run: `db verify` and `scan --verify-db` refuse a database
// whose contents changed after its build, and a scan without the flag does
// not read for it.
func TestRun_VerifyDatabase(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("ASSAY_DB_DIR", dir)
	path, err := store.DefaultPath()
	if err != nil {
		t.Fatal(err)
	}
	w, err := store.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.SetMeta(store.Meta{Providers: map[string]store.Provenance{"osv": {Ecosystems: []string{"npm"}}}}); err != nil {
		t.Fatal(err)
	}
	w.Close()
	sbom := filepath.Join(dir, "s.cdx.json")
	if err := os.WriteFile(sbom, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","components":[{"type":"library","name":"x","version":"1.0.0","purl":"pkg:npm/x@1.0.0"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	try := func(args ...string) (int, string, string) {
		var out, errOut bytes.Buffer
		return run(args, &out, &errOut), out.String(), errOut.String()
	}
	if code, out, errOut := try("db", "verify"); code != 0 || !strings.Contains(out, "0 entries verified") {
		t.Fatalf("healthy db verify: exit %d, %q %q", code, out, errOut)
	}
	if code, _, errOut := try("scan", sbom, "--verify-db"); code != 0 {
		t.Fatalf("healthy --verify-db: exit %d, %s", code, errOut)
	}
	if code, _, _ := try("db", "verify", "x"); code != 2 {
		t.Errorf("db verify with an argument: exit %d, want 2", code)
	}
	raw, err := bolt.Open(path, 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := raw.Update(func(tx *bolt.Tx) error { return tx.Bucket([]byte("ratings")).Put([]byte("k"), []byte("v")) }); err != nil {
		t.Fatal(err)
	}
	raw.Close()
	if code, out, errOut := try("db", "verify"); code != 2 || out != "" || !strings.Contains(errOut, "database is damaged") || !strings.Contains(errOut, "db update") {
		t.Errorf("damaged db verify: exit %d, %q %q", code, out, errOut)
	}
	if code, out, errOut := try("scan", sbom, "--verify-db"); code != 2 || out != "" || !strings.Contains(errOut, "error: --verify-db: vulnerability database is damaged") {
		t.Errorf("damaged --verify-db: exit %d, %q %q", code, out, errOut)
	}
	if code, _, _ := try("scan", sbom); code != 0 {
		t.Errorf("a scan without the flag: exit %d", code)
	}
}
