package scancmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	bolt "go.etcd.io/bbolt"
)

// QA 2026-11-20. A database file cut short killed the scan with a Go runtime
// fault inside store.Open: no "error:" line, no sidecar, and exit 2 only
// because that is the runtime's crash code. Without the check this test does
// not fail, it takes the test binary down.
func TestRun_ATruncatedDatabaseIsAnErrorWithASidecar(t *testing.T) {
	dir := t.TempDir()
	db := provDB(t, dir)
	sbom := filepath.Join(dir, "s.cdx.json")
	provSBOM(t, sbom, "1.0.0")
	whole, err := os.ReadFile(db)
	if err != nil {
		t.Fatal(err)
	}
	for _, size := range []int{2 * os.Getpagesize(), 3 * os.Getpagesize(), 4*os.Getpagesize() + 1} {
		cut := filepath.Join(dir, "cut.db")
		if size >= len(whole) {
			t.Fatalf("the fixture database is only %d bytes", len(whole))
		}
		if err := os.WriteFile(cut, whole[:size], 0o600); err != nil {
			t.Fatal(err)
		}
		side := filepath.Join(dir, "prov.json")
		os.Remove(side)
		stdout, stderr, code := provRun(t, cut, sbom, Options{ProvenanceFile: side})
		if code != 2 || stdout != "" {
			t.Errorf("%d bytes: exit %d with stdout %q, want 2 and nothing", size, code, stdout)
		}
		if !strings.Contains(stderr, "the file is truncated") || !strings.Contains(stderr, "run `assay db update`") {
			t.Errorf("%d bytes: stderr names neither the truncation nor the remedy:\n%s", size, stderr)
		}
		if e, _ := at(t, readSidecar(t, side), "run", "error").(string); !strings.Contains(e, "truncated") {
			t.Errorf("%d bytes: sidecar run.error = %q", size, e)
		}
	}
}

// A record the store cannot answer for reaches the verdict as exit 2, not as
// one finding fewer.
func TestRun_ADanglingIndexEntryIsExitTwo(t *testing.T) {
	dir := t.TempDir()
	db := provDB(t, dir)
	sbom := filepath.Join(dir, "s.cdx.json")
	provSBOM(t, sbom, "1.0.0")
	raw, err := bolt.Open(db, 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := raw.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("by-id"))
		var keys [][]byte
		if err := b.ForEach(func(k, _ []byte) error {
			keys = append(keys, append([]byte(nil), k...))
			return nil
		}); err != nil {
			return err
		}
		for _, k := range keys {
			if err := b.Delete(k); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	raw.Close()
	stdout, stderr, code := provRun(t, db, sbom, Options{})
	if code != 2 || stdout != "" || !strings.Contains(stderr, "error: match:") {
		t.Errorf("exit %d, stdout %q, want 2 and a match error; stderr:%s", code, stdout, stderr)
	}
}
