package store

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	bolt "go.etcd.io/bbolt"

	"github.com/kun9497/assay/internal/advisory"
)

func verifyDB(t *testing.T, n int) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "v.db")
	w, err := Create(path)
	if err != nil {
		t.Fatal(err)
	}
	var as []advisory.Advisory
	for i := 0; i < n; i++ {
		as = append(as, sample(fmt.Sprintf("GHSA-%05d", i), "npm", fmt.Sprintf("pkg%05d", i)))
	}
	if err := w.PutMany(as); err != nil {
		t.Fatal(err)
	}
	if err := w.PutRatings([]advisory.Rating{{CVE: "CVE-2026-1", Source: "nvd"}}); err != nil {
		t.Fatal(err)
	}
	if err := w.SetMeta(Meta{Providers: map[string]Provenance{"osv": {Ecosystems: []string{"npm"}}}}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func verifyAt(t *testing.T, path string) (int, error) {
	t.Helper()
	b, err := Open(path)
	if err != nil {
		return 0, err
	}
	defer b.Close()
	return b.Verify()
}

// Every entry of every data bucket is covered, and the artifact record that
// `db update` writes afterwards is not.
func TestVerify_ReadsEveryBucket(t *testing.T) {
	path := verifyDB(t, 3)
	if n, err := verifyAt(t, path); err != nil || n != 7 {
		t.Fatalf("healthy: %d entries, %v; want 7 (3 index, 3 records, 1 rating)", n, err)
	}
	if err := SetArtifactAt(path, ArtifactRecord{Digest: "sha256:x"}); err != nil {
		t.Fatal(err)
	}
	if err := StripEnrichment(path); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyAt(t, path); err != nil {
		t.Fatalf("after the artifact record and the strip: %v", err)
	}
	for name, edit := range map[string]func(tx *bolt.Tx) error{
		"index entry gone": func(tx *bolt.Tx) error { c := tx.Bucket(bucketAdvisories).Cursor(); c.First(); return c.Delete() },
		"record changed":   func(tx *bolt.Tx) error { return tx.Bucket(bucketByID).Put([]byte("GHSA-00001"), []byte("{}")) },
		"rating gone":      func(tx *bolt.Tx) error { c := tx.Bucket(bucketRatings).Cursor(); c.First(); return c.Delete() },
		"enrichment added": func(tx *bolt.Tx) error { return tx.Bucket(bucketEnrichment).Put([]byte("k"), []byte("v")) },
		"key length shifts": func(tx *bolt.Tx) error {
			b := tx.Bucket(bucketRatings)
			c := b.Cursor()
			k, v := c.First()
			nk, nv := append(append([]byte(nil), k...), v[0]), append([]byte(nil), v[1:]...)
			c.Delete()
			return b.Put(nk, nv)
		},
	} {
		p := verifyDB(t, 3)
		raw, err := bolt.Open(p, 0o600, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := raw.Update(edit); err != nil {
			t.Fatal(err)
		}
		raw.Close()
		if _, err := verifyAt(t, p); !errors.Is(err, ErrDamaged) {
			t.Errorf("%s: %v, want ErrDamaged", name, err)
		}
	}
}

// A strip of a database with enrichment leaves digests for what is left.
func TestVerify_AfterEnrichmentIsStripped(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v.db")
	w, err := Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.PutEnrichment(advisory.Enrichment{CVE: "CVE-2026-1", Source: "kisa", Title: "t"}); err != nil {
		t.Fatal(err)
	}
	if err := w.SetMeta(Meta{}); err != nil {
		t.Fatal(err)
	}
	w.Close()
	if err := StripEnrichment(path); err != nil {
		t.Fatal(err)
	}
	if n, err := verifyAt(t, path); err != nil || n != 0 {
		t.Errorf("%d entries, %v; want an empty, verified database", n, err)
	}
}

// Damage on disk: a page that holds entries, overwritten with zeros or noise
// past its header, never verifies. A page can also make bbolt panic or read
// outside the file; that is the same answer, not a crash.
func TestVerify_DamagedPages(t *testing.T) {
	path := verifyDB(t, 3000)
	whole, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := bolt.Open(path, 0o600, &bolt.Options{ReadOnly: true, PreLoadFreelist: true})
	if err != nil {
		t.Fatal(err)
	}
	page := raw.Info().PageSize
	var live []int
	if err := raw.View(func(tx *bolt.Tx) error {
		for id := 2; int64(id)*int64(page) < tx.Size(); id++ {
			info, err := tx.Page(id)
			if err != nil {
				return err
			}
			if info != nil && (info.Type == "leaf" || info.Type == "branch") && info.Count > 1 {
				live = append(live, id)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	raw.Close()
	if len(live) < 20 {
		t.Fatalf("only %d pages hold entries; the fixture is too small", len(live))
	}
	for _, id := range live {
		for _, fill := range []byte{0, 0xff} {
			b := append([]byte(nil), whole...)
			for i := id*page + 16; i < (id+1)*page; i++ {
				b[i] = fill
			}
			p := filepath.Join(t.TempDir(), "cut.db")
			if err := os.WriteFile(p, b, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := verifyAt(t, p); err == nil {
				t.Errorf("page %d filled with %#x: verified", id, fill)
			}
		}
	}
}

func TestVerify_ADatabaseWithoutDigests(t *testing.T) {
	path := verifyDB(t, 1)
	raw, err := bolt.Open(path, 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := raw.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketMeta).Put([]byte("meta"), []byte(fmt.Sprintf(`{"schema":%d}`, SchemaVersion)))
	}); err != nil {
		t.Fatal(err)
	}
	raw.Close()
	if _, err := verifyAt(t, path); !errors.Is(err, ErrNoDigests) {
		t.Errorf("%v, want ErrNoDigests", err)
	}
	if err := StripEnrichment(path); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyAt(t, path); !errors.Is(err, ErrNoDigests) {
		t.Errorf("a strip gave it digests: %v", err)
	}
}
