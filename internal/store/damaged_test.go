package store

import (
	"path/filepath"
	"strings"
	"testing"

	bolt "go.etcd.io/bbolt"

	"github.com/kun9497/assay/internal/advisory"
)

// QA 2026-11-20. Lookup and RatingsFor fail loudly on an inconsistent
// database, and nothing held it: each of the three returns could become a
// `continue` -- a short list that reads as fewer vulnerabilities -- with
// every suite green.

// damage builds a current-schema database, opens it for writing as bbolt and
// edits it, then reopens it through the store.
func damage(t *testing.T, edit func(tx *bolt.Tx) error) *Bolt {
	t.Helper()
	path := filepath.Join(t.TempDir(), "d.db")
	w, err := Create(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"GHSA-a", "GHSA-b"} {
		if err := w.Put(sample(id, "npm", "left-pad")); err != nil {
			t.Fatal(err)
		}
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
	raw, err := bolt.Open(path, 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := raw.Update(edit); err != nil {
		t.Fatal(err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}
	b, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { b.Close() })
	return b
}

func TestLookup_ADanglingIndexEntryIsAnError(t *testing.T) {
	b := damage(t, func(tx *bolt.Tx) error { return tx.Bucket(bucketByID).Delete([]byte("GHSA-a")) })
	got, err := b.Lookup("npm", "left-pad")
	if err == nil || !strings.Contains(err.Error(), "references missing advisory") {
		t.Errorf("Lookup = %d advisories, err %v; want the dangling entry refused", len(got), err)
	}
}

func TestLookup_AnUndecodableAdvisoryIsAnError(t *testing.T) {
	b := damage(t, func(tx *bolt.Tx) error { return tx.Bucket(bucketByID).Put([]byte("GHSA-a"), []byte("{")) })
	got, err := b.Lookup("npm", "left-pad")
	if err == nil || !strings.Contains(err.Error(), "decode advisory") {
		t.Errorf("Lookup = %d advisories, err %v; want the record refused", len(got), err)
	}
}

func TestRatingsFor_AnUndecodableRatingIsAnError(t *testing.T) {
	b := damage(t, func(tx *bolt.Tx) error {
		c := tx.Bucket(bucketRatings).Cursor()
		k, _ := c.First()
		return tx.Bucket(bucketRatings).Put(append([]byte(nil), k...), []byte("{"))
	})
	got, err := b.RatingsFor("CVE-2026-1")
	if err == nil || !strings.Contains(err.Error(), "decode rating") {
		t.Errorf("RatingsFor = %d ratings, err %v; want the record refused", len(got), err)
	}
}
