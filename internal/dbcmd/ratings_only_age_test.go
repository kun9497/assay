package dbcmd

import (
	"bytes"
	"context"
	"io"
	"path/filepath"
	"testing"
	"time"

	"github.com/kun9497/assay/internal/provider"
	"github.com/kun9497/assay/internal/store"
)

// QA 2026-11-20. A ratings-only build carries its seed's advisories, so it
// carries their date, through a chain of such builds.
func TestUpdate_RatingsOnlyKeepsTheAdvisoriesDate(t *testing.T) {
	built := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	dir := t.TempDir()
	seed := filepath.Join(dir, "seed.db")
	w, err := store.Create(seed)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.SetMeta(store.Meta{BuiltAt: built, Providers: map[string]store.Provenance{"osv": {Ecosystems: []string{"Go"}}}}); err != nil {
		t.Fatal(err)
	}
	w.Close()
	for _, name := range []string{"one.db", "two.db"} {
		dst := filepath.Join(dir, name)
		var errOut bytes.Buffer
		ann := fakeAnnotator{name: "nvd"}
		if code := Update(context.Background(), dst, seed, "", true, nil, []provider.Annotator{ann}, nil, nil, io.Discard, &errOut); code != 0 {
			t.Fatalf("%s: %s", name, errOut.String())
		}
		db, err := store.Open(dst)
		if err != nil {
			t.Fatal(err)
		}
		m, err := db.Meta()
		db.Close()
		if err != nil {
			t.Fatal(err)
		}
		if !m.AdvisoriesBuiltAt.Equal(built) || m.BuiltAt.Equal(built) {
			t.Errorf("%s: advisories %v, build %v; want %v and this run's", name, m.AdvisoriesBuiltAt, m.BuiltAt, built)
		}
		seed = dst
	}
}
