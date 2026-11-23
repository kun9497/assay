package main

import (
	"bytes"
	"fmt"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/registry"

	"github.com/kun9497/assay/internal/store"
)

// D169, the dispatch: `db update` must hand --allow-older to the pull. The
// parser accepts the flag and dbcmd's own tests hold the refusal, so the one
// line in case "update": that joins them is what this drives. The published
// artifact is built now; the database in place says it was built an hour
// from now, so the two runs differ only in the flag.
func TestRun_DBUpdateAllowOlderReachesPull(t *testing.T) {
	srv := httptest.NewServer(registry.New())
	defer srv.Close()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	ref := fmt.Sprintf("%s/assay-db:v%d", u.Host, store.SchemaVersion)
	publishUnsignedSeedArtifact(t, ref, store.SchemaVersion)

	dir := t.TempDir()
	t.Setenv("ASSAY_DB_DIR", dir)
	w, err := store.Create(filepath.Join(dir, "vulnerability.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := w.SetMeta(store.Meta{BuiltAt: time.Now().UTC().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if code := run([]string{"db", "update", "--from", ref, "--allow-unsigned"}, &stdout, &stderr); code != exitError {
		t.Fatalf("db update of an older artifact = %d, want %d\n%s", code, exitError, stderr.String())
	}
	if !strings.Contains(stderr.String(), "refusing to replace a newer database with an older one") {
		t.Errorf("stderr does not say why:\n%s", stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"db", "update", "--from", ref, "--allow-unsigned", "--allow-older"}, &stdout, &stderr); code != exitOK {
		t.Fatalf("db update --allow-older = %d, want %d\n%s", code, exitOK, stderr.String())
	}
}
