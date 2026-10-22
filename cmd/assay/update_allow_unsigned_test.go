package main

import (
	"bytes"
	"fmt"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/registry"

	"github.com/kun9497/assay/internal/store"
)

// The dispatch, not the parser: `db update` must hand --allow-unsigned to
// dbcmd.Pull (CLAUDE.md: "the helper is covered; nothing calls it" --
// TestResolveUpdateRef_AllowUnsigned holds the parser, and dbcmd's own
// tests hold Pull, so the one line in case "update": that joins them was
// held by nothing). An unsigned artifact in an in-process registry is
// refused without the flag and installed, loudly, with it; the two runs
// differ only in that flag, so a dispatch that dropped it fails the second.
func TestRun_DBUpdateAllowUnsignedReachesPull(t *testing.T) {
	srv := httptest.NewServer(registry.New())
	defer srv.Close()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	ref := fmt.Sprintf("%s/assay-db:v%d", u.Host, store.SchemaVersion)
	publishUnsignedSeedArtifact(t, ref, store.SchemaVersion)
	t.Setenv("ASSAY_DB_DIR", t.TempDir())

	var stdout, stderr bytes.Buffer
	if code := run([]string{"db", "update", "--from", ref}, &stdout, &stderr); code != exitError {
		t.Fatalf("db update of an unsigned artifact = %d, want %d\n%s", code, exitError, stderr.String())
	}
	if !strings.Contains(stderr.String(), "is not signed") {
		t.Errorf("stderr does not say why:\n%s", stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"db", "update", "--from", ref, "--allow-unsigned"}, &stdout, &stderr); code != exitOK {
		t.Fatalf("db update --allow-unsigned = %d, want %d\n%s", code, exitOK, stderr.String())
	}
	if !strings.Contains(stderr.String(), "UNVERIFIED") {
		t.Errorf("stderr does not warn that the install is unverified:\n%s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Errorf("db update wrote to stdout:\n%s", stdout.String())
	}
}
