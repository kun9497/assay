package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/kun9497/assay/internal/report"
	"github.com/kun9497/assay/internal/store"
)

// D120 through the CLI: `db update` keeps the digest it pulled and a scan
// names it, the tool record carries the ldflags values, and --provenance is
// parsed in both spellings, refused twice, and honoured on an exit that
// happens before scancmd.Run.

func provSBOMFile(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "s.cdx.json")
	doc := `{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[` +
		`{"type":"library","name":"example.com/a","version":"1.0.0","purl":"pkg:golang/example.com/a@1.0.0"}]}`
	if err := os.WriteFile(p, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRun_D120_DBUpdateDigestReachesTheScan(t *testing.T) {
	srv := httptest.NewServer(registry.New())
	defer srv.Close()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	ref := fmt.Sprintf("%s/assay-db:v%d", u.Host, store.SchemaVersion)
	publishSeedArtifact(t, ref, store.SchemaVersion)
	r, err := name.ParseReference(ref)
	if err != nil {
		t.Fatal(err)
	}
	img, err := remote.Image(r)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := img.Digest()
	if err != nil {
		t.Fatal(err)
	}
	dbDir := t.TempDir()
	t.Setenv("ASSAY_DB_DIR", dbDir)

	var stdout, stderr bytes.Buffer
	if code := run([]string{"db", "update", "--from", ref}, &stdout, &stderr); code != exitOK {
		t.Fatalf("db update = %d, want 0\n%s", code, stderr.String())
	}
	if _, err := os.Stat(filepath.Join(dbDir, "vulnerability.db.artifact.json")); err != nil {
		t.Fatalf("db update wrote no artifact record: %v", err)
	}

	stdout.Reset()
	stderr.Reset()
	side := filepath.Join(t.TempDir(), "prov.json")
	run([]string{"scan", provSBOMFile(t), "--output", "json", "--provenance=" + side}, &stdout, &stderr)
	var doc report.Document
	if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
		t.Fatalf("scan wrote no JSON report: %v\n%s\n%s", err, stdout.String(), stderr.String())
	}
	if doc.Provenance == nil || doc.Provenance.Database == nil || doc.Provenance.Database.Artifact == nil {
		t.Fatalf("report names no artifact: %+v", doc.Provenance)
	}
	if got := doc.Provenance.Database.Artifact.Digest; got != digest.String() {
		t.Errorf("provenance.database.artifact.digest = %s, want the pulled %s", got, digest)
	}
	tool := doc.Provenance.Tool
	if tool.Name != "assay" || tool.Version != version || tool.Commit != commit || tool.BuildDate != date || !tool.Dev {
		t.Errorf("provenance.tool = %+v, want the ldflags values of this dev build", tool)
	}
	data, err := os.ReadFile(side)
	if err != nil {
		t.Fatalf("--provenance=<path> wrote nothing: %v", err)
	}
	if !strings.Contains(string(data), digest.String()) {
		t.Errorf("sidecar does not carry the digest:\n%s", data)
	}
	if strings.Contains(string(data), dbDir) || strings.Contains(string(data), strings.ReplaceAll(dbDir, `\`, `\\`)) {
		t.Errorf("sidecar names the database directory:\n%s", data)
	}
}

func TestParseScanArgs_D120_Provenance(t *testing.T) {
	_, opts, err := parseScanArgs([]string{"x.json", "--provenance", "a.json"})
	if err != nil || opts.ProvenanceFile != "a.json" {
		t.Errorf("--provenance a.json = %q, %v", opts.ProvenanceFile, err)
	}
	_, opts, err = parseScanArgs([]string{"--provenance=b.json", "x.json"})
	if err != nil || opts.ProvenanceFile != "b.json" {
		t.Errorf("--provenance=b.json = %q, %v", opts.ProvenanceFile, err)
	}
	for _, args := range [][]string{
		{"x.json", "--provenance", "a.json", "--provenance=b.json"},
		{"x.json", "--provenance=a.json", "--provenance", "a.json"},
	} {
		if _, _, err := parseScanArgs(args); err == nil || !strings.Contains(err.Error(), "more than once") {
			t.Errorf("%v: err = %v, want a refusal of the second --provenance", args, err)
		}
	}
	for _, args := range [][]string{{"x.json", "--provenance"}, {"x.json", "--provenance="}} {
		if _, _, err := parseScanArgs(args); err == nil {
			t.Errorf("%v: accepted a missing path", args)
		}
	}
}

// An exit after argument parsing but before scancmd.Run — no target — still
// writes the sidecar.
func TestRun_D120_NoTargetStillWritesTheSidecar(t *testing.T) {
	side := filepath.Join(t.TempDir(), "prov.json")
	var stdout, stderr bytes.Buffer
	if code := run([]string{"scan", "--provenance", side}, &stdout, &stderr); code != exitError {
		t.Fatalf("scan with no target = %d, want %d", code, exitError)
	}
	if !strings.HasPrefix(stderr.String(), "error: scan requires a target\n") {
		t.Errorf("stderr = %q, want the refusal first", stderr.String())
	}
	data, err := os.ReadFile(side)
	if err != nil {
		t.Fatalf("no sidecar: %v", err)
	}
	var sc struct {
		Run struct {
			ExitCode int    `json:"exitCode"`
			Error    string `json:"error"`
		} `json:"run"`
	}
	if err := json.Unmarshal(data, &sc); err != nil || sc.Run.ExitCode != 2 || sc.Run.Error != "scan requires a target" {
		t.Errorf("sidecar run = %+v (err %v), want exit 2 and the error", sc.Run, err)
	}
}
