package scancmd

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/store"
)

// 2026-10-22 audit A11: Alpine edge writes VERSION_ID as
// "X.Y.0_alphaYYYYMMDD" (a real alpine:20251224 snapshot reads
// 3.24.0_alpha20251224; alpine:edge on 2026-10-30, 3.25.0_alpha20260805),
// and the key took the first two components and dropped the rest unchecked:
// the image was judged as stable Alpine 3.24, with nothing marking it edge.
// OSV publishes no edge ecosystem, and distro.go's own comment already says
// edge is refused rather than keyed best-effort: a key nothing stored under it
// matches nothing, and the wrong release's key matches the wrong fixes.
func TestRun_A11_AlpineEdgeIsNotJudgedAsAStableRelease(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vulnerability.db")
	w, err := store.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Put(advisory.Advisory{
		ID: "ALPINE-A11-0001", Kind: advisory.KindVulnerability, Database: "ALPINE",
		Affected: []advisory.Affected{{Ecosystem: "Alpine:v3.24", Name: "busybox", Ranges: []advisory.Range{{
			Type: advisory.RangeEcosystem, Events: []advisory.Event{{Introduced: "0"}, {Fixed: "1.36.1-r16"}},
		}}}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := w.SetMeta(store.Meta{Providers: map[string]store.Provenance{"osv": {Ecosystems: []string{"Alpine:v3.24"}}}}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	tarPath := filepath.Join(t.TempDir(), "image.tar")
	writeImageTar(t, tarPath, map[string]string{
		osReleasePath: "ID=alpine\nVERSION_ID=3.24.0_alpha20251224\nPRETTY_NAME=\"Alpine Linux edge\"\n",
		apkDBPath:     apkOneRecord,
	})
	var out, errOut bytes.Buffer
	code := Run(context.Background(), path, "docker-archive:"+tarPath, Options{Output: "json"}, &out, &errOut)
	var r struct {
		Findings []json.RawMessage `json:"findings"`
		Summary  struct {
			NotEvaluated int `json:"notEvaluated"`
		} `json:"summary"`
	}
	if err := json.Unmarshal(out.Bytes(), &r); err != nil {
		t.Fatalf("decode: %v\nstderr: %s", err, errOut.String())
	}
	if len(r.Findings) != 0 || r.Summary.NotEvaluated != 1 || code != 2 {
		t.Errorf("findings = %d, notEvaluated = %d, exit = %d; want 0, 1, 2: an edge image has no advisory ecosystem\nstderr: %s",
			len(r.Findings), r.Summary.NotEvaluated, code, errOut.String())
	}
	if strings.Contains(out.String(), "Alpine:v3.24") {
		t.Errorf("the report names Alpine:v3.24, the stable release an edge image is not:\n%s", out.String())
	}
}
