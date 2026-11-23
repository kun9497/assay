package scancmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/store"
)

// D172 end to end: the notice is named on the finding it announced, and is
// not an unrated finding of its own under --fail-on-unknown.
func TestRun_ANoticeIsNotAnUnratedSecondFinding(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "v.db")
	w, err := store.Create(db)
	if err != nil {
		t.Fatal(err)
	}
	const eco = "Ubuntu:22.04:LTS"
	aff := []advisory.Affected{{Ecosystem: eco, Name: "openssl", Ranges: []advisory.Range{{Type: "ECOSYSTEM",
		Events: []advisory.Event{{Introduced: "0"}, {Fixed: "3.0.2-0ubuntu1.10"}}}}}}
	for _, a := range []advisory.Advisory{
		{ID: "UBUNTU-CVE-2031-1", Database: "UBUNTU", Kind: advisory.KindVulnerability, Upstream: []string{"CVE-2031-1"}, Affected: aff,
			Severity: []advisory.Severity{{Type: "Ubuntu", Score: "medium"}}},
		{ID: "USN-1-1", Database: "USN", Kind: advisory.KindVulnerability, Upstream: []string{"CVE-2031-1", "UBUNTU-CVE-2031-1"}, Affected: aff},
	} {
		if err := w.Put(a); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.SetMeta(store.Meta{Providers: map[string]store.Provenance{"osv": {Ecosystems: []string{eco}}}}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	sbom := filepath.Join(dir, "s.cdx.json")
	if err := os.WriteFile(sbom, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","components":[{"type":"library","name":"openssl","version":"3.0.2-0ubuntu1.9","purl":"pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1.9?arch=amd64&distro=ubuntu-22.04"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	out, stderr, code := provRun(t, db, sbom, Options{Output: "json", FailOnUnknown: true})
	if code != 0 {
		t.Errorf("exit %d, want 0: the one vulnerability is rated\n%s", code, stderr)
	}
	compact := strings.NewReplacer(" ", "", string(rune(10)), "").Replace(out)
	if !strings.Contains(compact, `"notices":["USN-1-1"]`) || !strings.Contains(compact, `"findings":1,`) {
		t.Errorf("want one finding naming the notice:\n%s", out)
	}
	ex, _, _ := provRun(t, db, sbom, Options{Explain: "CVE-2031-1"})
	if !strings.Contains(ex, "notices:  USN-1-1") {
		t.Errorf("--explain does not name the notice:\n%s", ex)
	}
}
