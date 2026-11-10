package scancmd

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/report"
	"github.com/kun9497/assay/internal/store"
)

// PR #270 review, end to end, on the review's own document shapes.
//
// An unkeyed busybox under a subject that declares two Alpine releases,
// beside busybox keyed to 3.19 and to 3.20 at the top, belongs to neither
// provably: it stays its own package, not evaluated (exit 2 under
// --fail-on-incomplete), and its install path is on no finding -- in either
// order of the two keyed listings. With one keyed twin it is that package.
//
// An operating-system component's own children are keyed by it: Alpine as
// metadata.component with busybox directly under it is Alpine, with or
// without a Debian declared at the top (which keyed it Debian:11 before).
func TestRun_PR270_AmbiguousTwinAndOSParent(t *testing.T) {
	db := filepath.Join(t.TempDir(), "vulnerability.db")
	w, err := store.Create(db)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range []advisory.Advisory{
		{ID: "ALPINE319-CVE-2024-58251", Kind: advisory.KindVulnerability, Database: "ALPINE", Upstream: []string{"CVE-2024-58251"},
			Affected: []advisory.Affected{{Ecosystem: "Alpine:v3.19", Name: "busybox",
				Ranges: []advisory.Range{{Type: advisory.RangeEcosystem, Events: []advisory.Event{{Introduced: "0"}, {Fixed: "1.36.1-r21"}}}}}}},
		{ID: "ALPINE320-CVE-2025-46394", Kind: advisory.KindVulnerability, Database: "ALPINE", Upstream: []string{"CVE-2025-46394"},
			Affected: []advisory.Affected{{Ecosystem: "Alpine:v3.20", Name: "busybox",
				Ranges: []advisory.Range{{Type: advisory.RangeEcosystem, Events: []advisory.Event{{Introduced: "0"}, {Fixed: "1.36.1-r30"}}}}}}},
		{ID: "DEBIAN-CVE-2099-0001", Kind: advisory.KindVulnerability, Database: "DEBIAN", Upstream: []string{"CVE-2099-0001"},
			Affected: []advisory.Affected{{Ecosystem: "Debian:11", Name: "busybox",
				Ranges: []advisory.Range{{Type: advisory.RangeEcosystem, Events: []advisory.Event{{Introduced: "0"}, {Fixed: "1:9.9"}}}}}}},
	} {
		if err := w.Put(a); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.SetMeta(store.Meta{Providers: map[string]store.Provenance{"osv": {Ecosystems: []string{"Alpine:v3.19", "Alpine:v3.20", "Debian:11"}}}}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	const (
		start  = `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,`
		bb319  = `{"type":"library","name":"busybox","version":"1.36.1-r20","purl":"pkg:apk/alpine/busybox@1.36.1-r20?arch=x86_64&distro=alpine-3.19","properties":[{"name":"syft:location:0:path","value":"/image-0/lib/apk/db/installed"}]}`
		bb320  = `{"type":"library","name":"busybox","version":"1.36.1-r20","purl":"pkg:apk/alpine/busybox@1.36.1-r20?arch=x86_64&distro=alpine-3.20","properties":[{"name":"syft:location:0:path","value":"/image-1/lib/apk/db/installed"}]}`
		child  = `{"type":"library","name":"busybox","version":"1.36.1-r20","purl":"pkg:apk/alpine/busybox@1.36.1-r20?arch=x86_64","properties":[{"name":"syft:location:0:path","value":"/child/root/lib/apk/db/installed"}]}`
		os319  = `{"type":"operating-system","name":"alpine","version":"3.19"}`
		os320  = `{"type":"operating-system","name":"alpine","version":"3.20"}`
		osAlp  = `{"type":"operating-system","name":"alpine","version":"3.19.9","components":[` + child + `]}`
		debian = `{"type":"operating-system","name":"debian","version":"11"}`
	)
	run := func(body string) (int, report.Document) {
		t.Helper()
		p := filepath.Join(t.TempDir(), "sbom.cdx.json")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		var out, errOut bytes.Buffer
		code := Run(context.Background(), db, p, Options{Output: "json", FailOnIncomplete: true}, &out, &errOut)
		var doc report.Document
		if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
			t.Fatalf("decode: %v\n%s", err, errOut.String())
		}
		return code, doc
	}
	// finding id -> ecosystem and the install paths on it.
	seen := func(doc report.Document) map[string]string {
		m := map[string]string{}
		for _, f := range doc.Findings {
			var paths []string
			for _, l := range f.Package.Locations {
				paths = append(paths, l.Path)
			}
			sort.Strings(paths)
			m[f.Advisory.ID] = f.Package.Ecosystem + " " + strings.Join(paths, ",")
		}
		return m
	}
	subject := func(children string) string {
		return `"metadata":{"component":{"type":"container","name":"demo","components":[` + children + `]}}}`
	}
	for _, order := range [][2]string{{bb319, bb320}, {bb320, bb319}} {
		code, doc := run(start + `"components":[` + order[0] + `,` + order[1] + `],` + subject(os319+`,`+os320+`,`+child))
		got := seen(doc)
		if code != 2 || doc.Summary.NotEvaluated != 1 || doc.Summary.Components != 3 {
			t.Errorf("ambiguous twin: exit=%d notEvaluated=%d components=%d, want 2, 1, 3", code, doc.Summary.NotEvaluated, doc.Summary.Components)
		}
		for id, v := range got {
			if strings.Contains(v, "/child/") {
				t.Errorf("ambiguous twin: the unkeyed listing's path is on %s: %s", id, v)
			}
		}
		if !strings.HasPrefix(got["ALPINE319-CVE-2024-58251"], "Alpine:v3.19 ") || !strings.HasPrefix(got["ALPINE320-CVE-2025-46394"], "Alpine:v3.20 ") {
			t.Errorf("ambiguous twin: findings = %v, want each release's own", got)
		}
	}
	t.Run("one keyed twin is that package", func(t *testing.T) {
		code, doc := run(start + `"components":[` + bb319 + `],` + subject(os319+`,`+os320+`,`+child))
		got := seen(doc)
		if code != 0 || doc.Summary.NotEvaluated != 0 || doc.Summary.Components != 1 || got["ALPINE319-CVE-2024-58251"] != "Alpine:v3.19 /child/root/lib/apk/db/installed,/image-0/lib/apk/db/installed" {
			t.Errorf("exit=%d notEvaluated=%d components=%d findings=%v", code, doc.Summary.NotEvaluated, doc.Summary.Components, got)
		}
	})
	for _, top := range []string{"", debian} {
		t.Run("OS parent, top="+top, func(t *testing.T) {
			code, doc := run(start + `"components":[` + top + `],"metadata":{"component":` + osAlp + `}}`)
			got := seen(doc)
			if code != 0 || len(got) != 1 || !strings.HasPrefix(got["ALPINE319-CVE-2024-58251"], "Alpine:v3.19 ") || doc.Summary.NotEvaluated != 0 {
				t.Errorf("exit=%d notEvaluated=%d findings=%v, want ALPINE319 on Alpine:v3.19 only", code, doc.Summary.NotEvaluated, got)
			}
		})
	}
}
