package scancmd

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/report"
	"github.com/kun9497/assay/internal/store"
)

// QA 2026-11-10 ①, end to end. libc6 2.31-13+deb11u14 is listed twice --
// in bom.components and as the subject -- and only one listing states its
// glibc source version, 2.31-13+deb11u13. The advisory is keyed on the
// source and fixed in deb11u14, so the package is affected only when the
// stated source version is kept. Before: affected one way round, clean the
// other. Now both orders find it; two listings stating different source
// versions are judged on neither, with a target-cause skip and exit 2.
func TestRun_QA1110_DuplicateListingKeepsTheStatedSourceVersion(t *testing.T) {
	db := filepath.Join(t.TempDir(), "vulnerability.db")
	w, err := store.Create(db)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Put(advisory.Advisory{
		ID: "DEBIAN-CVE-2026-4046", Kind: advisory.KindVulnerability, Database: "DEBIAN", Upstream: []string{"CVE-2026-4046"},
		Affected: []advisory.Affected{{Ecosystem: "Debian:11", Name: "glibc",
			Ranges: []advisory.Range{{Type: advisory.RangeEcosystem, Events: []advisory.Event{{Introduced: "0"}, {Fixed: "2.31-13+deb11u14"}}}}}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := w.SetMeta(store.Meta{Providers: map[string]store.Provenance{"osv": {Ecosystems: []string{"Debian:11"}}}}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	const (
		start     = `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,`
		versioned = `{"type":"library","name":"libc6","version":"2.31-13+deb11u14","purl":"pkg:deb/debian/libc6@2.31-13%2Bdeb11u14?arch=amd64&distro=debian-11&upstream=glibc%402.31-13%2Bdeb11u13"}`
		nameOnly  = `{"type":"library","name":"libc6","version":"2.31-13+deb11u14","purl":"pkg:deb/debian/libc6@2.31-13%2Bdeb11u14?arch=amd64&distro=debian-11&upstream=glibc"}`
		other     = `{"type":"library","name":"libc6","version":"2.31-13+deb11u14","purl":"pkg:deb/debian/libc6@2.31-13%2Bdeb11u14?arch=amd64&distro=debian-11&upstream=glibc%402.31-13%2Bdeb11u12"}`
	)
	run := func(top, subject string) (int, report.Document) {
		t.Helper()
		p := filepath.Join(t.TempDir(), "sbom.cdx.json")
		if err := os.WriteFile(p, []byte(start+`"components":[`+top+`],"metadata":{"component":`+subject+`}}`), 0o600); err != nil {
			t.Fatal(err)
		}
		var out, errOut bytes.Buffer
		code := Run(context.Background(), db, p, Options{Output: "json", FailOnIncomplete: true, FailOnIncompleteTarget: true}, &out, &errOut)
		var doc report.Document
		if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
			t.Fatalf("decode: %v\n%s\n%s", err, out.String(), errOut.String())
		}
		return code, doc
	}
	for _, tc := range []struct{ name, top, subject string }{
		{"stated version in components", versioned, nameOnly},
		{"stated version in the subject", nameOnly, versioned},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, doc := run(tc.top, tc.subject)
			if len(doc.Findings) != 1 || doc.Findings[0].Advisory.ID != "DEBIAN-CVE-2026-4046" {
				t.Errorf("findings = %v, want DEBIAN-CVE-2026-4046 either way round", findingIDs(doc))
			}
		})
	}
	t.Run("two stated versions contradict", func(t *testing.T) {
		for _, order := range [][2]string{{versioned, other}, {other, versioned}} {
			code, doc := run(order[0], order[1])
			if code != 2 {
				t.Errorf("exit = %d, want 2 (D11: an untrustworthy result outranks findings)", code)
			}
			if len(doc.Findings) != 0 || doc.Summary.TargetIncomplete != 1 || len(doc.Skipped) != 1 {
				t.Fatalf("findings=%v targetIncomplete=%d skipped=%+v, want no finding and one target skip",
					findingIDs(doc), doc.Summary.TargetIncomplete, doc.Skipped)
			}
			if r := doc.Skipped[0].Reason; !strings.Contains(r, "2.31-13+deb11u12 and 2.31-13+deb11u13") || doc.Skipped[0].Cause != "target" {
				t.Errorf("skip = %+v, want both versions, sorted, and cause target", doc.Skipped[0])
			}
		}
	})
}
