package scancmd

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/report"
	"github.com/kun9497/assay/internal/store"
)

// QA 2026-11-10 ③, end to end. A distro package is keyed by the OS declared
// in its own branch of the document, not by the first one found anywhere:
// Alpine and busybox moved under the subject read 0 findings, not evaluated,
// exit 2; and in a document carrying Debian at the top and Alpine under the
// subject, the release keyed busybox to Debian:11 (51 false findings on the
// public DB).
func TestRun_QA1110_OSContextIsTheBranchs(t *testing.T) {
	db := filepath.Join(t.TempDir(), "vulnerability.db")
	w, err := store.Create(db)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range []advisory.Advisory{
		{ID: "ALPINE-CVE-2024-58251", Kind: advisory.KindVulnerability, Database: "ALPINE", Upstream: []string{"CVE-2024-58251"},
			Affected: []advisory.Affected{{Ecosystem: "Alpine:v3.19", Name: "busybox",
				Ranges: []advisory.Range{{Type: advisory.RangeEcosystem, Events: []advisory.Event{{Introduced: "0"}, {Fixed: "1.36.1-r21"}}}}}}},
		// A Debian record for a package named busybox: what a mis-keyed
		// Alpine busybox would wrongly match.
		{ID: "DEBIAN-CVE-2099-0001", Kind: advisory.KindVulnerability, Database: "DEBIAN", Upstream: []string{"CVE-2099-0001"},
			Affected: []advisory.Affected{{Ecosystem: "Debian:11", Name: "busybox",
				Ranges: []advisory.Range{{Type: advisory.RangeEcosystem, Events: []advisory.Event{{Introduced: "0"}, {Fixed: "1:9.9"}}}}}}},
		{ID: "DEBIAN-CVE-2026-4046", Kind: advisory.KindVulnerability, Database: "DEBIAN", Upstream: []string{"CVE-2026-4046"},
			Affected: []advisory.Affected{{Ecosystem: "Debian:11", Name: "glibc",
				Ranges: []advisory.Range{{Type: advisory.RangeEcosystem, Events: []advisory.Event{{Introduced: "0"}, {Fixed: "2.31-13+deb11u14"}}}}}}},
	} {
		if err := w.Put(a); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.SetMeta(store.Meta{Providers: map[string]store.Provenance{"osv": {Ecosystems: []string{"Alpine:v3.19", "Debian:11"}}}}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	const (
		alpine  = `{"type":"operating-system","name":"alpine","version":"3.19.9"}`
		debian  = `{"type":"operating-system","name":"debian","version":"11"}`
		busybox = `{"type":"library","name":"busybox","version":"1.36.1-r20","purl":"pkg:apk/alpine/busybox@1.36.1-r20?arch=x86_64"}`
		libc6   = `{"type":"library","name":"libc6","version":"2.31-13+deb11u13","purl":"pkg:deb/debian/libc6@2.31-13%2Bdeb11u13?arch=amd64&upstream=glibc"}`
		start   = `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,`
	)
	run := func(body string) (int, report.Document) {
		t.Helper()
		p := filepath.Join(t.TempDir(), "sbom.cdx.json")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		var out, errOut bytes.Buffer
		code := Run(context.Background(), db, p, Options{Output: "json", FailOnIncomplete: true, FailOnIncompleteTarget: true}, &out, &errOut)
		var doc report.Document
		if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
			t.Fatalf("decode: %v\n%s", err, errOut.String())
		}
		return code, doc
	}
	keyed := func(doc report.Document) map[string]string {
		m := map[string]string{}
		for _, f := range doc.Findings {
			m[f.Advisory.ID] = f.Package.Ecosystem
		}
		return m
	}
	for _, tc := range []struct {
		name string
		body string
		want map[string]string
	}{
		{"OS and package at the top", start + `"components":[` + alpine + `,` + busybox + `]}`,
			map[string]string{"ALPINE-CVE-2024-58251": "Alpine:v3.19"}},
		{"OS and package under the subject", start + `"components":[],"metadata":{"component":{"type":"container","name":"demo","components":[` + alpine + `,` + busybox + `]}}}`,
			map[string]string{"ALPINE-CVE-2024-58251": "Alpine:v3.19"}},
		{"OS above, package nested deeper inherits it", start + `"components":[` + alpine + `,{"type":"application","name":"app","purl":"pkg:generic/app@1","version":"1","components":[` + busybox + `]}]}`,
			map[string]string{"ALPINE-CVE-2024-58251": "Alpine:v3.19"}},
		{"Debian at the top, Alpine under the subject", start + `"components":[` + debian + `,` + libc6 + `],"metadata":{"component":{"type":"container","name":"demo","components":[` + alpine + `,` + busybox + `]}}}`,
			map[string]string{"ALPINE-CVE-2024-58251": "Alpine:v3.19", "DEBIAN-CVE-2026-4046": "Debian:11"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, doc := run(tc.body)
			got := keyed(doc)
			if len(got) != len(tc.want) {
				t.Fatalf("findings = %v, want %v", got, tc.want)
			}
			for id, eco := range tc.want {
				if got[id] != eco {
					t.Errorf("%s keyed %q, want %q (all %v)", id, got[id], eco, got)
				}
			}
		})
	}
	// Two different OS side by side and a package with no distro qualifier:
	// it is not keyed to either, and the strict gate says so.
	t.Run("two OS side by side, no qualifier", func(t *testing.T) {
		code, doc := run(start + `"components":[` + alpine + `,` + debian + `,` + busybox + `]}`)
		if len(doc.Findings) != 0 || doc.Summary.NotEvaluated != 1 || code != 2 {
			t.Errorf("exit=%d findings=%v notEvaluated=%d, want exit 2, nothing keyed by a guess, one not evaluated",
				code, keyed(doc), doc.Summary.NotEvaluated)
		}
	})
	// The same, with the purl's own distro qualifier: that identifies it.
	t.Run("two OS side by side, qualifier identifies it", func(t *testing.T) {
		q := `{"type":"library","name":"busybox","version":"1.36.1-r20","purl":"pkg:apk/alpine/busybox@1.36.1-r20?arch=x86_64&distro=alpine-3.19.9"}`
		_, doc := run(start + `"components":[` + alpine + `,` + debian + `,` + q + `]}`)
		if got := keyed(doc); got["ALPINE-CVE-2024-58251"] != "Alpine:v3.19" || len(got) != 1 {
			t.Errorf("findings = %v, want the Alpine one only", got)
		}
	})
}
