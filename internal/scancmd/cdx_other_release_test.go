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

// twoDebianDB covers Debian:11 and Debian:12 with one advisory each on the
// source package sample, so a scan says which release's listing was judged.
func twoDebianDB(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vulnerability.db")
	w, err := store.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range []struct{ id, eco string }{{"QA-CONTROL-11", "Debian:11"}, {"QA-CONTROL-12", "Debian:12"}} {
		if err := w.Put(advisory.Advisory{
			ID: a.id, Kind: advisory.KindVulnerability, Database: "QA",
			Affected: []advisory.Affected{{
				Ecosystem: a.eco, Name: "sample",
				Ranges: []advisory.Range{{Type: advisory.RangeEcosystem, Events: []advisory.Event{{Introduced: "0"}, {Fixed: "99"}}}},
			}},
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.SetMeta(store.Meta{Providers: map[string]store.Provenance{"osv": {Ecosystems: []string{"Debian:11", "Debian:12"}}}}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

// Linux QA of v0.18.1 (2026-11-13), through Run: the document the QA ran,
// one deb name and version listed bare under Debian 11 and Debian 12 with
// the subject installing it on Debian 11. Both releases' listings are
// judged -- 2 of 2, both control advisories, exit 0 under
// --fail-on-incomplete=target -- in either order of the top listings and
// with the two listings stating one source version or two. v0.18.1 judged
// the Debian 11 install only and exited 2 on a "7 and 7" contradiction.
func TestRun_CycloneDXABareListingOfAnotherReleaseIsJudged(t *testing.T) {
	db := twoDebianDB(t)
	const example = "pkg:deb/debian/example@1.0"
	for _, tc := range []struct{ name, src12 string }{{"one source version", "7"}, {"two source versions", "2"}} {
		for _, order := range [][2]string{{"debian-11", "debian-12"}, {"debian-12", "debian-11"}} {
			t.Run(tc.name+" "+order[0]+" first", func(t *testing.T) {
				src := map[string]string{"debian-11": "7", "debian-12": tc.src12}
				var comps []string
				for _, r := range order {
					comps = append(comps, `{"type":"library","name":"example","version":"1.0","purl":"`+example+`?distro=`+r+`&upstream=sample%40`+src[r]+`"}`)
				}
				doc := `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[` + strings.Join(comps, ",") + `],` +
					`"metadata":{"component":{"type":"container","name":"subject","components":[` +
					`{"type":"library","name":"example","version":"1.0","purl":"` + example + `?arch=amd64&distro=debian-11&upstream=sample%407"}]}}}`
				p := filepath.Join(t.TempDir(), "two-releases.cdx.json")
				if err := os.WriteFile(p, []byte(doc), 0o644); err != nil {
					t.Fatal(err)
				}
				var out, errOut bytes.Buffer
				code := Run(context.Background(), db, "sbom:"+p, Options{Output: "json", FailOnIncompleteTarget: true}, &out, &errOut)
				var rep report.Document
				if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
					t.Fatalf("stdout is not one JSON document: %v\n%s\nstderr: %s", err, out.String(), errOut.String())
				}
				ids := map[string]bool{}
				for _, f := range rep.Findings {
					ids[f.Advisory.ID] = true
				}
				if code != 0 || rep.Summary.Evaluated != 2 || rep.Summary.TargetIncomplete != 0 || len(rep.Skipped) != 0 || !ids["QA-CONTROL-11"] || !ids["QA-CONTROL-12"] {
					t.Fatalf("Run = %d, evaluated %d of %d, targetIncomplete %d, skipped %+v, findings %v; want 0, 2 of 2, 0, none, both controls\nstderr: %s",
						code, rep.Summary.Evaluated, rep.Summary.Components, rep.Summary.TargetIncomplete, rep.Skipped, ids, errOut.String())
				}
			})
		}
	}
}
