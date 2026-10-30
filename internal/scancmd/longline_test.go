package scancmd

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/severity"
	"github.com/kun9497/assay/internal/store"
)

// longLineDB rates one package per lockfile reader critical. Each name sits
// below a long line in its fixture, so a reader that stops at the long line
// reports the package as absent, not as clean.
func longLineDB(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vulnerability.db")
	w, err := store.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range []struct{ id, eco, name string }{
		{"QA1030-0001", "RubyGems", "hidden-gem"},
		{"QA1030-0002", "crates.io", "hidden-crate"},
		{"QA1030-0003", "PyPI", "hidden-uv"},
		{"QA1030-0004", "PyPI", "hidden-req"},
	} {
		if err := w.Put(advisory.Advisory{
			ID: r.id, Kind: advisory.KindVulnerability, Database: "GHSA",
			Severity: []advisory.Severity{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}},
			Affected: []advisory.Affected{{Ecosystem: r.eco, Name: r.name, Ranges: []advisory.Range{{
				Type: advisory.RangeEcosystem, Events: []advisory.Event{{Introduced: "0"}, {Fixed: "2.0.0"}},
			}}}},
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.SetMeta(store.Meta{Providers: map[string]store.Provenance{"osv": {Ecosystems: []string{"RubyGems", "crates.io", "PyPI"}}}}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

// QA 2026-10-30: the Gemfile.lock, Cargo.lock/uv.lock (tomlblock) and
// requirements.txt readers split lines with bufio.Scanner and never read
// Err(). A line over the Scanner's 64 KiB token stopped the loop, and every
// package after it vanished while the reader reported success, so a critical
// package below a long comment scanned as exit 0 with nothing incomplete. A
// stop at a long line is now impossible: each reader splits the file it
// already holds. The short-line rows are the control: the same fixture with
// a 128-byte line, which found the package before the fix too.
func TestRun_QA1030_ALongLineDoesNotHideTheLockfileBelowIt(t *testing.T) {
	db := longLineDB(t)
	cases := []struct {
		file, want string
		body       func(filler string) string
	}{
		{"Gemfile.lock", "hidden-gem@1.0.0", func(f string) string {
			return "GEM\n  remote: https://rubygems.org/\n  specs:\n    first-gem (1.0.0)\n" +
				f + "\n    hidden-gem (1.0.0)\n\nPLATFORMS\n  ruby\n"
		}},
		{"Cargo.lock", "hidden-crate@1.0.0", func(f string) string {
			return "version = 3\n\n[[package]]\nname = \"first-crate\"\nversion = \"1.0.0\"\n\n# " + f +
				"\n[[package]]\nname = \"hidden-crate\"\nversion = \"1.0.0\"\n"
		}},
		{"uv.lock", "hidden-uv@1.0.0", func(f string) string {
			return "version = 1\n\n[[package]]\nname = \"first-uv\"\nversion = \"1.0.0\"\n\n# " + f +
				"\n[[package]]\nname = \"hidden-uv\"\nversion = \"1.0.0\"\n"
		}},
		{"requirements.txt", "hidden-req@1.0.0", func(f string) string {
			return "first-req==1.0.0\n# " + f + "\nhidden-req==1.0.0\n"
		}},
	}
	for _, c := range cases {
		for _, n := range []int{128, 70 * 1024} {
			t.Run(c.file+"/"+map[int]string{128: "short", 70 * 1024: "70KiB"}[n], func(t *testing.T) {
				dir := t.TempDir()
				writeManifest(t, dir, c.file, c.body(strings.Repeat(" ", n)))
				crit := severity.Critical
				var out, errOut bytes.Buffer
				code := Run(context.Background(), db, "dir:"+dir, Options{
					Output: "json", FailOn: &crit, FailOnIncomplete: true,
				}, &out, &errOut)
				var r struct {
					Summary struct {
						Components int `json:"components"`
					} `json:"summary"`
					Findings []struct {
						Package struct {
							Name    string `json:"name"`
							Version string `json:"version"`
						} `json:"package"`
					} `json:"findings"`
				}
				if err := json.Unmarshal(out.Bytes(), &r); err != nil {
					t.Fatalf("decode: %v\nstderr: %s", err, errOut.String())
				}
				var found []string
				for _, f := range r.Findings {
					found = append(found, f.Package.Name+"@"+f.Package.Version)
				}
				if !slices.Contains(found, c.want) || code != 1 {
					t.Errorf("exit %d, findings %v: want exit 1 with %s, which sits below the long line\nstderr: %s", code, found, c.want, errOut.String())
				}
				if r.Summary.Components != 2 {
					t.Errorf("components = %d, want 2: the package above the line and the one below it", r.Summary.Components)
				}
			})
		}
	}
}
