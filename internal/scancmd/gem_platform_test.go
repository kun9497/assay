package scancmd

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/store"
)

// gemPlatformDB holds RubyGems records, each with its own IDs so no package
// name appears inside an advisory ID:
//   - GEM-A6-0001 is introduced AT nokogiri 1.13.8 and fixed in 1.13.9, so a
//     native nokogiri 1.13.8 is affected;
//   - GEM-A6-0002 fixes ffi in 1.17.0, so a native ffi 1.17.0 is clean;
//   - GEM-A6-0003 fixes rack-fixture in 3.0.0, so a 3.0.0 prerelease is still
//     affected;
//   - GEM-A6-0004 fixes sqlite3 in 1.7.0, so a native sqlite3 1.7.0 is clean
//     (an arm64-darwin build, which read as a prerelease of 1.7.0 and was a
//     false positive, where ffi's x86_64 was not evaluated at all).
func gemPlatformDB(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vulnerability.db")
	w, err := store.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range []struct{ id, name, introduced, fixed string }{
		{"GEM-A6-0001", "nokogiri", "1.13.8", "1.13.9"},
		{"GEM-A6-0002", "ffi", "0", "1.17.0"},
		{"GEM-A6-0003", "rack-fixture", "0", "3.0.0"},
		{"GEM-A6-0004", "sqlite3", "0", "1.7.0"},
		{"GEM-A6-0005", "odd-fixture", "0", "2.0.0"},
	} {
		if err := w.Put(advisory.Advisory{
			ID: r.id, Kind: advisory.KindVulnerability, Database: "GHSA",
			Severity: []advisory.Severity{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}},
			Affected: []advisory.Affected{{Ecosystem: "RubyGems", Name: r.name, Ranges: []advisory.Range{{
				Type: advisory.RangeEcosystem, Events: []advisory.Event{{Introduced: r.introduced}, {Fixed: r.fixed}},
			}}}},
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.SetMeta(store.Meta{Providers: map[string]store.Provenance{"osv": {Ecosystems: []string{"RubyGems"}}}}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

type gemScan struct {
	found   []string // name@version of every package with a finding
	skipped int      // packages reported as not evaluated
}

func runGemScan(t *testing.T, db, target string) gemScan {
	t.Helper()
	var out, errOut bytes.Buffer
	Run(context.Background(), db, target, Options{Output: "json"}, &out, &errOut)
	var r struct {
		Findings []struct {
			Package struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"package"`
		} `json:"findings"`
		Skipped []json.RawMessage `json:"skipped"`
	}
	if err := json.Unmarshal(out.Bytes(), &r); err != nil {
		t.Fatalf("decode: %v\nstdout: %s\nstderr: %s", err, out.String(), errOut.String())
	}
	var s gemScan
	for _, f := range r.Findings {
		k := f.Package.Name + "@" + f.Package.Version
		if !slices.Contains(s.found, k) {
			s.found = append(s.found, k)
		}
	}
	slices.Sort(s.found)
	s.skipped = len(r.Skipped)
	return s
}

// 2026-10-22 audit A6: bundler writes a native gem's platform after its
// version ("nokogiri (1.13.8-x86_64-linux)"), and the cataloger kept it as
// part of the version. The Gem comparer, following Gem::Version, read the
// hyphen as a prerelease ("1.13.8.pre.arm64.darwin", below 1.13.8) or
// refused the underscore in x86_64 outright. So an advisory introduced at
// the installed version found nothing, one fixed at it was a false positive,
// and x86_64-linux gems were not evaluated at all. Bundler's own grammar
// (lockfile_parser.rb, NAME_VERSION) takes the version up to the first
// hyphen and the platform after it; RubyGems rewrites any hyphen in a real
// version to ".pre.", so a lockfile version never holds one.
func TestRun_A6_GemfileLockPlatformIsNotPartOfTheVersion(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "Gemfile.lock", `GEM
  remote: https://rubygems.org/
  specs:
    ffi (1.17.0-x86_64-linux-musl)
    nokogiri (1.13.8-arm64-darwin)
      racc (~> 1.4)
    rack-fixture (3.0.0.rc1)
    sqlite3 (1.7.0-arm64-darwin)

PLATFORMS
  arm64-darwin
  x86_64-linux-musl

DEPENDENCIES
  ffi
  nokogiri
  rack-fixture
  sqlite3

BUNDLED WITH
   2.5.6
`)
	got := runGemScan(t, gemPlatformDB(t), "dir:"+dir)
	if want := []string{"nokogiri@1.13.8", "rack-fixture@3.0.0.rc1"}; !slices.Equal(got.found, want) {
		t.Errorf("findings = %v, want %v: nokogiri at its introduced version, ffi and sqlite3 clean at their fixes, the prerelease below its fix", got.found, want)
	}
	if got.skipped != 0 {
		t.Errorf("skipped = %d, want 0: an x86_64 platform must not make a gem unreadable", got.skipped)
	}
}

// The same gems arrive in SBOMs spelled the way syft spells them: the
// lockfile's version, platform and all, in both the version and the purl. A
// suffix is taken off only when it names a platform Gem::Platform knows
// (linux, darwin, mingw, java, ...); a prerelease spelled with a hyphen
// ("3.0.0-rc1", which a producer may write unnormalized) is left alone and
// still sorts below its release.
func TestRun_A6_SBOMGemPlatformIsNotPartOfTheVersion(t *testing.T) {
	type comp struct{ name, version, qualifiers string }
	comps := []comp{
		{"ffi", "1.17.0-x86_64-linux-musl", ""},
		{"nokogiri", "1.13.8-arm64-darwin", ""},
		{"rack-fixture", "3.0.0-rc1", ""},
		{"sqlite3", "1.7.0-arm64-darwin", ""},
		// A platform Gem::Platform does not know, declared by the purl's
		// own qualifier: clean at its fix only if the reader passes the
		// qualifier on.
		{"odd-fixture", "2.0.0-weirdplat", "?platform=weirdplat"},
	}
	want := []string{"nokogiri@1.13.8", "rack-fixture@3.0.0-rc1"}
	db := gemPlatformDB(t)

	cdx := `{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[`
	spdx := `{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","packages":[`
	for i, c := range comps {
		purl := "pkg:gem/" + c.name + "@" + c.version + c.qualifiers
		if i > 0 {
			cdx += ","
			spdx += ","
		}
		cdx += `{"type":"library","name":"` + c.name + `","version":"` + c.version + `","purl":"` + purl + `"}`
		spdx += `{"name":"` + c.name + `","SPDXID":"SPDXRef-Package-` + c.name + `","versionInfo":"` + c.version + `",` +
			`"externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl","referenceLocator":"` + purl + `"}]}`
	}
	cdx += `]}`
	spdx += `]}`

	for name, doc := range map[string]string{"s.cdx.json": cdx, "s.spdx.json": spdx} {
		path := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
			t.Fatal(err)
		}
		got := runGemScan(t, db, path)
		if !slices.Equal(got.found, want) {
			t.Errorf("%s: findings = %v, want %v", name, got.found, want)
		}
		if got.skipped != 0 {
			t.Errorf("%s: skipped = %d, want 0", name, got.skipped)
		}
	}
}
